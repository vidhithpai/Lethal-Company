from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
JAVAPARSER_JAR = _REPO_ROOT / "tools" / "javaparser-cli.jar"

logger = logging.getLogger(__name__)

ENTRY_ANNOTATIONS = {
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
    "Action", "Controller",
}
STRUTS_ENTRY_METHODS = {"execute", "doDefault", "list", "ping", "logout", "adminShowUsers"}
GUARD_ANNOTATIONS = {"Valid", "NotNull", "Validated"}
GUARD_NAME_PREFIXES = ("validate", "sanitize", "check", "escape", "filter")

SOURCE_BODY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        r"getParameter\s*\(",
        r"getServletRequest\s*\(",
        r"getCookies\s*\(",
        r"getHeader\s*\(",
        r"getInputStream\s*\(",
        r"HttpServletRequest",
        r"@PathParam",
        r"@QueryParam",
        r"request\.get",
    )
]

SINK_PATTERNS: list[dict[str, Any]] = [
    {
        "key": "cmd_exec",
        "pattern": re.compile(
            r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|Runtime\.exec\s*\(|\.exec\s*\(|new\s+ProcessBuilder\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 9.0,
        "cwe": "CWE-78",
        "cwe_name": "OS Command Injection",
        "sink_kind": "cmd_execution",
    },
    {
        "key": "sql_exec",
        "pattern": re.compile(
            r"executeQuery\s*\(|executeUpdate\s*\(|createQuery\s*\(|createNativeQuery\s*\(|(?:statement|stmt|query|session|jdbc).{0,40}\.execute\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 8.0,
        "cwe": "CWE-89",
        "cwe_name": "SQL Injection",
        "sink_kind": "sql_execution",
    },
    {
        "key": "deserialization",
        "pattern": re.compile(
            r"ObjectInputStream\s*\(|readObject\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 8.5,
        "cwe": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "sink_kind": "deserialization",
    },
    {
        "key": "reflection",
        "pattern": re.compile(
            r"Class\.forName\s*\(|Method\.invoke\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 8.5,
        "cwe": "CWE-470",
        "cwe_name": "Unsafe Reflection",
        "sink_kind": "reflection",
    },
    {
        "key": "xss",
        "pattern": re.compile(
            r"response\.getWriter\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 7.0,
        "cwe": "CWE-79",
        "cwe_name": "Cross-Site Scripting",
        "sink_kind": "xss",
    },
    {
        "key": "file_write",
        "pattern": re.compile(
            r"new\s+FileWriter\s*\(|Files\.write\s*\(",
            re.IGNORECASE | re.DOTALL,
        ),
        "severity": 6.0,
        "cwe": "CWE-22",
        "cwe_name": "Path Traversal / Unsafe File Write",
        "sink_kind": "file_write",
    },
]

METHOD_START_RE = re.compile(
    r"^\s*"
    r"(?:(?:public|private|protected|static|final|native|synchronized|abstract)\s+)*"
    r"(?:[\w<>\[\],\s.?@]+?\s+)?"
    r"(?P<name>\w+)\s*\("
    r"(?P<rest>[^;]*)"
    r"\)\s*(?:throws\s+[\w\s,.<>]+)?\s*\{?"
)

ANNOTATION_RE = re.compile(r"@(\w+)")

JAVA_KEYWORDS = {
    "if", "for", "while", "switch", "catch", "return", "new", "throw", "else", "try",
}


def _empty_result() -> dict[str, list[dict[str, Any]]]:
    return {"entry": [], "sink": [], "guard": [], "normal": []}


def _node(name: str, filepath: str, line: int, sink_info: dict[str, Any] | None = None) -> dict[str, Any]:
    n = {"name": name, "file": filepath, "line": line}
    if sink_info:
        n.update({
            "cwe": sink_info.get("cwe"),
            "cwe_name": sink_info.get("cwe_name"),
            "sink_kind": sink_info.get("sink_kind"),
            "severity": sink_info.get("severity"),
        })
    return n


def _is_ping_action(filepath: str) -> bool:
    return filepath.replace("\\", "/").endswith("PingAction.java")


def _debug_enabled() -> bool:
    return os.environ.get("VULNGRAPH_DEBUG", "").lower() in {"1", "true", "yes"}


def _debug_ping_action_context(lines: list[str]) -> None:
    print("[java_parser] PingAction.java lines 12-32 (context around line 22):")
    for idx in range(11, min(32, len(lines))):
        print(f"  {idx + 1}: {lines[idx]}")


def _collect_method_body(lines: list[str], start_idx: int) -> tuple[str, int]:
    """Return the full method body text (signature + all lines) and next line index."""
    line = lines[start_idx]
    body_lines: list[str] = []

    if "{" in line:
        body_lines.append(line)
        brace_depth = line.count("{") - line.count("}")
        j = start_idx + 1
        while j < len(lines) and brace_depth > 0:
            body_lines.append(lines[j])
            brace_depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        return "\n".join(body_lines), j

    body_lines.append(line)
    j = start_idx + 1
    while j < len(lines) and "{" not in lines[j]:
        if lines[j].strip().endswith(";"):
            body_lines.append(lines[j])
            return "\n".join(body_lines), j + 1
        j += 1

    if j >= len(lines):
        return "\n".join(body_lines), j

    body_lines.append(lines[j])
    brace_depth = lines[j].count("{") - lines[j].count("}")
    k = j + 1
    while k < len(lines) and brace_depth > 0:
        body_lines.append(lines[k])
        brace_depth += lines[k].count("{") - lines[k].count("}")
        k += 1
    return "\n".join(body_lines), k


def _method_body_only(body: str) -> str:
    """Use implementation lines only — exclude signature/return type false positives."""
    idx = body.find("{")
    if idx >= 0:
        return body[idx + 1 :]
    return body


def _strip_java_comments(code: str) -> str:
    # Note: String-literal false positives are a known limitation pending future AST-based parser implementation.
    code_no_single = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
    code_no_comments = re.sub(r"/\*.*?\*/", "", code_no_single, flags=re.DOTALL)
    return code_no_comments


def _search_text(body: str) -> str:
    """Single string for regex: preserve newlines and also offer collapsed whitespace."""
    impl = _method_body_only(body)
    clean_impl = _strip_java_comments(impl)
    collapsed = re.sub(r"\s+", " ", clean_impl.replace("\r\n", "\n"))
    return f"{clean_impl}\n{collapsed}"


def _get_body_sink_info(body: str) -> dict[str, Any] | None:
    text = _search_text(body)
    for entry in SINK_PATTERNS:
        if entry["pattern"].search(text):
            return entry
    return None


def _body_has_sink(body: str) -> bool:
    return _get_body_sink_info(body) is not None


def _body_has_source(body: str) -> bool:
    text = _search_text(body)
    for pattern in SOURCE_BODY_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _javap_available() -> bool:
    return shutil.which("javap") is not None


def _run_javaparser_cli(filepath: str) -> dict[str, list[dict[str, Any]]] | None:
    if not JAVAPARSER_JAR.exists():
        return None
    if shutil.which("java") is None:
        return None

    try:
        proc = subprocess.run(
            ["java", "-jar", str(JAVAPARSER_JAR), filepath],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    if proc.returncode != 0 or not proc.stdout.strip():
        return None

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None

    parsed = _parse_javaparser_json(payload, filepath)
    if not _parsed_has_useful_bodies(parsed, payload):
        return None
    return parsed


def _parsed_has_useful_bodies(parsed: dict[str, list[dict[str, Any]]], payload: Any) -> bool:
    methods = _extract_methods_from_json(payload)
    if not methods:
        return False
    for method in methods:
        body = str(method.get("body", method.get("content", ""))).strip()
        if body and _body_has_sink(body):
            return True
    total = sum(len(v) for v in parsed.values())
    return total > 0 and any(
        str(method.get("body", method.get("content", ""))).strip()
        for method in methods
    )


def _parse_javaparser_json(payload: Any, filepath: str) -> dict[str, list[dict[str, Any]]]:
    result = _empty_result()
    methods = _extract_methods_from_json(payload)

    for method in methods:
        name = str(method.get("name", ""))
        line = int(method.get("line", method.get("beginLine", 1)) or 1)
        annotations = {str(a).lstrip("@") for a in method.get("annotations", [])}
        body = str(method.get("body", method.get("content", "")))

        category, sink_info = _classify_method(name, annotations, body, filepath=filepath)
        result[category].append(_node(name, filepath, line, sink_info=sink_info))

    return result


def _extract_methods_from_json(payload: Any) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if "name" in node and ("body" in node or "beginLine" in node or "line" in node):
                if node.get("type") in (None, "MethodDeclaration", "method", "Method"):
                    methods.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(payload)
    return methods


def _classify_method(
    name: str,
    annotations: set[str],
    body: str,
    *,
    filepath: str = "",
) -> tuple[str, dict[str, Any] | None]:
    name_lower = name.lower()

    # Narrow check* prefix: check* is only a guard if body ALSO matches SOURCE_BODY_PATTERNS
    is_guard_name = False
    for prefix in ("validate", "sanitize", "escape", "filter"):
        if name_lower.startswith(prefix):
            is_guard_name = True
            break
    if name_lower.startswith("check") and _body_has_source(body):
        is_guard_name = True

    # Narrow Struts entry methods: list, ping, logout require SOURCE_BODY_PATTERNS or entry annotations
    is_entry_method = False
    if name in {"execute", "doDefault", "adminShowUsers"} or name == "main":
        is_entry_method = True
    elif name in {"list", "ping", "logout"}:
        if _body_has_source(body) or (annotations & ENTRY_ANNOTATIONS):
            is_entry_method = True

    sink_info = _get_body_sink_info(body)

    if annotations & GUARD_ANNOTATIONS or is_guard_name:
        category = "guard"
    elif sink_info is not None:
        category = "sink"
    elif is_entry_method or annotations & ENTRY_ANNOTATIONS or _body_has_source(body):
        category = "entry"
    else:
        category = "normal"

    return category, (sink_info if category == "sink" else None)


def _extract_methods_regex(content: str, filepath: str) -> dict[str, list[dict[str, Any]]]:
    result = _empty_result()
    lines = content.splitlines()
    pending_annotations: list[str] = []
    i = 0

    if _debug_enabled() and _is_ping_action(filepath):
        _debug_ping_action_context(lines)

    while i < len(lines):
        line = lines[i]
        ann_matches = ANNOTATION_RE.findall(line)
        if ann_matches and ";" not in line.split("//")[0]:
            pending_annotations.extend(ann_matches)
            if "{" not in line and "(" not in line:
                i += 1
                continue

        match = METHOD_START_RE.match(line)
        if match and ";" not in line.split("//")[0]:
            name = match.group("name")
            if name in JAVA_KEYWORDS:
                i += 1
                continue

            line_no = i + 1
            annotations = set(pending_annotations)
            body, next_i = _collect_method_body(lines, i)

            if _debug_enabled() and _is_ping_action(filepath):
                print(
                    f"[java_parser] PingAction regex block: method={name!r} line={line_no} "
                    f"before classification"
                )
                print(f"[java_parser] PingAction raw body text:\n{body}\n---")

            category, sink_info = _classify_method(name, annotations, body, filepath=filepath)
            result[category].append(_node(name, filepath, line_no, sink_info=sink_info))
            pending_annotations = []
            i = next_i
            continue

        if line.strip() and not line.strip().startswith("@"):
            pending_annotations = []
        i += 1

    return result


def _match_ast_sink(inv: Any) -> dict[str, Any] | None:
    member = getattr(inv, "member", "") or ""
    qual = getattr(inv, "qualifier", "") or ""

    if member == "exec" and (qual in ("Runtime", "runtime", "Runtime.getRuntime()") or "runtime" in qual.lower()):
        return {
            "key": "cmd_exec",
            "severity": 9.0,
            "cwe": "CWE-78",
            "cwe_name": "OS Command Injection",
            "sink_kind": "cmd_execution",
        }
    if member in ("execute", "executeQuery", "executeUpdate", "createQuery", "createNativeQuery"):
        if member != "execute" or any(k in qual.lower() for k in ("statement", "stmt", "query", "session", "jdbc")):
            return {
                "key": "sql_exec",
                "severity": 8.0,
                "cwe": "CWE-89",
                "cwe_name": "SQL Injection",
                "sink_kind": "sql_execution",
            }
    if member == "readObject" and (qual == "ObjectInputStream" or "stream" in qual.lower() or member == "readObject"):
        return {
            "key": "deserialization",
            "severity": 8.5,
            "cwe": "CWE-502",
            "cwe_name": "Deserialization of Untrusted Data",
            "sink_kind": "deserialization",
        }
    if member in ("forName", "invoke") and qual in ("Class", "Method"):
        return {
            "key": "reflection",
            "severity": 8.5,
            "cwe": "CWE-470",
            "cwe_name": "Unsafe Reflection",
            "sink_kind": "reflection",
        }
    if member == "getWriter" and qual == "response":
        return {
            "key": "xss",
            "severity": 7.0,
            "cwe": "CWE-79",
            "cwe_name": "Cross-Site Scripting",
            "sink_kind": "xss",
        }
    if member == "write" and qual == "Files":
        return {
            "key": "file_write",
            "severity": 6.0,
            "cwe": "CWE-22",
            "cwe_name": "Path Traversal / Unsafe File Write",
            "sink_kind": "file_write",
        }
    return None


def _parse_javalang_ast(filepath: str, content: str) -> dict[str, list[dict[str, Any]]] | None:
    try:
        import javalang
        tree = javalang.parse.parse(content)
    except Exception as e:
        logger.warning("javalang AST parsing failed for %s, falling back to regex: %s", filepath, e)
        return None

    result = _empty_result()
    SOURCE_MEMBERS = {"getParameter", "getServletRequest", "getCookies", "getHeader", "getInputStream", "request.get"}

    for path, method in tree.filter(javalang.tree.MethodDeclaration):
        name = method.name
        line = method.position.line if method.position else 1
        annotations = {a.name for a in (method.annotations or [])}

        tainted_vars = set()
        for param in (method.parameters or []):
            p_anns = {a.name for a in (param.annotations or [])}
            if p_anns & {"RequestParam", "PathVariable", "QueryParam", "FormParam", "HeaderParam", "Context"}:
                tainted_vars.add(param.name)
            elif param.name and any(kw in param.name.lower() for kw in ("input", "query", "cmd", "req", "param", "user")):
                tainted_vars.add(param.name)

        if method.body:
            for _, var_decl in method.filter(javalang.tree.LocalVariableDeclaration):
                for decl in var_decl.declarators:
                    if decl.initializer:
                        has_source = False
                        if hasattr(decl.initializer, "filter"):
                            for _, inv in decl.initializer.filter(javalang.tree.MethodInvocation):
                                if inv.member in SOURCE_MEMBERS or (inv.member and inv.member.startswith("get")) or (inv.qualifier and inv.qualifier == "request"):
                                    has_source = True
                                    break

                        has_tainted_ref = False
                        if hasattr(decl.initializer, "filter"):
                            for _, ref in decl.initializer.filter(javalang.tree.MemberReference):
                                if ref.member in tainted_vars:
                                    has_tainted_ref = True
                                    break

                        if has_source or has_tainted_ref:
                            tainted_vars.add(decl.name)

            for _, assign in method.filter(javalang.tree.Assignment):
                rhs_tainted = False
                if hasattr(assign.value, "filter"):
                    for _, inv in assign.value.filter(javalang.tree.MethodInvocation):
                        if inv.member in SOURCE_MEMBERS or (inv.member and inv.member.startswith("get")):
                            rhs_tainted = True
                    for _, ref in assign.value.filter(javalang.tree.MemberReference):
                        if ref.member in tainted_vars:
                            rhs_tainted = True
                if rhs_tainted and hasattr(assign.expressionl, "filter"):
                    for _, lhs_ref in assign.expressionl.filter(javalang.tree.MemberReference):
                        tainted_vars.add(lhs_ref.member)

        sink_info = None
        has_ast_sink = False
        has_ast_source = False

        if method.body:
            for _, inv in method.filter(javalang.tree.MethodInvocation):
                if inv.member in SOURCE_MEMBERS or (inv.member and inv.member.startswith("get")):
                    has_ast_source = True

                s_info = _match_ast_sink(inv)
                if s_info:
                    has_ast_sink = True
                    arg_vars = set()
                    for arg in (inv.arguments or []):
                        if hasattr(arg, "filter"):
                            for _, ref in arg.filter(javalang.tree.MemberReference):
                                arg_vars.add(ref.member)

                    is_tainted = bool(arg_vars & tainted_vars)
                    sev = s_info["severity"]
                    base_risk = "critical" if sev >= 9.0 else ("high" if sev >= 7.0 else "medium")
                    downgrade_map = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}
                    final_risk = base_risk if is_tainted else downgrade_map.get(base_risk, "low")

                    sink_info = dict(s_info)
                    sink_info["taint_confirmed"] = is_tainted
                    sink_info["risk"] = final_risk
                    break

            if not sink_info:
                for _, creator in method.filter(javalang.tree.ClassCreator):
                    c_name = creator.type.name
                    if c_name == "ProcessBuilder":
                        sink_info = {
                            "key": "cmd_exec", "severity": 9.0, "cwe": "CWE-78",
                            "cwe_name": "OS Command Injection", "sink_kind": "cmd_execution",
                            "taint_confirmed": False, "risk": "high"
                        }
                        has_ast_sink = True
                    elif c_name == "FileWriter":
                        sink_info = {
                            "key": "file_write", "severity": 6.0, "cwe": "CWE-22",
                            "cwe_name": "Path Traversal / Unsafe File Write", "sink_kind": "file_write",
                            "taint_confirmed": False, "risk": "low"
                        }
                        has_ast_sink = True

        name_lower = name.lower()
        is_guard = (annotations & GUARD_ANNOTATIONS) or any(name_lower.startswith(p) for p in ("validate", "sanitize", "escape", "filter"))
        if name_lower.startswith("check") and (has_ast_source or (method.parameters and len(method.parameters) > 0)):
            is_guard = True

        is_entry = (name in {"execute", "doDefault", "adminShowUsers", "main"}) or bool(annotations & ENTRY_ANNOTATIONS)
        if name in {"list", "ping", "logout"} and (has_ast_source or (annotations & ENTRY_ANNOTATIONS)):
            is_entry = True

        if is_guard:
            category = "guard"
        elif has_ast_sink:
            category = "sink"
        elif is_entry or has_ast_source:
            category = "entry"
        else:
            category = "normal"

        node_item = _node(name, filepath, line, sink_info=(sink_info if category == "sink" else None))
        result[category].append(node_item)

    return result


def parse_java_file(filepath: str) -> dict[str, list[dict[str, Any]]]:
    path = Path(filepath)
    if not path.exists() or path.suffix.lower() != ".java":
        return _empty_result()

    mode = os.environ.get("JAVA_CLASSIFIER_MODE", "ast").lower()
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return _empty_result()

    if mode == "ast":
        ast_result = _parse_javalang_ast(str(path.resolve()), content)
        if ast_result is not None:
            return ast_result

    return _extract_methods_regex(content, str(path.resolve()))
