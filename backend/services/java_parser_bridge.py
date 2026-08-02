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

SINK_PATTERNS: list[tuple[re.Pattern[str], float]] = [
    (re.compile(r"\.execute\s*\(", re.IGNORECASE | re.DOTALL), 8.0),
    (re.compile(r"\.exec\s*\(", re.IGNORECASE | re.DOTALL), 9.0),
    (re.compile(r"executeQuery\s*\(", re.IGNORECASE | re.DOTALL), 8.0),
    (re.compile(r"executeUpdate\s*\(", re.IGNORECASE | re.DOTALL), 8.0),
    (re.compile(r"createQuery\s*\(", re.IGNORECASE | re.DOTALL), 8.0),
    (re.compile(r"createNativeQuery\s*\(", re.IGNORECASE | re.DOTALL), 8.5),
    (re.compile(r"getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", re.IGNORECASE | re.DOTALL), 9.0),
    (re.compile(r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(", re.IGNORECASE | re.DOTALL), 9.0),
    (re.compile(r"Runtime\.exec\s*\(", re.IGNORECASE | re.DOTALL), 9.0),
    (re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE | re.DOTALL), 9.0),
    (re.compile(r"new\s+FileWriter\s*\(", re.IGNORECASE | re.DOTALL), 6.0),
    (re.compile(r"Files\.write\s*\(", re.IGNORECASE | re.DOTALL), 6.0),
    (re.compile(r"Class\.forName\s*\(", re.IGNORECASE | re.DOTALL), 8.5),
    (re.compile(r"Method\.invoke\s*\(", re.IGNORECASE | re.DOTALL), 8.5),
    (re.compile(r"response\.getWriter\s*\(", re.IGNORECASE | re.DOTALL), 7.0),
    (re.compile(r"ObjectInputStream\s*\(", re.IGNORECASE | re.DOTALL), 8.5),
    (re.compile(r"readObject\s*\(", re.IGNORECASE | re.DOTALL), 8.5),
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


def _node(name: str, filepath: str, line: int) -> dict[str, Any]:
    return {"name": name, "file": filepath, "line": line}


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


def _search_text(body: str) -> str:
    """Single string for regex: preserve newlines and also offer collapsed whitespace."""
    impl = _method_body_only(body)
    collapsed = re.sub(r"\s+", " ", impl.replace("\r\n", "\n"))
    return f"{impl}\n{collapsed}"


def _body_has_sink(body: str) -> bool:
    text = _search_text(body)
    for pattern, _ in SINK_PATTERNS:
        if pattern.search(text):
            return True
    return False


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

        category = _classify_method(name, annotations, body, filepath=filepath)
        result[category].append(_node(name, filepath, line))

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
) -> str:
    if _debug_enabled() and _is_ping_action(filepath):
        print(
            f"[java_parser] PingAction classify: method={name!r} "
            f"annotations={sorted(annotations)} body_len={len(body)}"
        )
        print(f"[java_parser] PingAction raw body for {name!r}:\n{body}\n---")

    if annotations & GUARD_ANNOTATIONS or any(
        name.lower().startswith(prefix) for prefix in GUARD_NAME_PREFIXES
    ):
        category = "guard"
    elif _body_has_sink(body):
        category = "sink"
    elif (
        name == "main"
        or annotations & ENTRY_ANNOTATIONS
        or name in STRUTS_ENTRY_METHODS
        or _body_has_source(body)
    ):
        category = "entry"
    else:
        category = "normal"

    if _debug_enabled() and _is_ping_action(filepath) and name == "getCommandOutput":
        graph_type = {"entry": "source", "sink": "sink", "guard": "sanitizer", "normal": "normal"}[category]
        print(f"[java_parser] PingAction getCommandOutput() graph type={graph_type!r} (category={category!r})")

    return category


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

            category = _classify_method(name, annotations, body, filepath=filepath)
            result[category].append(_node(name, filepath, line_no))
            pending_annotations = []
            i = next_i
            continue

        if line.strip() and not line.strip().startswith("@"):
            pending_annotations = []
        i += 1

    return result


def parse_java_file(filepath: str) -> dict[str, list[dict[str, Any]]]:
    path = Path(filepath)
    if not path.exists() or path.suffix.lower() != ".java":
        return _empty_result()

    _javap_available()

    parsed = _run_javaparser_cli(str(path))
    if parsed is not None:
        return parsed

    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return _empty_result()

    return _extract_methods_regex(content, str(path.resolve()))
