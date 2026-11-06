import os
import tempfile
from pathlib import Path
from typing import Union
from fastapi import HTTPException

# In-memory registry of paths scanned during the server lifecycle
_SCANNED_ROOTS: set[Path] = set()


def register_scanned_root(path: Union[str, Path, None]) -> Path | None:
    """Register a project root as having been scanned."""
    if not path:
        return None
    try:
        p = Path(path).resolve()
        _SCANNED_ROOTS.add(p)
        return p
    except Exception:
        return None


def get_scanned_roots() -> set[Path]:
    """Return all currently registered scanned project roots."""
    return set(_SCANNED_ROOTS)


def clear_scanned_roots() -> None:
    """Clear scanned roots (primarily for testing)."""
    _SCANNED_ROOTS.clear()


def get_allowed_roots() -> list[Path]:
    """
    Compute all allowed base directories:
    - Previously scanned project roots
    - Current working directory
    - VULNGRAPH_ALLOWED_ROOTS environment variable (split by os.pathsep)
    - Default uploads and container paths if they exist
    """
    roots: list[Path] = []

    # 1. Registered scanned roots
    for sr in _SCANNED_ROOTS:
        if sr not in roots:
            roots.append(sr)

    # 2. Currently active security root from code_security_graph (if set)
    try:
        from backend.services.code_security_graph import get_security_root
        sec_root = get_security_root()
        if sec_root:
            r = Path(sec_root).resolve()
            if r not in roots:
                roots.append(r)
    except Exception:
        pass

    # 3. Current working directory
    cwd = Path.cwd().resolve()
    if cwd not in roots:
        roots.append(cwd)

    # 4. Environment variable VULNGRAPH_ALLOWED_ROOTS
    env_roots = os.environ.get("VULNGRAPH_ALLOWED_ROOTS", "").strip()
    if env_roots:
        for entry in env_roots.split(os.pathsep):
            entry = entry.strip()
            if entry:
                try:
                    p = Path(entry).resolve()
                    if p not in roots:
                        roots.append(p)
                except Exception:
                    pass

    # 5. Standard uploads and temporary directories
    try:
        up1 = Path("/tmp/vulngraph_uploads").resolve()
        if up1 not in roots:
            roots.append(up1)
    except Exception:
        pass

    try:
        up2 = (Path(tempfile.gettempdir()) / "vulngraph_uploads").resolve()
        if up2 not in roots:
            roots.append(up2)
    except Exception:
        pass

    if Path("/app").exists():
        try:
            app_p = Path("/app").resolve()
            if app_p not in roots:
                roots.append(app_p)
        except Exception:
            pass

    if Path("/host").exists():
        try:
            host_p = Path("/host").resolve()
            if host_p not in roots:
                roots.append(host_p)
        except Exception:
            pass

    return roots


def is_safe_file_path(target_file: Path) -> bool:
    """Check if target_file is inside any allowed root."""
    try:
        resolved = target_file.resolve()
    except Exception:
        return False

    for ar in get_allowed_roots():
        try:
            if resolved == ar or resolved.is_relative_to(ar):
                return True
        except (ValueError, AttributeError):
            # Fallback for Python < 3.9 if ever needed
            norm_res = str(resolved).replace("\\", "/").lower()
            norm_ar = str(ar).replace("\\", "/").lower()
            if norm_res.startswith(norm_ar.rstrip("/") + "/"):
                return True

    return False


def resolve_allowed_repo(path: Union[str, Path, None]) -> Path:
    """
    Validate and resolve repo_path / project_path:
    - Resolves with Path.resolve() (defeats ../ and symlink tricks)
    - Allows path only if inside a previously scanned root, current working directory,
      or VULNGRAPH_ALLOWED_ROOTS.
    - Also allows a git parent of a scanned project root if it contains .git and
      the scanned root is inside it.
    - Raises HTTPException(403, "Path not allowed") if unauthorized.
    - Raises HTTPException(404, "Path not found") if authorized but does not exist.
    """
    if path is None or str(path).strip() == "":
        raise HTTPException(status_code=400, detail="repo_path or project_path is required")

    try:
        resolved = Path(path).resolve()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid path: {e}")

    # Check if path is allowed
    is_allowed = False

    # 1. Check if inside or equal to any allowed root
    for ar in get_allowed_roots():
        try:
            if resolved == ar or resolved.is_relative_to(ar):
                is_allowed = True
                break
        except (ValueError, AttributeError):
            norm_res = str(resolved).replace("\\", "/").lower()
            norm_ar = str(ar).replace("\\", "/").lower()
            if norm_res == norm_ar or norm_res.startswith(norm_ar.rstrip("/") + "/"):
                is_allowed = True
                break

    # 2. Check if path is a git parent of any scanned root
    if not is_allowed:
        for sr in _SCANNED_ROOTS:
            try:
                # sr is inside resolved
                if sr.is_relative_to(resolved):
                    # Check if resolved contains a .git directory (or file in case of git worktree)
                    git_dir = resolved / ".git"
                    if git_dir.exists():
                        is_allowed = True
                        break
            except Exception:
                pass

    if not is_allowed:
        raise HTTPException(status_code=403, detail=f"Path not allowed: {path}")

    if not resolved.exists():
        raise HTTPException(status_code=404, detail=f"Path not found: {resolved}")

    return resolved

