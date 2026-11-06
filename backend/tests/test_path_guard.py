import os
import tempfile
import pytest
from pathlib import Path
from fastapi import HTTPException
from fastapi.testclient import TestClient

from backend.services.path_guard import (
    register_scanned_root,
    get_scanned_roots,
    clear_scanned_roots,
    get_allowed_roots,
    is_safe_file_path,
    resolve_allowed_repo,
)
from backend.main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_roots():
    clear_scanned_roots()
    yield
    clear_scanned_roots()


def test_outside_allowed_roots_raises_403():
    # An arbitrary directory outside CWD, scanned roots, or allowed env
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir).resolve()
        # Verify not inside CWD
        cwd = Path.cwd().resolve()
        assert not tmp_path.is_relative_to(cwd)

        with pytest.raises(HTTPException) as exc_info:
            resolve_allowed_repo(str(tmp_path))
        assert exc_info.value.status_code == 403
        assert "Path not allowed" in exc_info.value.detail


def test_traversal_attempts_raise_403():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Register a subfolder inside tmpdir
        sub = Path(tmpdir) / "project"
        sub.mkdir()
        register_scanned_root(sub)

        # Attempt to escape using ../
        traversal_path = str(sub / ".." / ".." / "some_secret")
        with pytest.raises(HTTPException) as exc_info:
            resolve_allowed_repo(traversal_path)
        assert exc_info.value.status_code == 403


def test_symlink_pointing_outside_raises_403():
    with tempfile.TemporaryDirectory() as outside_dir:
        with tempfile.TemporaryDirectory() as project_dir:
            p_proj = Path(project_dir).resolve()
            register_scanned_root(p_proj)

            outside_target = Path(outside_dir).resolve() / "outside_target"
            outside_target.mkdir()

            link_path = p_proj / "link_to_outside"
            try:
                link_path.symlink_to(outside_target, target_is_directory=True)
            except (OSError, NotImplementedError):
                pytest.skip("Symlink creation not permitted or supported in this environment")

            # Resolving the symlink should resolve to outside_dir, raising 403
            with pytest.raises(HTTPException) as exc_info:
                resolve_allowed_repo(str(link_path))
            assert exc_info.value.status_code == 403


def test_scanned_project_root_succeeds():
    with tempfile.TemporaryDirectory() as tmpdir:
        p = Path(tmpdir).resolve()
        register_scanned_root(p)
        resolved = resolve_allowed_repo(str(p))
        assert resolved == p


def test_git_parent_of_scanned_child_succeeds():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_root = Path(tmpdir).resolve()
        git_dir = repo_root / ".git"
        git_dir.mkdir()

        child = repo_root / "src" / "subproject"
        child.mkdir(parents=True)
        register_scanned_root(child)

        # Querying with repo_root (which contains .git and contains child) must be allowed
        resolved = resolve_allowed_repo(str(repo_root))
        assert resolved == repo_root


def test_allowed_but_nonexistent_path_raises_404():
    cwd = Path.cwd().resolve()
    nonexistent = cwd / "non_existent_directory_for_test_12345"
    assert not nonexistent.exists()

    with pytest.raises(HTTPException) as exc_info:
        resolve_allowed_repo(str(nonexistent))
    assert exc_info.value.status_code == 404
    assert "Path not found" in exc_info.value.detail


def test_is_safe_file_path():
    cwd = Path.cwd().resolve()
    safe_file = cwd / "backend" / "main.py"
    assert is_safe_file_path(safe_file) is True

    with tempfile.TemporaryDirectory() as tmpdir:
        outside_file = Path(tmpdir).resolve() / "secret.txt"
        outside_file.write_text("secret")
        assert is_safe_file_path(outside_file) is False


def test_api_git_timeline_outside_allowed_returns_403():
    with tempfile.TemporaryDirectory() as tmpdir:
        res = client.get("/api/git/timeline", params={"project_path": tmpdir})
        assert res.status_code == 403


def test_api_tdra_timeline_outside_allowed_returns_403():
    with tempfile.TemporaryDirectory() as tmpdir:
        res = client.get("/api/tdra/timeline", params={"repo_path": tmpdir})
        assert res.status_code == 403


def test_api_file_source_outside_allowed_returns_403():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test.py"
        test_file.write_text("print('test')")
        res = client.get("/api/file/source", params={"filepath": str(test_file)})
        assert res.status_code == 403


def test_mock_timeline_never_indexed_in_rag():
    import inspect
    from backend.routers import scan
    source = inspect.getsource(scan.scan)
    # Verify mock_tdra_data is never used in scan
    assert "get_mock_timeline" not in source
    assert "tdra_results = []" in source

