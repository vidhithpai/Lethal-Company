import os
import sys
from pathlib import Path

# Ensure backend can be imported
sys.path.insert(0, str(Path(".").resolve()))

from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_commit_graph_diff_endpoint():
    repo_path = "demo_project"
    commit_hash = "9729e0f"

    # Test 1: Valid commit
    res = client.get(f"/api/tdra/commit-graph-diff?repo_path={repo_path}&commit={commit_hash}")
    print("Valid commit response status:", res.status_code)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert "commit" in data
    assert "nodes" in data
    assert "edges" in data
    assert "removed_nodes" in data
    assert "removed_edges" in data
    assert "weakened" in data
    assert "truncated" in data
    print(f"Data summary: {len(data['nodes'])} nodes, {len(data['edges'])} edges, {len(data['removed_nodes'])} removed nodes, {len(data['weakened'])} weakened guards")

    # Test 2: Invalid commit hash regex validation (reject non-hex / wrong length)
    res_bad = client.get(f"/api/tdra/commit-graph-diff?repo_path={repo_path}&commit=invalid;hash!")
    print("Invalid commit status:", res_bad.status_code)
    assert res_bad.status_code == 400

    # Test 3: Missing repo_path
    res_no_repo = client.get(f"/api/tdra/commit-graph-diff?repo_path=nonexistent_dir_xyz&commit={commit_hash}")
    print("Missing repo status:", res_no_repo.status_code)
    assert res_no_repo.status_code == 404

    # Test 4: Commit with no TDRA data (dummy commit hash)
    # If commit exists in git, e.g. b30d12f
    res_b30 = client.get(f"/api/tdra/commit-graph-diff?repo_path={repo_path}&commit=b30d12f")
    assert res_b30.status_code == 200
    data_b30 = res_b30.json()
    assert isinstance(data_b30["nodes"], dict)
    assert isinstance(data_b30["removed_nodes"], list)
    print("b30d12f success:", len(data_b30["nodes"]), "nodes diffed")

    print("ALL BACKEND TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_commit_graph_diff_endpoint()

