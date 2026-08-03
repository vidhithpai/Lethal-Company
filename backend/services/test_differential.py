import os
import sys
import shutil
import subprocess
from pathlib import Path

# Add project root to python path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import git
import networkx as nx
from backend.services.differential_engine import DifferentialEngine

def setup_test_repo() -> str:
    test_dir = Path("/tmp/test_git_repo")
    if test_dir.exists():
        shutil.rmtree(test_dir)
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Init git
    subprocess.check_call(["git", "init", "-b", "main"], cwd=str(test_dir))
    subprocess.check_call(["git", "config", "user.name", "Test User"], cwd=str(test_dir))
    subprocess.check_call(["git", "config", "user.email", "test@example.com"], cwd=str(test_dir))
    
    # Commit 1: baseline without vulnerability
    file_path = test_dir / "app.py"
    file_content_1 = """def run():
    print("Hello world")
"""
    file_path.write_text(file_content_1)
    subprocess.check_call(["git", "add", "app.py"], cwd=str(test_dir))
    subprocess.check_call(["git", "commit", "-m", "First commit"], cwd=str(test_dir))
    
    # Commit 2: introduce a vulnerability (source to sink)
    file_content_2 = """def run():
    x = input()
    eval(x)
"""
    file_path.write_text(file_content_2)
    subprocess.check_call(["git", "add", "app.py"], cwd=str(test_dir))
    subprocess.check_call(["git", "commit", "-m", "Introduce vulnerability"], cwd=str(test_dir))
    
    return str(test_dir)

def run_test():
    repo_path = setup_test_repo()
    print(f"Test repo setup at: {repo_path}")
    
    try:
        engine = DifferentialEngine(repo_path)
        pairs = engine.get_commit_pairs(limit=5)
        print(f"Found commit pairs: {pairs}")
        
        if not pairs:
            print("Error: No commit pairs found.")
            sys.exit(1)
            
        parent_hash, commit_hash = pairs[0]
        print(f"Analyzing pair: {parent_hash} -> {commit_hash}")
        
        res = engine.analyze_commit(parent_hash, commit_hash)
        print("Analysis Result:")
        import pprint
        pprint.pprint(res)
        
        # Validate result fields
        assert res["commit_hash"] == commit_hash
        assert res["parent_hash"] == parent_hash
        assert res["new_attack_paths"] > 0, "Should have detected the new attack path!"
        assert res["risk_factor"] > 0, "Risk factor should be > 0"
        print("SUCCESS: Differential analysis validated successfully!")
    except Exception as e:
        print(f"Test failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Clean up
        if Path(repo_path).exists():
            shutil.rmtree(repo_path)

if __name__ == "__main__":
    run_test()
