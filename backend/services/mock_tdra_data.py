"""
Mock TDRA data — used when no .git repo is available (demos, CI without git history).
"""
from datetime import datetime, timedelta

def get_mock_timeline() -> list[dict]:
    base = datetime(2025, 1, 15)
    raw = [
        ("a1b2c3d", "Alice Chen",    "Add user search endpoint",            0.82, 3, 1, "Critical"),
        ("e4f5g6h", "Bob Kumar",     "Refactor DB connection pool",         0.61, 2, 0, "High"),
        ("i7j8k9l", "Alice Chen",    "Fix login redirect bug",              0.41, 1, 1, "Medium"),
        ("m1n2o3p", "Carlos Ruiz",   "Add input sanitizer utility",         0.08, 0, 0, "Low"),
        ("q4r5s6t", "Bob Kumar",     "Implement file upload feature",       0.73, 2, 2, "Critical"),
        ("u7v8w9x", "Diana Park",    "Update Spring Boot dependencies",     0.12, 0, 0, "Low"),
        ("y1z2a3b", "Carlos Ruiz",   "Add admin management API endpoint",   0.55, 2, 0, "High"),
        ("c4d5e6f", "Alice Chen",    "Integrate third-party OAuth flow",    0.38, 1, 1, "Medium"),
        ("g7h8i9j", "Diana Park",    "Remove deprecated REST endpoint",     0.04, 0, 0, "Low"),
        ("k1l2m3n", "Bob Kumar",     "Add dynamic command execution handler", 0.91, 4, 2, "Critical"),
    ]
    results = []
    for i, (h, author, msg, rf, np_, gw, sev) in enumerate(raw):
        full_hash = h + "0" * (40 - len(h))
        results.append({
            "commit_hash": full_hash,
            "parent_hash": "parent" + full_hash[:7],
            "author": author,
            "date": (base + timedelta(days=i * 6)).isoformat(),
            "message": msg,
            "changed_files": ["src/main/java/com/example/App.java"],
            "diff_lines_changed": 12 + i * 3,
            "new_attack_paths": np_,
            "guard_weakening_events": gw,
            "paths_before": max(2, 5 - i % 3),
            "paths_after": max(2, 5 - i % 3) + np_,
            "risk_factor": rf,
            "severity": sev,
            "total_attenuation_drop": round(gw * 0.35, 4),
            "guard_regression_score": round(gw * 0.18, 4),
            "path_expansion_score": round(rf * 0.6, 4),
            "new_paths_detail": [
                [f"source:handleRequest_{i}", f"method:process_{i}", f"sink:execute_{i}"]
            ] if np_ > 0 else [],
            "analysis_method": "mock",
        })
    return results


def get_mock_risk_summary(timeline: list[dict]) -> dict:
    if not timeline:
        return {
            "total_commits_analyzed": 0,
            "critical_commits": [],
            "high_commits": [],
            "riskiest_commit": None,
            "avg_risk_factor": 0.0,
            "total_new_paths_introduced": 0,
            "total_guard_weakening_events": 0,
        }
    critical = [c for c in timeline if c["risk_factor"] >= 0.7]
    high = [c for c in timeline if 0.45 <= c["risk_factor"] < 0.7]
    sorted_rf = sorted(timeline, key=lambda x: x["risk_factor"], reverse=True)
    return {
        "total_commits_analyzed": len(timeline),
        "critical_commits": critical,
        "high_commits": high,
        "riskiest_commit": sorted_rf[0],
        "avg_risk_factor": round(sum(c["risk_factor"] for c in timeline) / len(timeline), 4),
        "total_new_paths_introduced": sum(c["new_attack_paths"] for c in timeline),
        "total_guard_weakening_events": sum(c["guard_weakening_events"] for c in timeline),
        "source": "mock",
    }
