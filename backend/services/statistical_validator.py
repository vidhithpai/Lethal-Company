import numpy as np
from scipy.stats import mannwhitneyu

def compute_cliffs_delta(group1: list[float], group2: list[float]) -> float:
    n1, n2 = len(group1), len(group2)
    if n1 == 0 or n2 == 0: return 0.0
    greater = sum(1 for a in group1 for b in group2 if a > b)
    return round((2 * greater - n1 * n2) / (n1 * n2), 4)

def classify_effect(delta: float) -> str:
    a = abs(delta)
    if a > 0.474: return "large"
    if a > 0.330: return "medium"
    if a > 0.147: return "small"
    return "negligible"

def validate_risk_scores(vcc: list[float], non_vcc: list[float]) -> dict:
    if len(vcc) < 2 or len(non_vcc) < 2:
        return {"error": "Need ≥2 samples in each group",
                "vcc_count": len(vcc), "non_vcc_count": len(non_vcc)}
    stat, p = mannwhitneyu(vcc, non_vcc, alternative="greater")
    d = compute_cliffs_delta(vcc, non_vcc)
    sig = bool(p < 0.05)
    return {
        "mann_whitney_u": round(float(stat), 4),
        "p_value": round(float(p), 6),
        "cliffs_delta": d,
        "effect_size": classify_effect(d),
        "statistically_significant": sig,
        "verdict": "TDRA VALIDATED" if sig and abs(d) > 0.147 else "NOT SIGNIFICANT",
        "interpretation": (
            f"RF scores {'DO' if sig else 'do NOT'} significantly separate "
            f"VCC from non-VCC commits "
            f"(p={'< 0.05' if sig else '≥ 0.05'}, δ={d}, {classify_effect(d)} effect)."
        ),
        "vcc_mean": round(float(np.mean(vcc)), 4),
        "non_vcc_mean": round(float(np.mean(non_vcc)), 4),
        "vcc_median": round(float(np.median(vcc)), 4),
        "non_vcc_median": round(float(np.median(non_vcc)), 4),
        "sample_sizes": {"vcc": len(vcc), "non_vcc": len(non_vcc)},
    }
