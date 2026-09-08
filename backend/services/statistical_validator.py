import numpy as np
from scipy.stats import mannwhitneyu

def compute_cliffs_delta(group1: list[float], group2: list[float]) -> float:
    n1, n2 = len(group1), len(group2)
    if n1 == 0 or n2 == 0: return 0.0
    greater = sum(1 for a in group1 for b in group2 if a > b)
    lesser = sum(1 for a in group1 for b in group2 if a < b)
    return round((greater - lesser) / (n1 * n2), 4)

def compute_cles(group1: list[float], group2: list[float]) -> float:
    """
    Common Language Effect Size (CLES / AUC Probability of Superiority).
    Represents the statistical probability that a score from group 1 > group 2.
    Strictly bounded in [0, 1].
    """
    n1, n2 = len(group1), len(group2)
    if n1 == 0 or n2 == 0: return 0.5
    greater = sum(1 for a in group1 for b in group2 if a > b)
    ties = sum(1 for a in group1 for b in group2 if a == b)
    return round((greater + 0.5 * ties) / (n1 * n2), 4)

def classify_effect(delta: float) -> str:
    a = abs(delta)
    if a > 0.474: return "large"
    if a > 0.330: return "medium"
    if a > 0.147: return "small"
    return "negligible"

def validate_risk_scores(vcc: list[float], non_vcc: list[float]) -> dict:
    if not vcc:
        return {
            "error": "No matching VCC commits found in analyzed history",
            "detail": "None of the specified commit hashes were matched in the repository history.",
            "statistically_significant": False,
            "sample_sizes": {"vcc": 0, "non_vcc": len(non_vcc)},
            "vcc_mean": 0.0,
            "non_vcc_mean": round(float(np.mean(non_vcc)), 4) if non_vcc else 0.0,
            "vcc_median": 0.0,
            "non_vcc_median": round(float(np.median(non_vcc)), 4) if non_vcc else 0.0,
            "cliffs_delta": 0.0,
            "p_value": 1.0,
            "effect_size": "—",
            "verdict": "[ERROR] No VCC Commits Found",
            "interpretation": "Please verify that the commit hashes exist in the target repository.",
        }

    if not non_vcc:
        return {
            "error": "No non-VCC baseline commits available",
            "detail": "At least one non-VCC baseline commit is required for comparison.",
            "statistically_significant": False,
            "sample_sizes": {"vcc": len(vcc), "non_vcc": 0},
            "vcc_mean": round(float(np.mean(vcc)), 4),
            "non_vcc_mean": 0.0,
            "vcc_median": round(float(np.median(vcc)), 4),
            "non_vcc_median": 0.0,
            "cliffs_delta": 0.0,
            "p_value": 1.0,
            "effect_size": "—",
            "verdict": "[ERROR] Baseline Comparison Missing",
            "interpretation": "Need non-VCC commits in history to establish baseline risk comparison.",
        }

    stat = None
    p_val = 1.0
    try:
        mw_res, p = mannwhitneyu(vcc, non_vcc, alternative="greater")
        stat = round(float(mw_res), 4)
        p_val = round(float(p), 6)
    except Exception:
        pass

    d = compute_cliffs_delta(vcc, non_vcc)
    cles = compute_cles(vcc, non_vcc)
    eff = classify_effect(d)
    sig = bool(p_val < 0.05)

    vcc_mean = round(float(np.mean(vcc)), 4)
    non_vcc_mean = round(float(np.mean(non_vcc)), 4)
    vcc_median = round(float(np.median(vcc)), 4)
    non_vcc_median = round(float(np.median(non_vcc)), 4)

    is_single_sample = len(vcc) == 1

    if sig and abs(d) > 0.147:
        if is_single_sample:
            verdict = "[VALIDATED] Directional Separation (n=1)"
            interp = (
                f"VCC commit risk ({vcc_mean:.2f}) significantly exceeds non-VCC baseline "
                f"({non_vcc_mean:.2f}, p={p_val:.4f}, δ={d:.4f}, {eff} effect). "
                f"Directionally validated (≥2 VCC samples recommended for full hypothesis testing)."
            )
        else:
            verdict = "[VALIDATED] TDRA Statistical Separation Confirmed"
            interp = (
                f"RF scores significantly separate VCC from non-VCC commits "
                f"(p={p_val:.4f} < 0.05, δ={d:.4f}, {eff} effect)."
            )
    else:
        if is_single_sample:
            verdict = "[INCONCLUSIVE] Not Statistically Significant (n=1)"
            interp = (
                f"VCC commit RF score ({vcc_mean:.2f}) does not significantly exceed non-VCC baseline "
                f"(baseline mean: {non_vcc_mean:.2f}, p={p_val:.4f}, δ={d:.4f})."
            )
        else:
            verdict = "[INCONCLUSIVE] Not Statistically Significant"
            interp = (
                f"RF scores do not significantly separate VCC from non-VCC commits "
                f"(p={p_val:.4f}, δ={d:.4f}, {eff} effect)."
            )

    return {
        "mann_whitney_u": stat,
        "p_value": p_val,
        "cliffs_delta": d,
        "cles": cles,
        "normalized_effect_size": round(abs(d), 4),
        "probability_of_superiority": cles,
        "effect_size": eff,
        "statistically_significant": sig,
        "verdict": verdict,
        "interpretation": interp,
        "vcc_mean": vcc_mean,
        "non_vcc_mean": non_vcc_mean,
        "vcc_median": vcc_median,
        "non_vcc_median": non_vcc_median,
        "sample_sizes": {"vcc": len(vcc), "non_vcc": len(non_vcc)},
    }
