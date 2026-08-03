"""
statistical_validator.py
========================
Core statistical validation for the TDRA research paper.
Tests whether the RF formula correctly separates VCC commits
from non-VCC commits using Mann-Whitney U and Cliff's delta.
"""
from __future__ import annotations

import numpy as np
from scipy.stats import mannwhitneyu


def compute_cliffs_delta(group1: list[float], group2: list[float]) -> float:
    """
    Effect size measure: proportion of (g1, g2) pairs where g1 > g2.
    Range: [-1, +1]. Positive value means group1 tends to have higher values.
    """
    n1, n2 = len(group1), len(group2)
    if n1 == 0 or n2 == 0:
        return 0.0
    pairs_greater = sum(1 for a in group1 for b in group2 if a > b)
    return round((2 * pairs_greater - n1 * n2) / (n1 * n2), 4)


def classify_effect_size(delta: float) -> str:
    """Cliff's delta thresholds per Romano et al. (2006)."""
    abs_d = abs(delta)
    if abs_d > 0.474:
        return "large"
    elif abs_d > 0.33:
        return "medium"
    elif abs_d > 0.147:
        return "small"
    else:
        return "negligible"


def validate_risk_scores(
    vcc_scores: list[float],      # RF scores of known CVE-linked commits
    non_vcc_scores: list[float],  # RF scores of normal commits
) -> dict:
    """
    Tests whether TDRA correctly scores VCC commits higher than non-VCC.

    Uses one-sided Mann-Whitney U (H1: VCC RF > non-VCC RF) and Cliff's delta
    for effect size. Both are non-parametric, making no distribution assumptions.

    Returns
    -------
    dict with full statistical report suitable for publication.
    """
    if len(vcc_scores) < 2 or len(non_vcc_scores) < 2:
        return {"error": "Need at least 2 samples in each group"}

    stat, p_value = mannwhitneyu(
        vcc_scores, non_vcc_scores, alternative="greater"
    )
    cliffs_d = compute_cliffs_delta(vcc_scores, non_vcc_scores)
    effect_size = classify_effect_size(cliffs_d)
    significant = bool(p_value < 0.05)  # cast numpy.bool_ → Python bool

    return {
        "mann_whitney_u_statistic": round(float(stat), 4),
        "p_value": round(float(p_value), 6),
        "cliffs_delta": float(cliffs_d),
        "effect_size_label": effect_size,
        "statistically_significant": significant,
        "interpretation": (
            f"TDRA RF scores {'successfully' if significant else 'do not'} "
            f"separate VCC from non-VCC commits "
            f"(p={'< 0.05' if significant else '≥ 0.05'}, "
            f"Cliff's δ={cliffs_d}, {effect_size} effect)."
        ),
        "vcc_mean_rf": round(float(np.mean(vcc_scores)), 4),
        "non_vcc_mean_rf": round(float(np.mean(non_vcc_scores)), 4),
        "vcc_median_rf": round(float(np.median(vcc_scores)), 4),
        "non_vcc_median_rf": round(float(np.median(non_vcc_scores)), 4),
        "sample_sizes": {"vcc": len(vcc_scores), "non_vcc": len(non_vcc_scores)},
    }
