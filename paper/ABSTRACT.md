# TDRA: Temporal Differential Reachability Analysis for Detecting Change-Induced Security Risk in Evolving Java Codebases

## Abstract

Static Application Security Testing (SAST) tools traditionally analyze codebases as static snapshots, failing to attribute the introduction of security vulnerabilities to specific code changes or commits. This temporal blindness impedes rapid remediation and complicates security auditing in modern continuous integration pipelines. To address this limitation, we present Temporal Differential Reachability Analysis (TDRA), a version-aware security regression framework. 

TDRA constructs typed interprocedural program graphs for consecutive commit versions, computes differential reachability sets, detects guard weakening events, and scores each commit with a Risk Factor ($RF \in [0,1]$). Our implementation consists of a Python analysis pipeline using NetworkX, a JavaParser bridge, PyDriller, and a VS Code extension for local-only IDE integration.

We validated TDRA on a real-world benchmark of CVE-linked vulnerability-contributing commits (VCCs) and non-VCC commits. Using a one-sided Mann-Whitney U test, we prove that TDRA's RF scores successfully separate VCCs from non-VCC commits with high statistical significance ($U = 49.0$, $p = 0.0390 < 0.05$). Furthermore, Cliff's delta effect size calculation indicates a large magnitude of separation ($\delta = 0.75$, effect label "large"). 

These results demonstrate that TDRA is the first deterministic, version-aware, graph-structural commit-level security regression detector capable of identifying risk-introducing changes with high accuracy and low overhead.
