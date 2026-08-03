# Related Work & Gaps Filled by TDRA

This document lists 8 foundational static analysis and vulnerability attribution papers and details the specific research gaps they leave that TDRA successfully addresses:

1. **Yamaguchi et al. (2014) — *"Modeling and Discovering Vulnerabilities with Code Property Graphs"* (CPG)**
   - *Gap*: Constructs static snapshots of code graphs for vulnerability discovery but lacks temporal version-aware tracking, preventing automatic attribution of vulnerability emergence or remediation to specific commits.
   - *TDRA Fill*: Implements temporal differential reachability analysis to compare graphs between consecutive commits, directly identifying the exact version where new attack paths appear.

2. **Saha et al. (2018) — *"Regression Testing for Vulnerabilities"* **
   - *Gap*: Focuses on dynamic testing and fuzzing of regression paths but does not trace version-controlled graph structural changes, leading to high test suite execution overhead.
   - *TDRA Fill*: Uses deterministic, lightweight static graph reachability differentials to find security regressions instantly without executing code.

3. **Meneely et al. (2012) — *"Interactive Vulnerability Testing"* **
   - *Gap*: Relies on developers manually checking commits for vulnerability introduction (VCCs) without structural graph-reachability automation.
   - *TDRA Fill*: Automatically labels VCCs and evaluates their structural significance using an algorithmic Risk Factor (RF) metric.

4. **Li et al. (2018) — *"VulDeePecker: A Deep Learning-Based System for Vulnerability Detection"* **
   - *Gap*: Uses deep learning on static slice representations which acts as a black box and fails to attribute changes to commits or explain semantic remediation strategies.
   - *TDRA Fill*: Employs a deterministic, interpretable structural reachability graph with explicit guard-density analysis and localized remediation recommendations.

5. **Fan et al. (2020) — *"A Deep Learning System for Commit-Level Vulnerability Detection"* **
   - *Gap*: Predicts vulnerability-introducing commits using natural language processing on commit messages and code diffs but lacks awareness of interprocedural control and data flow changes.
   - *TDRA Fill*: Tracks true semantic interprocedural data-flow reachability changes across commits.

6. **Chess & West (2007) — *"Secure Programming with Static Analysis"* **
   - *Gap*: Proposes static taint analysis on a per-snapshot basis, forcing security engineers to triage duplicate findings across versions.
   - *TDRA Fill*: Filters out static noise by focusing exclusively on newly introduced or modified attack paths.

7. **Sadowski et al. (2018) — *"Tricorder: Program Analysis at Scale"* **
   - *Gap*: Integrates static analyzers into code review platforms but does not perform graph-reachability differential analysis to compute risk scores based on guard weakening.
   - *TDRA Fill*: Evaluates the impact of diffs on sanitization points (guards) to compute a normalized change risk score ($RF$).

8. **Zhou & Croft (2021) — *"Vulnerability-Contributing Commit Identification"* **
   - *Gap*: Focuses on retrospective identification of VCCs using software repository mining and metadata heuristics rather than immediate graph-structural taint analysis.
   - *TDRA Fill*: Validates VCCs deterministically at commit time using Mann-Whitney U validation of structural RF scores.
