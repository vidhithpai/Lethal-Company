# VulnGraph Changelog

## 0.2.0
- Full TDRA differential analysis integration
- 5 decoration types: ENTRY, SINK, GUARD, CRITICAL SINK, NEW PATH
- Risk dashboard with 3 tabs: commit timeline, sink analysis, validation
- Statistical validation: Mann-Whitney U + Cliff's delta inline
- Pre-commit risk check command in Source Control panel
- Git diff-scoped analysis: O(diff) not O(repo)
- Guard-aware attenuation model with CWE classification
- Cross-file Spring MVC attack path detection
- Report export as HTML
- Click commit → view diff in VS Code git panel
- "Open 3D view" → launches web UI at localhost:5173

## 0.1.5
- Initial ENTRY/SINK/GUARD inline decorations
- On-save analysis trigger
