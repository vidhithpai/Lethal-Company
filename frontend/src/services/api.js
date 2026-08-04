export const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8002";

export const endpoints = {
  graph: `${API_BASE}/api/graph`,
  graphPath: `${API_BASE}/api/graph/path`,
  attackPaths: `${API_BASE}/api/attack-paths`,
  highRiskPaths: `${API_BASE}/api/high-risk-paths`,
  patchNode: (nodeId) => `${API_BASE}/api/graph/patch/${encodeURIComponent(nodeId)}`,
  ask: `${API_BASE}/api/query/ask`,
  explainNode: `${API_BASE}/api/query/explain-node`,
  scan: `${API_BASE}/api/cve/scan`,
  scanUpload: `${API_BASE}/api/cve/scan/upload`,
  scanStatus: `${API_BASE}/api/cve/scan/status`,
  useMock: `${API_BASE}/api/graph/use-mock`,
  gitBlame: (projectPath) => `${API_BASE}/api/git/blame?project_path=${encodeURIComponent(projectPath)}`,
  gitTimeline: (projectPath, filepath) =>
    `${API_BASE}/api/git/timeline?project_path=${encodeURIComponent(projectPath)}&filepath=${encodeURIComponent(filepath)}`,
  tdraAnalyze: `${API_BASE}/api/tdra/analyze`,
  tdraRiskSummary: (repoPath, limit = 20) => `${API_BASE}/api/tdra/risk-summary?repo_path=${encodeURIComponent(repoPath)}&limit=${limit}`,
  tdraCommit: (commitHash, repoPath) => `${API_BASE}/api/tdra/commit/${encodeURIComponent(commitHash)}?repo_path=${encodeURIComponent(repoPath)}`,
  tdraPathContributions: (commitHash, repoPath) => `${API_BASE}/api/tdra/commit/${encodeURIComponent(commitHash)}/path-contributions?repo_path=${encodeURIComponent(repoPath)}`,
  tdraTimeline: (repoPath, limit = 50) => `${API_BASE}/api/tdra/timeline?repo_path=${encodeURIComponent(repoPath)}&limit=${limit}`,
};

export const normalizeGraph = (payload) => ({
  nodes: (payload?.nodes || []).map((n) => ({ ...n, id: n.id || String(n.id) })),
  links: payload?.links || payload?.edges || [],
});
