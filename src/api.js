const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

export const endpoints = {
  graph: `${API_BASE}/api/graph`,
  graphPath: `${API_BASE}/api/graph/path`,
  patchNode: (nodeId) => `${API_BASE}/api/graph/patch/${encodeURIComponent(nodeId)}`,
  ask: `${API_BASE}/api/query/ask`,
  scan: `${API_BASE}/api/cve/scan`,
  scanUpload: `${API_BASE}/api/cve/scan/upload`,
  useMock: `${API_BASE}/api/graph/use-mock`
};

export const normalizeGraph = (payload) => ({
  nodes: payload?.nodes || [],
  links: payload?.links || payload?.edges || []
});
