import { create } from "zustand";

export const MOCK_GRAPH = {
  nodes: [
    { id: "internet", label: "Internet", type: "external" },
    { id: "firewall", label: "Firewall", type: "network" },
    { id: "webserver", label: "Web Server", type: "server" },
    { id: "appserver", label: "App Server", type: "server" },
    { id: "database", label: "Database", type: "data" },
    { id: "cache", label: "Cache", type: "data" }
  ],
  links: [
    { source: "internet", target: "firewall", cve: "CVE-2023-44487", severity: "HIGH" },
    { source: "firewall", target: "webserver", cve: "CVE-2024-21626", severity: "HIGH" },
    { source: "webserver", target: "appserver", cve: "CVE-2023-46604", severity: "CRITICAL" },
    { source: "appserver", target: "database", cve: "CVE-2024-3400", severity: "CRITICAL" },
    { source: "webserver", target: "cache", cve: "CVE-2023-4966", severity: "CRITICAL" },
    { source: "appserver", target: "cache", cve: "CVE-2024-1709", severity: "CRITICAL" }
  ]
};

const useStore = create((set, get) => ({
  graphData: MOCK_GRAPH,
  attackPath: [],
  selectedNode: null,
  explanation: "",
  loading: false,
  setGraphData: (graphData) => set({ graphData }),
  setAttackPath: (attackPath) => set({ attackPath }),
  setSelectedNode: (selectedNode) => set({ selectedNode }),
  setExplanation: (explanation) => set({ explanation }),
  setLoading: (loading) => set({ loading }),
  patchNodeLocal: (nodeId) =>
    set({
      graphData: {
        ...get().graphData,
        nodes: (get().graphData?.nodes || []).map((node) =>
          node.id === nodeId ? { ...node, patched: true } : node
        ),
        links: get().graphData?.links || []
      }
    })
}));

export default useStore;
