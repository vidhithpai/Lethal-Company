import { create } from "zustand";

const EMPTY_GRAPH = { nodes: [], links: [] };

const useStore = create((set, get) => ({
  graph: EMPTY_GRAPH,
  path: [],
  selectedNode: null,
  explanation: "",
  loading: false,
  setGraph: (graph) => set({ graph }),
  setPath: (path) => set({ path }),
  setSelectedNode: (selectedNode) => set({ selectedNode }),
  setExplanation: (explanation) => set({ explanation }),
  setLoading: (loading) => set({ loading }),
  patchNodeLocal: (nodeId) =>
    set({
      graph: {
        ...get().graph,
        nodes: (get().graph?.nodes || []).map((node) =>
          node.id === nodeId ? { ...node, patched: true } : node
        ),
        links: get().graph?.links || []
      }
    })
}));

export default useStore;
