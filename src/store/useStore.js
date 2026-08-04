import { create } from "zustand";

const EMPTY_GRAPH = { nodes: [], links: [] };

const useStore = create((set, get) => ({
  // ── Core graph state ──────────────────────────────────────────────────────
  graph:        EMPTY_GRAPH,
  path:         [],
  selectedNode: null,
  explanation:  "",
  loading:      false,

  setGraph:        (graph)        => set({ graph }),
  setPath:         (path)         => set({ path }),
  setSelectedNode: (selectedNode) => set({ selectedNode }),
  setExplanation:  (explanation)  => set({ explanation }),
  setLoading:      (loading)      => set({ loading }),

  patchNodeLocal: (nodeId) =>
    set({
      graph: {
        ...get().graph,
        nodes: (get().graph?.nodes || []).map((node) =>
          node.id === nodeId ? { ...node, patched: true } : node
        ),
        links: get().graph?.links || [],
      },
    }),

  // ── Multi-path animation state ────────────────────────────────────────────
  isAnimating:    false,
  animationIndex: 0,
  totalPaths:     0,

  setIsAnimating:     (v)           => set({ isAnimating: v }),
  setAnimationStatus: (idx, total)  => set({ animationIndex: idx, totalPaths: total }),

  // ── Camera zoom trigger ───────────────────────────────────────────────────
  zoomTrigger: 0,
  bumpZoom:    ()  => set({ zoomTrigger: get().zoomTrigger + 1 }),

  // ── UI presentation state (pure frontend, no backend impact) ──────────────
  // active graph layer filter: 'all'|'ast'|'callgraph'|'controlflow'|'reachability'|'differential'|'blast'
  activeLayer:      "all",
  setActiveLayer:   (activeLayer) => set({ activeLayer }),

  // diff/version-compare mode
  diffMode:      false,
  setDiffMode:   (diffMode) => set({ diffMode }),

  // node hover for 3D glow effect
  hoveredNodeId:    null,
  setHoveredNodeId: (hoveredNodeId) => set({ hoveredNodeId }),

  // blast-radius ripple trigger
  blastNodeId:    null,
  setBlastNodeId: (blastNodeId) => set({ blastNodeId }),
}));

export default useStore;
