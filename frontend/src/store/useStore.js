import { create } from "zustand";

const EMPTY_GRAPH = { nodes: [], links: [] };

const useStore = create((set, get) => ({
  // ── Core graph state ──────────────────────────────────────────────────────
  graph:        EMPTY_GRAPH,
  path:         [],
  selectedNode: null,
  explanation:  "",
  loading:      false,

  setGraph:       (graph)       => set({ graph }),
  setPath:        (path)        => set({ path }),
  setSelectedNode:(selectedNode)=> set({ selectedNode }),
  setExplanation: (explanation) => set({ explanation }),
  setLoading:     (loading)     => set({ loading }),

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
  animationIndex: 0,       // 1-based (for display)
  totalPaths:     0,

  setIsAnimating:    (v)         => set({ isAnimating: v }),
  setAnimationStatus:(idx, total)=> set({ animationIndex: idx, totalPaths: total }),

  // ── Camera zoom trigger ───────────────────────────────────────────────────
  // GraphCanvas watches this; every increment fires a zoomToFit()
  zoomTrigger: 0,
  bumpZoom: () => set({ zoomTrigger: get().zoomTrigger + 1 }),

  // ── Differential / Commit state ───────────────────────────────────────────
  diffMode: false,
  selectedCommit: null,
  commitTimeline: [],
  newPaths: [],

  setDiffMode: (v) => set({ diffMode: v }),
  setSelectedCommit: (c) => set({ selectedCommit: c }),
  setCommitTimeline: (t) => set({ commitTimeline: t }),
  setNewPaths: (p) => set({ newPaths: p }),
}));

export default useStore;
