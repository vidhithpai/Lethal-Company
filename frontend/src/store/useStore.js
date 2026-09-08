import { create } from "zustand";

const EMPTY_GRAPH = { nodes: [], links: [] };

const useStore = create((set, get) => ({
  // ── Core graph state ──────────────────────────────────────────────────────
  graph:        EMPTY_GRAPH,
  path:         [],
  selectedNode: null,
  loading:      false,

  // ── Project scan completion progress state ────────────────────────────────
  scanProgress: {
    status: "idle", // "idle" | "scanning" | "complete" | "error"
    percent: 0,
    scannedFiles: 0,
    totalFiles: 0,
    currentFile: "",
  },
  setScanProgress: (sp) =>
    set((state) => ({
      scanProgress: { ...state.scanProgress, ...sp },
    })),
  resetScanProgress: () =>
    set({
      scanProgress: {
        status: "idle",
        percent: 0,
        scannedFiles: 0,
        totalFiles: 0,
        currentFile: "",
      },
    }),

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

  // ── Explorer panel filter state ───────────────────────────────────────────
  nodeVisibility: {
    source: true, sink: true, sanitizer: true, normal: true
  },
  edgeVisibility: {
    call: true, cross_file_call: true, reaching_def_flow: true,
    dataflow: true, same_file_call: true, extends: true,
    implements: true, imports: true,
  },
  focusDepth: null,  // null = show all, N = N hops from selected node

  setNodeVisibility: (v) => set({ nodeVisibility: v }),
  setEdgeVisibility: (v) => set({ edgeVisibility: v }),
  setFocusDepth:     (d) => set({ focusDepth: d }),
}));

export default useStore;
