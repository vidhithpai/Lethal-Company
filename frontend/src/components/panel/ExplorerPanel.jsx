import { useState, useMemo, useEffect } from "react";
import useStore from "../../store/useStore";
import { endpoints } from "../../services/api";

/**
 * Build a nested directory tree from a flat list of file paths.
 * Each node has { name, path, type: 'file'|'dir', children, nodeCount, nodeTypes }
 */
function buildDirTree(nodes) {
  const root = { name: "root", path: "", type: "dir", children: {}, nodeCount: 0 };

  for (const node of nodes) {
    const filePath = node.file || "";
    if (!filePath) continue;

    const parts = filePath.replace(/\\/g, "/").split("/").filter(Boolean);
    const meaningfulIdx = parts.findIndex(
      (p, i) =>
        i > 0 &&
        !["tmp", "app", "home", "usr", "var", "private", "vulngraph_uploads", "uploads"].includes(p)
    );
    const relativeParts =
      meaningfulIdx >= 0
        ? parts.slice(meaningfulIdx)
        : parts.slice(-Math.min(parts.length, 5));

    if (relativeParts.length === 0) continue;

    let cur = root;
    for (let i = 0; i < relativeParts.length; i++) {
      const part = relativeParts[i];
      const isFile = i === relativeParts.length - 1;
      if (!cur.children[part]) {
        cur.children[part] = {
          name: part,
          path: relativeParts.slice(0, i + 1).join("/"),
          fullPath: filePath,
          type: isFile ? "file" : "dir",
          children: {},
          nodeCount: 0,
          nodeTypes: {},
        };
      }
      cur.children[part].nodeCount += 1;
      if (isFile) {
        const t = String(node.type || "normal").toLowerCase();
        cur.children[part].nodeTypes[t] = (cur.children[part].nodeTypes[t] || 0) + 1;
      }
      cur = cur.children[part];
    }
  }

  function sortTree(node) {
    const childArr = Object.values(node.children);
    childArr.sort((a, b) => {
      if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    node.childArr = childArr.map(sortTree);
    return node;
  }

  return sortTree(root);
}

// Filter tree based on search query
function filterTree(node, term) {
  if (!term) return node;
  if (node.type === "file") {
    return node.name.toLowerCase().includes(term.toLowerCase()) ? node : null;
  }
  const filteredChildren = [];
  for (const child of node.childArr || []) {
    const res = filterTree(child, term);
    if (res) filteredChildren.push(res);
  }
  if (filteredChildren.length > 0) {
    return { ...node, childArr: filteredChildren, forceOpen: true };
  }
  return null;
}

// File icon matching the reference (code file outline with <> brackets)
function CodeFileIcon() {
  return (
    <svg
      style={{ width: 13, height: 13, color: "#38BDF8", flexShrink: 0, marginRight: 5 }}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <polyline points="10 13 8 15 10 17" />
      <polyline points="14 13 16 15 14 17" />
    </svg>
  );
}

// Folder icon in purple/blue
function FolderIcon({ open }) {
  return (
    <svg
      style={{ width: 13, height: 13, color: "#60A5FA", flexShrink: 0, marginRight: 5 }}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {open ? (
        <>
          <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
          <line x1="9" y1="14" x2="15" y2="14" />
        </>
      ) : (
        <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
      )}
    </svg>
  );
}

// Risk dot
function NodeTypeDots({ nodeTypes }) {
  const colors = {
    source: "#10B981",
    sink: "#EF4444",
    sanitizer: "#0EA5E9",
    normal: "#3B82F6",
  };
  return (
    <span style={{ display: "flex", gap: 2.5, marginLeft: "auto", flexShrink: 0 }}>
      {Object.entries(nodeTypes || {}).map(([t, count]) => (
        <span
          key={t}
          title={`${count} ${t}`}
          style={{
            width: 5,
            height: 5,
            borderRadius: "50%",
            background: colors[t] || "#6B7280",
          }}
        />
      ))}
    </span>
  );
}

// Recursive tree node renderer
function TreeNode({ node, depth, onFileClick, selectedFile, forceOpen }) {
  const [open, setOpen] = useState(depth < 1 || Boolean(forceOpen));

  useEffect(() => {
    if (forceOpen) setOpen(true);
  }, [forceOpen]);

  const isSelected = selectedFile === node.fullPath;

  if (node.type === "file") {
    return (
      <div
        onClick={() => onFileClick(node)}
        style={{
          display: "flex",
          alignItems: "center",
          padding: `3.5px 8px 3.5px ${10 + depth * 14}px`,
          cursor: "pointer",
          borderRadius: 4,
          background: isSelected ? "rgba(245, 158, 11, 0.16)" : "transparent",
          border: isSelected ? "1px solid rgba(245, 158, 11, 0.3)" : "1px solid transparent",
          color: isSelected ? "#FCD34D" : "#C9D1D9",
          fontSize: 11.5,
          fontFamily: "'JetBrains Mono', monospace",
          transition: "background 0.12s ease",
          userSelect: "none",
        }}
        onMouseEnter={(e) => {
          if (!isSelected) e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)";
        }}
        onMouseLeave={(e) => {
          if (!isSelected) e.currentTarget.style.background = "transparent";
        }}
      >
        <CodeFileIcon />
        <span
          style={{
            flex: 1,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          {node.name}
        </span>
        <NodeTypeDots nodeTypes={node.nodeTypes} />
      </div>
    );
  }

  return (
    <div>
      <div
        onClick={() => setOpen((o) => !o)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 3,
          padding: `3.5px 8px 3.5px ${8 + depth * 14}px`,
          cursor: "pointer",
          color: "#8B949E",
          fontSize: 11.5,
          userSelect: "none",
          borderRadius: 4,
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = "rgba(255, 255, 255, 0.04)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "transparent";
        }}
      >
        <span style={{ fontSize: 9, width: 10, textAlign: "center", color: "#6E7681" }}>
          {open ? "▾" : "▸"}
        </span>
        <FolderIcon open={open} />
        <span style={{ flex: 1, color: "#C9D1D9", fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {node.name}
        </span>
        <span style={{ fontSize: 9.5, color: "#4B5563", marginLeft: "auto" }}>
          {node.nodeCount}
        </span>
      </div>
      {open &&
        node.childArr?.map((child) => (
          <TreeNode
            key={child.path}
            node={child}
            depth={depth + 1}
            onFileClick={onFileClick}
            selectedFile={selectedFile}
            forceOpen={forceOpen}
          />
        ))}
    </div>
  );
}

// Code Viewer with line numbers and syntax styling
function CodeViewer({ content, highlightLine }) {
  if (!content) {
    return (
      <div style={{ padding: 18, color: "#4B5563", fontSize: 12 }}>
        Select a file from the explorer to view its contents.
      </div>
    );
  }

  const lines = content.split("\n");
  return (
    <div
      style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 11,
        lineHeight: 1.6,
        overflow: "auto",
        height: "100%",
        padding: "8px 0",
        background: "#080C16",
      }}
    >
      {lines.map((line, i) => (
        <div
          key={i}
          style={{
            display: "flex",
            background: highlightLine === i + 1 ? "rgba(245, 158, 11, 0.18)" : "transparent",
            borderLeft: highlightLine === i + 1 ? "3px solid #F59E0B" : "3px solid transparent",
          }}
        >
          <span
            style={{
              minWidth: 38,
              textAlign: "right",
              paddingRight: 12,
              color: highlightLine === i + 1 ? "#F59E0B" : "#4B5563",
              userSelect: "none",
              flexShrink: 0,
            }}
          >
            {i + 1}
          </span>
          <pre
            style={{
              margin: 0,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              overflowWrap: "anywhere",
              color: "#E6EDF3",
              fontFamily: "inherit",
            }}
          >
            {line}
          </pre>
        </div>
      ))}
    </div>
  );
}

// Default filter configurations
const DEFAULT_NODE_FILTERS = {
  folder: true,
  file: true,
  class: true,
  interface: true,
  enum: true,
  type: true,
  function: true,
  method: true,
  variable: true,
  property: true,
  const: true,
  source: true,
  sink: true,
  sanitizer: true,
  normal: true,
};

const DEFAULT_EDGE_FILTERS = {
  contains: true,
  defines: true,
  imports: true,
  calls: true,
  call: true,
  cross_file_call: true,
  reaching_def_flow: true,
  dataflow: true,
  extends: true,
  implements: true,
};

// Node Types list matching reference screenshot 4
const NODE_TYPE_ITEMS = [
  { key: "folder", label: "Folder", icon: "📁" },
  { key: "file", label: "File", icon: "📄" },
  { key: "class", label: "Class", icon: "📦" },
  { key: "interface", label: "Interface", icon: "#" },
  { key: "enum", label: "Enum", icon: "☰" },
  { key: "type", label: "Type", icon: "𝐓" },
  { key: "function", label: "Function", icon: "{ }" },
  { key: "method", label: "Method", icon: "{ }" },
  { key: "variable", label: "Variable", icon: "(x)" },
  { key: "property", label: "Property", icon: "(x)" },
  { key: "const", label: "Const", icon: "◎" },
  { key: "source", label: "Source (Entry)", icon: "🟢" },
  { key: "sink", label: "Sink (Dangerous)", icon: "🔴" },
  { key: "sanitizer", label: "Sanitizer (Guard)", icon: "🛡️" },
];

// Edge Types list matching reference screenshot 4
const EDGE_TYPE_ITEMS = [
  { key: "contains", label: "Contains", color: "#10B981" },
  { key: "defines", label: "Defines", color: "#06B6D4" },
  { key: "imports", label: "Imports", color: "#3B82F6" },
  { key: "calls", label: "Calls", color: "#3B82F6" },
  { key: "reaching_def_flow", label: "Taint flow", color: "#0EA5E9" },
  { key: "cross_file_call", label: "Cross-file", color: "#06B6D4" },
  { key: "extends", label: "Extends", color: "#F59E0B" },
  { key: "implements", label: "Implements", color: "#EC4899" },
];

export default function ExplorerPanel({ collapsed, onToggle }) {
  // Panel navigation state
  const [activeSection, setActiveSection] = useState("explorer"); // 'explorer' | 'filters'
  const [isPanelOpen, setIsPanelOpen] = useState(!collapsed);
  const [searchQuery, setSearchQuery] = useState("");

  // Code inspector state & dragging
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileContent, setFileContent] = useState(null);
  const [fileLoading, setFileLoading] = useState(false);
  const [showCodeInspector, setShowCodeInspector] = useState(false);
  const [inspectorWidth, setInspectorWidth] = useState(() => {
    try {
      const saved = localStorage.getItem("vulngraph_inspector_width");
      if (saved) {
        const val = parseInt(saved, 10);
        if (val >= 280 && val <= 1400) return val;
      }
    } catch (_) {}
    return 500;
  });
  const [isResizing, setIsResizing] = useState(false);
  const [isFloating, setIsFloating] = useState(false);
  const [floatPos, setFloatPos] = useState({ x: 280, y: 70 });
  const [floatHeight, setFloatHeight] = useState(580);
  const [isMovingFloat, setIsMovingFloat] = useState(false);

  // Resize handler for docked / right-border dragging
  const handleResizeMouseDown = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsResizing(true);
    const startX = e.clientX;
    const startW = inspectorWidth;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "col-resize";

    const onMouseMove = (moveEvt) => {
      const delta = moveEvt.clientX - startX;
      const maxAllowed = Math.max(350, window.innerWidth - 300);
      const nextW = Math.max(280, Math.min(maxAllowed, startW + delta));
      setInspectorWidth(nextW);
    };

    const onMouseUp = (upEvt) => {
      setIsResizing(false);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
      const delta = upEvt.clientX - startX;
      const maxAllowed = Math.max(350, window.innerWidth - 300);
      const nextW = Math.max(280, Math.min(maxAllowed, startW + delta));
      try {
        localStorage.setItem("vulngraph_inspector_width", String(nextW));
      } catch (_) {}
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  };

  // Header drag handler to move floating Code Inspector window
  const handleFloatHeaderMouseDown = (e) => {
    if (!isFloating) return;
    if (e.target.closest("button") || e.target.closest("input")) return;
    e.preventDefault();
    setIsMovingFloat(true);
    const startX = e.clientX;
    const startY = e.clientY;
    const startPosX = floatPos.x;
    const startPosY = floatPos.y;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "grabbing";

    const onMouseMove = (moveEvt) => {
      const nextX = Math.max(10, Math.min(window.innerWidth - 200, startPosX + (moveEvt.clientX - startX)));
      const nextY = Math.max(10, Math.min(window.innerHeight - 80, startPosY + (moveEvt.clientY - startY)));
      setFloatPos({ x: nextX, y: nextY });
    };

    const onMouseUp = () => {
      setIsMovingFloat(false);
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  };

  // Corner resize handler for floating mode
  const handleCornerResizeMouseDown = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const startY = e.clientY;
    const startW = inspectorWidth;
    const startH = floatHeight;
    document.body.style.userSelect = "none";
    document.body.style.cursor = "nwse-resize";

    const onMouseMove = (moveEvt) => {
      const nextW = Math.max(300, Math.min(window.innerWidth - 50, startW + (moveEvt.clientX - startX)));
      const nextH = Math.max(250, Math.min(window.innerHeight - 50, startH + (moveEvt.clientY - startY)));
      setInspectorWidth(nextW);
      setFloatHeight(nextH);
    };

    const onMouseUp = () => {
      document.body.style.userSelect = "";
      document.body.style.cursor = "";
      window.removeEventListener("mousemove", onMouseMove);
      window.removeEventListener("mouseup", onMouseUp);
    };

    window.addEventListener("mousemove", onMouseMove);
    window.addEventListener("mouseup", onMouseUp);
  };

  // Filters state
  const [nodeFilters, setNodeFilters] = useState(DEFAULT_NODE_FILTERS);
  const [edgeFilters, setEdgeFilters] = useState(DEFAULT_EDGE_FILTERS);

  // Store hooks
  const graph = useStore((s) => s.graph);
  const selectedNode = useStore((s) => s.selectedNode);
  const setNodeVisibility = useStore((s) => s.setNodeVisibility);
  const setEdgeVisibility = useStore((s) => s.setEdgeVisibility);

  // Sync external collapsed prop
  useEffect(() => {
    setIsPanelOpen(!collapsed);
  }, [collapsed]);

  // Build directory tree
  const rawTree = useMemo(() => buildDirTree(graph?.nodes || []), [graph?.nodes]);

  // Filtered directory tree
  const dirTree = useMemo(() => {
    if (!searchQuery.trim()) return rawTree;
    const filtered = filterTree(rawTree, searchQuery.trim());
    return filtered || { name: "root", path: "", type: "dir", childArr: [] };
  }, [rawTree, searchQuery]);

  // Load file content
  async function loadFile(fileNode) {
    if (!fileNode?.fullPath) return;
    setSelectedFile(fileNode.fullPath);
    setFileLoading(true);
    setShowCodeInspector(true);
    try {
      const res = await fetch(endpoints.fileSource(fileNode.fullPath));
      if (res.ok) {
        const data = await res.json();
        setFileContent(data);
      } else {
        setFileContent({ content: "// File could not be loaded from server", language: "txt" });
      }
    } catch {
      setFileContent({ content: "// Error loading file source", language: "txt" });
    } finally {
      setFileLoading(false);
    }
  }

  // Handle selectedNode change
  useEffect(() => {
    if (selectedNode?.file && isPanelOpen && activeSection === "explorer") {
      loadFile({ fullPath: selectedNode.file, name: selectedNode.file.split("/").pop() });
    }
  }, [selectedNode]);

  // Filter toggle handlers
  const toggleNodeFilter = (key) => {
    const next = { ...nodeFilters, [key]: !nodeFilters[key] };
    setNodeFilters(next);
    setNodeVisibility(next);
  };

  const toggleEdgeFilter = (key) => {
    const next = { ...edgeFilters, [key]: !edgeFilters[key] };
    setEdgeFilters(next);
    setEdgeVisibility(next);
  };

  // Rail item click handler
  const handleRailClick = (section) => {
    if (!isPanelOpen) {
      setIsPanelOpen(true);
      setActiveSection(section);
      if (onToggle) onToggle(false);
    } else if (activeSection === section) {
      // Clicking the already active icon collapses the panel
      setIsPanelOpen(false);
      if (onToggle) onToggle(true);
    } else {
      setActiveSection(section);
    }
  };

  const nodes = graph?.nodes || [];
  const links = graph?.links || graph?.edges || [];
  const highlightLine = selectedNode?.file === selectedFile ? selectedNode.line : null;

  return (
    <div className="two-level-sidebar-container" style={{ display: "flex", height: "100%", flexShrink: 0, zIndex: 30 }}>
      {/* ── 1. NARROW ICON RAIL (48px) ────────────────────────────────────── */}
      <div
        style={{
          width: 48,
          minWidth: 48,
          maxWidth: 48,
          height: "100%",
          background: "#050811",
          borderRight: "1px solid rgba(255, 255, 255, 0.08)",
          display: "flex",
          flexDirection: "column",
          alignItems: "center",
          paddingTop: 10,
          flexShrink: 0,
          userSelect: "none",
        }}
      >
        {/* Top Panel / Layout Toggle Icon */}
        <button
          type="button"
          onClick={() => {
            const next = !isPanelOpen;
            setIsPanelOpen(next);
            if (onToggle) onToggle(!next);
          }}
          title={isPanelOpen ? "Collapse Sidebar" : "Expand Sidebar"}
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: "transparent",
            border: "none",
            color: "#6E7681",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            marginBottom: 6,
            transition: "all 0.15s ease",
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.color = "#E6EDF3";
            e.currentTarget.style.background = "rgba(255, 255, 255, 0.06)";
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.color = "#6E7681";
            e.currentTarget.style.background = "transparent";
          }}
        >
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M9 3v18" />
          </svg>
        </button>

        {/* Subtle Divider */}
        <div style={{ width: 24, height: 1, background: "rgba(255, 255, 255, 0.08)", marginBottom: 8 }} />

        {/* Folder / Explorer Icon */}
        <button
          type="button"
          onClick={() => handleRailClick("explorer")}
          title="Project Explorer"
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: isPanelOpen && activeSection === "explorer" ? "rgba(6, 182, 212, 0.16)" : "transparent",
            border: isPanelOpen && activeSection === "explorer" ? "1px solid rgba(6, 182, 212, 0.4)" : "1px solid transparent",
            color: isPanelOpen && activeSection === "explorer" ? "#38BDF8" : "#6E7681",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            marginBottom: 6,
            transition: "all 0.15s ease",
          }}
          onMouseEnter={(e) => {
            if (!(isPanelOpen && activeSection === "explorer")) {
              e.currentTarget.style.color = "#E6EDF3";
              e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)";
            }
          }}
          onMouseLeave={(e) => {
            if (!(isPanelOpen && activeSection === "explorer")) {
              e.currentTarget.style.color = "#6E7681";
              e.currentTarget.style.background = "transparent";
            }
          }}
        >
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
          </svg>
        </button>

        {/* Filter Icon */}
        <button
          type="button"
          onClick={() => handleRailClick("filters")}
          title="Graph Filters"
          style={{
            width: 36,
            height: 36,
            borderRadius: 8,
            background: isPanelOpen && activeSection === "filters" ? "rgba(6, 182, 212, 0.16)" : "transparent",
            border: isPanelOpen && activeSection === "filters" ? "1px solid rgba(6, 182, 212, 0.4)" : "1px solid transparent",
            color: isPanelOpen && activeSection === "filters" ? "#38BDF8" : "#6E7681",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            cursor: "pointer",
            transition: "all 0.15s ease",
          }}
          onMouseEnter={(e) => {
            if (!(isPanelOpen && activeSection === "filters")) {
              e.currentTarget.style.color = "#E6EDF3";
              e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)";
            }
          }}
          onMouseLeave={(e) => {
            if (!(isPanelOpen && activeSection === "filters")) {
              e.currentTarget.style.color = "#6E7681";
              e.currentTarget.style.background = "transparent";
            }
          }}
        >
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
            <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
          </svg>
        </button>
      </div>

      {/* ── 2. SECONDARY EXPLORER / FILTERS PANEL (~215px) ────────────────── */}
      {isPanelOpen && (
        <div
          style={{
            width: 215,
            minWidth: 215,
            maxWidth: 215,
            height: "100%",
            background: "#0B101E",
            borderRight: "1px solid rgba(255, 255, 255, 0.08)",
            display: "flex",
            flexDirection: "column",
            overflow: "hidden",
            flexShrink: 0,
          }}
        >
          {/* Header with Tabs & Collapse Button */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "9px 10px 8px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
              flexShrink: 0,
            }}
          >
            {/* Explorer & Filters Tab Buttons */}
            <div style={{ display: "flex", gap: 4 }}>
              <button
                type="button"
                onClick={() => setActiveSection("explorer")}
                style={{
                  padding: "3.5px 10px",
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: "pointer",
                  border: activeSection === "explorer" ? "1px solid rgba(6, 182, 212, 0.4)" : "1px solid transparent",
                  background: activeSection === "explorer" ? "rgba(6, 182, 212, 0.18)" : "transparent",
                  color: activeSection === "explorer" ? "#38BDF8" : "#6E7681",
                  transition: "all 0.15s ease",
                }}
              >
                Explorer
              </button>
              <button
                type="button"
                onClick={() => setActiveSection("filters")}
                style={{
                  padding: "3.5px 10px",
                  borderRadius: 6,
                  fontSize: 11,
                  fontWeight: 600,
                  cursor: "pointer",
                  border: activeSection === "filters" ? "1px solid rgba(6, 182, 212, 0.4)" : "1px solid transparent",
                  background: activeSection === "filters" ? "rgba(6, 182, 212, 0.18)" : "transparent",
                  color: activeSection === "filters" ? "#38BDF8" : "#6E7681",
                  transition: "all 0.15s ease",
                }}
              >
                Filters
              </button>
            </div>

            {/* Collapse Button [|<] */}
            <button
              type="button"
              onClick={() => {
                setIsPanelOpen(false);
                if (onToggle) onToggle(true);
              }}
              title="Collapse"
              style={{
                width: 26,
                height: 26,
                borderRadius: 4,
                background: "transparent",
                border: "none",
                color: "#6E7681",
                cursor: "pointer",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = "#E6EDF3")}
              onMouseLeave={(e) => (e.currentTarget.style.color = "#6E7681")}
            >
              <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="18" height="18" rx="2" />
                <path d="M9 3v18" />
                <path d="m14 9-3 3 3 3" />
              </svg>
            </button>
          </div>

          {/* ── SECTION A: EXPLORER VIEW ────────────────────────────────────── */}
          {activeSection === "explorer" && (
            <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
              {/* Search Bar */}
              <div style={{ padding: "8px 10px 6px" }}>
                <div
                  style={{
                    background: "#080C16",
                    border: "1px solid rgba(255, 255, 255, 0.08)",
                    borderRadius: 6,
                    padding: "4px 8px",
                    display: "flex",
                    alignItems: "center",
                    gap: 6,
                  }}
                >
                  <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#6E7681" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                  <input
                    type="text"
                    placeholder="Search files..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    style={{
                      background: "transparent",
                      border: "none",
                      outline: "none",
                      color: "#E6EDF3",
                      fontSize: 11,
                      width: "100%",
                      fontFamily: "inherit",
                    }}
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery("")}
                      style={{ background: "none", border: "none", color: "#6E7681", cursor: "pointer", fontSize: 11, padding: 0 }}
                    >
                      ✕
                    </button>
                  )}
                </div>
              </div>

              {/* Title */}
              <div
                style={{
                  padding: "6px 10px 4px",
                  fontSize: 10,
                  fontWeight: 700,
                  color: "#6E7681",
                  textTransform: "uppercase",
                  letterSpacing: "0.06em",
                }}
              >
                Project files ({nodes.length} nodes)
              </div>

              {/* Scrollable File Tree */}
              <div style={{ flex: 1, overflowY: "auto", padding: "2px 4px" }}>
                {dirTree.childArr?.length === 0 ? (
                  <div style={{ fontSize: 11, color: "#4B5563", padding: "12px 10px" }}>
                    {searchQuery ? "No matching files found." : "Scan a repository to view its file tree."}
                  </div>
                ) : (
                  dirTree.childArr?.map((child) => (
                    <TreeNode
                      key={child.path}
                      node={child}
                      depth={0}
                      onFileClick={loadFile}
                      selectedFile={selectedFile}
                      forceOpen={Boolean(searchQuery)}
                    />
                  ))
                )}
              </div>
            </div>
          )}

          {/* ── SECTION B: FILTERS VIEW ─────────────────────────────────────── */}
          {activeSection === "filters" && (
            <div style={{ flex: 1, overflowY: "auto", padding: "10px 10px" }}>
              {/* NODE TYPES HEADER */}
              <div style={{ fontSize: 10, fontWeight: 700, color: "#6E7681", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>
                Node Types
              </div>
              <div style={{ fontSize: 10.5, color: "#8B949E", marginBottom: 10 }}>
                Toggle visibility of node types in the graph
              </div>

              {/* Node Types List */}
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {NODE_TYPE_ITEMS.map((item) => {
                  const active = nodeFilters[item.key] !== false;
                  return (
                    <div
                      key={item.key}
                      onClick={() => toggleNodeFilter(item.key)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "6px 9px",
                        background: "#131929",
                        border: "1px solid rgba(255, 255, 255, 0.04)",
                        borderRadius: 6,
                        cursor: "pointer",
                        transition: "all 0.12s ease",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "#192238")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "#131929")}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11.5, color: active ? "#E6EDF3" : "#6E7681" }}>
                        <span style={{ fontSize: 11, width: 14, textAlign: "center" }}>{item.icon}</span>
                        <span>{item.label}</span>
                      </div>
                      <div
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: active ? "#06B6D4" : "#374151",
                          boxShadow: active ? "0 0 8px rgba(6, 182, 212, 0.65)" : "none",
                          transition: "all 0.15s ease",
                        }}
                      />
                    </div>
                  );
                })}
              </div>

              {/* Divider */}
              <div style={{ height: 1, background: "rgba(255, 255, 255, 0.08)", margin: "14px 0 12px" }} />

              {/* EDGE TYPES HEADER */}
              <div style={{ fontSize: 10, fontWeight: 700, color: "#6E7681", textTransform: "uppercase", letterSpacing: "0.06em", marginBottom: 2 }}>
                Edge Types
              </div>
              <div style={{ fontSize: 10.5, color: "#8B949E", marginBottom: 10 }}>
                Toggle visibility of relationship types
              </div>

              {/* Edge Types List */}
              <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                {EDGE_TYPE_ITEMS.map((item) => {
                  const active = edgeFilters[item.key] !== false;
                  return (
                    <div
                      key={item.key}
                      onClick={() => toggleEdgeFilter(item.key)}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        padding: "6px 9px",
                        background: "#131929",
                        border: "1px solid rgba(255, 255, 255, 0.04)",
                        borderRadius: 6,
                        cursor: "pointer",
                        transition: "all 0.12s ease",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "#192238")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "#131929")}
                    >
                      <div style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 11.5, color: active ? "#E6EDF3" : "#6E7681" }}>
                        <div style={{ width: 14, height: 3, borderRadius: 2, background: active ? item.color : "#374151" }} />
                        <span>{item.label}</span>
                      </div>
                      <div
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: "50%",
                          background: active ? "#06B6D4" : "#374151",
                          boxShadow: active ? "0 0 8px rgba(6, 182, 212, 0.65)" : "none",
                          transition: "all 0.15s ease",
                        }}
                      />
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ── BOTTOM STATS ROW: 1033 nodes · 1309 edges ──────────────────── */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "7px 12px",
              borderTop: "1px solid rgba(255, 255, 255, 0.07)",
              background: "#070B16",
              fontSize: 10.5,
              fontFamily: "'JetBrains Mono', monospace",
              color: "#6E7681",
              flexShrink: 0,
            }}
          >
            <span>{nodes.length} nodes</span>
            <span>{links.length} edges</span>
          </div>

          {/* ── BOTTOM STATUS: ● Ready ──────────────────────────────────────── */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "6px 12px",
              borderTop: "1px solid rgba(255, 255, 255, 0.05)",
              background: "#050811",
              fontSize: 10.5,
              fontWeight: 500,
              color: "#6E7681",
              flexShrink: 0,
            }}
          >
            <div
              style={{
                width: 6,
                height: 6,
                borderRadius: "50%",
                background: "#10B981",
                boxShadow: "0 0 6px #10B981",
              }}
            />
            <span>Ready</span>
          </div>
        </div>
      )}

      {/* ── 3. CODE INSPECTOR PANE (Draggable & Resizable) ─────────────── */}
      {showCodeInspector && (
        <div
          style={
            isFloating
              ? {
                  position: "fixed",
                  top: floatPos.y,
                  left: floatPos.x,
                  width: inspectorWidth,
                  height: floatHeight,
                  minWidth: 320,
                  minHeight: 260,
                  background: "#0B101E",
                  border: "1px solid rgba(6, 182, 212, 0.4)",
                  borderRadius: 10,
                  boxShadow: "0 20px 50px rgba(0, 0, 0, 0.85), 0 0 24px rgba(6, 182, 212, 0.25)",
                  display: "flex",
                  flexDirection: "column",
                  overflow: "hidden",
                  zIndex: 100,
                }
              : {
                  width: inspectorWidth,
                  minWidth: 280,
                  maxWidth: "calc(100vw - 300px)",
                  height: "100%",
                  background: "#0B101E",
                  borderRight: "1px solid rgba(255, 255, 255, 0.08)",
                  display: "flex",
                  flexDirection: "column",
                  overflow: "hidden",
                  flexShrink: 0,
                  position: "relative",
                }
          }
        >
          {/* Top Title Bar (Draggable in floating mode) */}
          <div
            onMouseDown={handleFloatHeaderMouseDown}
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "9px 12px 8px",
              borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
              flexShrink: 0,
              cursor: isFloating ? (isMovingFloat ? "grabbing" : "grab") : "default",
              userSelect: "none",
              background: isFloating ? "#090F1C" : "transparent",
            }}
            title={isFloating ? "Click and drag to move window" : undefined}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 11.5, fontWeight: 600, color: "#38BDF8" }}>
              <span style={{ fontFamily: "monospace", fontSize: 12 }}>&lt;&gt;</span>
              <span>Code Inspector</span>
              {isFloating && (
                <span
                  style={{
                    fontSize: 9,
                    background: "rgba(6, 182, 212, 0.15)",
                    color: "#38BDF8",
                    padding: "1px 5px",
                    borderRadius: 3,
                    marginLeft: 4,
                    letterSpacing: "0.03em",
                  }}
                >
                  DRAGGABLE
                </span>
              )}
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
              {/* Dock / Float Toggle Button */}
              <button
                type="button"
                onClick={() => setIsFloating(!isFloating)}
                title={isFloating ? "Dock back to sidebar" : "Pop out into floating window (drag anywhere)"}
                style={{
                  width: 24,
                  height: 24,
                  borderRadius: 4,
                  background: "transparent",
                  border: "none",
                  color: isFloating ? "#38BDF8" : "#6E7681",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  transition: "all 0.15s ease",
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.color = "#38BDF8";
                  e.currentTarget.style.background = "rgba(6, 182, 212, 0.12)";
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.color = isFloating ? "#38BDF8" : "#6E7681";
                  e.currentTarget.style.background = "transparent";
                }}
              >
                {isFloating ? (
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="3" width="18" height="18" rx="2" />
                    <path d="M9 3v18" />
                    <path d="m15 12-3-3m0 0 3-3" />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                    <polyline points="15 3 21 3 21 9" />
                    <line x1="10" y1="14" x2="21" y2="3" />
                  </svg>
                )}
              </button>

              {/* Close Button */}
              <button
                type="button"
                onClick={() => {
                  setShowCodeInspector(false);
                  setIsFloating(false);
                }}
                title="Close Code Inspector"
                style={{
                  width: 24,
                  height: 24,
                  borderRadius: 4,
                  background: "transparent",
                  border: "none",
                  color: "#6E7681",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.color = "#E6EDF3")}
                onMouseLeave={(e) => (e.currentTarget.style.color = "#6E7681")}
              >
                ✕
              </button>
            </div>
          </div>

          {/* Sub-bar with SELECTED badge & filename */}
          <div
            style={{
              padding: "6px 12px",
              background: "#080C16",
              borderBottom: "1px solid rgba(255, 255, 255, 0.06)",
              display: "flex",
              alignItems: "center",
              gap: 8,
              flexShrink: 0,
            }}
          >
            <span
              style={{
                background: "rgba(245, 158, 11, 0.15)",
                color: "#F59E0B",
                border: "1px solid rgba(245, 158, 11, 0.3)",
                borderRadius: 4,
                padding: "1.5px 5px",
                fontSize: 9.5,
                fontWeight: 700,
                letterSpacing: "0.04em",
              }}
            >
              SELECTED
            </span>

            <span
              style={{
                fontSize: 11,
                fontFamily: "'JetBrains Mono', monospace",
                color: "#E6EDF3",
                flex: 1,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {selectedFile?.split("/").pop() || ""}
            </span>

            {fileContent?.line_count && (
              <span style={{ fontSize: 10, color: "#4B5563" }}>
                {fileContent.line_count} lines
              </span>
            )}
          </div>

          {/* Code Viewer */}
          <div style={{ flex: 1, overflow: "hidden", display: "flex", flexDirection: "column" }}>
            {fileLoading ? (
              <div style={{ padding: 18, color: "#6E7681", fontSize: 12 }}>
                Loading file source...
              </div>
            ) : (
              <CodeViewer content={fileContent?.content} highlightLine={highlightLine} />
            )}
          </div>

          {/* Draggable Resize Handle on Right Border (Docked & Floating) */}
          <div
            onMouseDown={handleResizeMouseDown}
            onDoubleClick={() => setInspectorWidth(500)}
            title="Drag border to resize width (Double click to reset)"
            style={{
              position: "absolute",
              top: 0,
              right: 0,
              width: 8,
              height: "100%",
              cursor: "col-resize",
              zIndex: 40,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background: isResizing ? "rgba(6, 182, 212, 0.35)" : "transparent",
              borderRight: isResizing ? "2px solid #06B6D4" : "1px solid rgba(255, 255, 255, 0.08)",
              transition: "background 0.12s ease, border-color 0.12s ease",
            }}
            onMouseEnter={(e) => {
              if (!isResizing) {
                e.currentTarget.style.background = "rgba(6, 182, 212, 0.25)";
                e.currentTarget.style.borderRight = "2px solid #38BDF8";
              }
            }}
            onMouseLeave={(e) => {
              if (!isResizing) {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.borderRight = "1px solid rgba(255, 255, 255, 0.08)";
              }
            }}
          >
            {/* 3 tiny grip dots in center */}
            <div
              style={{
                display: "flex",
                flexDirection: "column",
                gap: 3,
                alignItems: "center",
                padding: "4px 1px",
                borderRadius: 4,
                background: isResizing ? "rgba(6, 182, 212, 0.8)" : "rgba(255, 255, 255, 0.15)",
              }}
            >
              <div style={{ width: 3, height: 3, borderRadius: "50%", background: isResizing ? "#FFFFFF" : "#94A3B8" }} />
              <div style={{ width: 3, height: 3, borderRadius: "50%", background: isResizing ? "#FFFFFF" : "#94A3B8" }} />
              <div style={{ width: 3, height: 3, borderRadius: "50%", background: isResizing ? "#FFFFFF" : "#94A3B8" }} />
            </div>
          </div>

          {/* Corner 2D Resize Handle (Floating Mode) */}
          {isFloating && (
            <div
              onMouseDown={handleCornerResizeMouseDown}
              title="Drag to resize width and height"
              style={{
                position: "absolute",
                bottom: 0,
                right: 0,
                width: 14,
                height: 14,
                cursor: "nwse-resize",
                zIndex: 50,
                display: "flex",
                alignItems: "flex-end",
                justifyContent: "flex-end",
                padding: 2,
              }}
            >
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
                <path d="M8 2L2 8M8 5L5 8M8 8L8 8" stroke="#06B6D4" strokeWidth="1.6" strokeLinecap="round" />
              </svg>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
