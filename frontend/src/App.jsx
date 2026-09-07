import { useEffect, useState, useRef } from "react";
import GraphCanvas from "./components/canvas/GraphCanvas";
import MetricsBar from "./components/metrics/MetricsBar";
import UnifiedPanel from "./components/panel/UnifiedPanel";
import CommitTimeline from "./components/panel/CommitTimeline";
import ExplorerPanel from "./components/panel/ExplorerPanel";
import RepoAnalyzer from "./components/landing/RepoAnalyzer";
import { endpoints, normalizeGraph } from "./services/api";
import useStore from "./store/useStore";

const App = () => {
  const loading = useStore((state) => state.loading);
  const setLoading = useStore((state) => state.setLoading);
  const graph = useStore((state) => state.graph);
  const setGraph = useStore((state) => state.setGraph);
  const selectedNode = useStore((state) => state.selectedNode);
  const setSelectedNode = useStore((state) => state.setSelectedNode);
  const setExplanation = useStore((state) => state.setExplanation);
  const attackPath = useStore((state) => state.path);
  const setPath = useStore((state) => state.setPath);
  const patchNodeLocal = useStore((state) => state.patchNodeLocal);
  
  const [explorerCollapsed, setExplorerCollapsed] = useState(false);
  const [repoPath, setRepoPath] = useState("./demo_project");
  const [highlightedPathIndex, setHighlightedPathIndex] = useState(null);
  const [attackPaths, setAttackPaths] = useState([]);
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [panelTab, setPanelTab] = useState("node");

  useEffect(() => {
    fetch(endpoints.attackPaths)
      .then(res => res.json())
      .then(data => setAttackPaths(data.paths || data))
      .catch(console.error);
  }, []);

  useEffect(() => {
    if (highlightedPathIndex === null || !attackPaths.length) return;
    const pathNodes = attackPaths[highlightedPathIndex]?.path || [];
    setPath(pathNodes);
  }, [highlightedPathIndex, attackPaths, setPath]);

  const handlePatch = async (nodeId) => {
    patchNodeLocal(nodeId);
    try {
      const res = await fetch(endpoints.patchNode(nodeId), { method: "POST" });
      if (res.ok) {
        const payload = await res.json();
        setGraph(normalizeGraph(payload));
        setPath([]);
      }
    } catch (_) {}
  };

  useEffect(() => {
    const loadGraph = async () => {
      setLoading(true);
      try {
        const graphRes = await fetch(endpoints.graph);
        if (!graphRes.ok) {
          throw new Error("Failed to load graph");
        }
        const graphPayload = await graphRes.json();
        setGraph(normalizeGraph(graphPayload));
        setExplanation("Graph loaded.");
      } catch (error) {
        setGraph({ nodes: [], links: [] });
        setExplanation("Unable to load graph from backend.");
      } finally {
        setLoading(false);
      }
    };

    loadGraph();
  }, [setGraph, setExplanation, setLoading]);

  const handleAnalyzeFiles = async (files) => {
    if (!files || files.length === 0) return false;

    setLoading(true);
    setExplanation(`Uploading and analyzing ${files.length} files...`);
    
    const formData = new FormData();
    const folderName = files[0].webkitRelativePath 
      ? files[0].webkitRelativePath.split('/')[0] 
      : (files[0].name.replace(/\.[^/.]+$/, "") || "uploaded_project");
    formData.append("folder_name", folderName);
    setRepoPath(folderName);

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      // Skip heavy dependency folders, but keep .git for blame attribution
      if (file.webkitRelativePath && (
          file.webkitRelativePath.includes('node_modules/') || 
          file.webkitRelativePath.includes('.venv/') ||
          file.webkitRelativePath.includes('__pycache__/'))) {
        continue;
      }
      formData.append("files", file, file.webkitRelativePath || file.name);
    }

    try {
      const res = await fetch(endpoints.scanUpload, {
        method: "POST",
        body: formData
      });
      
      if (res.ok) {
        const scanRes = await res.json();
        const scannedPath = scanRes.git_root || scanRes.project_path || folderName;
        console.log("[Scan] Actual scanned project_path:", scannedPath);
        setRepoPath(scannedPath);

        const graphRes = await fetch(endpoints.graph);
        const graphPayload = await graphRes.json();
        setGraph(normalizeGraph(graphPayload));
        setExplanation(`Upload and scan complete for ${scannedPath}.`);
        
        fetch(endpoints.attackPaths)
          .then(r => r.json())
          .then(data => setAttackPaths(data.paths || data))
          .catch(console.error);

        setShowUploadModal(false);
        return true;
      } else {
        const err = await res.json();
        alert("Upload failed: " + (err.detail || err.error || "Unknown error"));
        setExplanation("Scan failed.");
        return false;
      }
    } catch (err) {
      alert("Error contacting backend: " + err.message);
      setExplanation("Scan failed.");
      return false;
    } finally {
      setLoading(false);
    }
  };

  const hasActiveGraph = Boolean(graph?.nodes && graph.nodes.length > 0);

  // If no repository has been loaded yet, show the centered RepoAnalyzer screen
  if (!hasActiveGraph && !loading) {
    return (
      <RepoAnalyzer
        onAnalyze={handleAnalyzeFiles}
        isLoading={loading}
        loadingMessage="Uploading & Analyzing Repository..."
        hasActiveGraph={false}
      />
    );
  }

  return (
    <div style={{ display: "flex", height: "100vh", overflow: "hidden", position: "relative" }}>
      {/* Modal overlay when user clicks 'Scan New Project' */}
      {showUploadModal && (
        <RepoAnalyzer
          onAnalyze={handleAnalyzeFiles}
          isLoading={loading}
          loadingMessage="Uploading & Analyzing Repository..."
          hasActiveGraph={true}
          onClose={() => setShowUploadModal(false)}
        />
      )}

      {/* LEFT: Explorer panel */}
      <ExplorerPanel
        collapsed={explorerCollapsed}
        onToggle={() => setExplorerCollapsed(c => !c)}
      />

      {/* CENTER + RIGHT: Main Security Analysis Layout */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <MetricsBar onScan={() => setShowUploadModal(true)} />
        <div className="main-layout" style={{ display: "flex", flex: 1, overflow: "hidden" }}>
          <div className="graph-wrap" style={{ flex: 1, position: "relative" }}>
            <GraphCanvas onNodeClick={setSelectedNode} />

            {/* Floating Query Button (Matches Reference Screenshots) */}
            <button
              type="button"
              className="floating-query-btn"
              onClick={() => setPanelTab(prev => prev === "ai" ? "node" : "ai")}
              title="Open AI Security Intelligence Query"
            >
              <span className="query-btn-icon">&gt;_</span>
              <span className="query-btn-text">Query</span>
            </button>
          </div>
          <div style={{ width: "30%", minWidth: "300px", height: "100%" }}>
            <UnifiedPanel
              selectedNode={selectedNode}
              attackPath={attackPath}
              attackPaths={attackPaths}
              onPatch={handlePatch}
              onHighlightPath={(idx) => {
                setHighlightedPathIndex(idx);
              }}
              onSelectNode={(nodeId) => {
                const node = graph?.nodes?.find(n => n.id === nodeId);
                if (node) setSelectedNode(node);
              }}
              externalTab={panelTab}
            />
          </div>
        </div>
      </div>
      <CommitTimeline repoPath={repoPath} />
    </div>
  );
};

export default App;

