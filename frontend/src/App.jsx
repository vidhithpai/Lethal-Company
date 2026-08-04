import { useEffect, useState, useRef } from "react";
import GraphCanvas from "./components/canvas/GraphCanvas";
import MetricsBar from "./components/metrics/MetricsBar";
import UnifiedPanel from "./components/panel/UnifiedPanel";
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
  
  const [highlightedPathIndex, setHighlightedPathIndex] = useState(null);
  const [attackPaths, setAttackPaths] = useState([]);
  const fileInputRef = useRef(null);

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

  const handleScanNewProject = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileUpload = async (e) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;

    setLoading(true);
    setExplanation(`Uploading ${files.length} files...`);
    
    const formData = new FormData();
    const folderName = files[0].webkitRelativePath ? files[0].webkitRelativePath.split('/')[0] : "uploaded_project";
    formData.append("folder_name", folderName);

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      // Skip heavy dependency folders, but keep .git for blame attribution
      if (file.webkitRelativePath.includes('node_modules/') || 
          file.webkitRelativePath.includes('.venv/') ||
          file.webkitRelativePath.includes('__pycache__/')) {
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
        const graphRes = await fetch(endpoints.graph);
        const graphPayload = await graphRes.json();
        setGraph(normalizeGraph(graphPayload));
        setExplanation(`Upload and scan complete.`);
        
        fetch(endpoints.attackPaths)
          .then(r => r.json())
          .then(data => setAttackPaths(data.paths || data))
          .catch(console.error);
      } else {
        const err = await res.json();
        alert("Upload failed: " + (err.detail || err.error || "Unknown error"));
        setExplanation("Scan failed.");
      }
    } catch (err) {
      alert("Error contacting backend: " + err.message);
      setExplanation("Scan failed.");
    } finally {
      setLoading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <div className="app-root" style={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden" }}>
      <input 
        type="file" 
        webkitdirectory="true" 
        directory="true" 
        multiple 
        ref={fileInputRef} 
        style={{ display: "none" }} 
        onChange={handleFileUpload} 
      />
      <MetricsBar onScan={handleScanNewProject} />
      <div className="main-layout" style={{ display: "flex", flex: 1, overflow: "hidden" }}>
        <div className="graph-wrap" style={{ flex: 1 }}>
          <GraphCanvas onNodeClick={setSelectedNode} />
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
          />
        </div>
      </div>
    </div>
  );
};

export default App;
