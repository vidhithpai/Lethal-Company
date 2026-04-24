import { useRef, useState } from "react";
import { endpoints, normalizeGraph } from "../api";
import useStore from "../store/useStore";

const QueryBar = () => {
  const [query, setQuery] = useState("");
  const [projectPath, setProjectPath] = useState("");
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [selectedFolderName, setSelectedFolderName] = useState("");
  const folderInputRef = useRef(null);
  const loading = useStore((state) => state.loading);
  const setLoading = useStore((state) => state.setLoading);
  const setPath = useStore((state) => state.setPath);
  const setGraph = useStore((state) => state.setGraph);
  const setExplanation = useStore((state) => state.setExplanation);

  const refreshGraph = async () => {
    const graphRes = await fetch(endpoints.graph);
    if (!graphRes.ok) {
      throw new Error("Failed to refresh graph");
    }
    const graphPayload = await graphRes.json();
    setGraph(normalizeGraph(graphPayload));
    setPath([]);
  };

  const handleRunQuery = async () => {
    const trimmedQuery = query.trim();
    if (!trimmedQuery) return;

    setLoading(true);
    try {
      const askRes = await fetch(endpoints.ask, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: trimmedQuery })
      });
      if (!askRes.ok) {
        throw new Error("Failed to ask query");
      }

      const askData = await askRes.json().catch(() => ({}));
      const targetNode = askData.target_node || "database";
      const pathRes = await fetch(`${endpoints.graphPath}?target=${encodeURIComponent(targetNode)}`);
      if (!pathRes.ok) {
        throw new Error("Failed to fetch path");
      }
      const pathData = await pathRes.json();

      const nextPath = pathData.path || [];
      setPath(nextPath);
      setExplanation(askData.explanation || `Likely path to ${targetNode}: ${nextPath.join(" -> ")}`);
    } catch (error) {
      setPath([]);
      setExplanation("Query failed. Backend may be unavailable.");
    } finally {
      setLoading(false);
    }
  };

  const handleScanProject = async () => {
    const trimmedPath = projectPath.trim();
    if (!trimmedPath && !selectedFiles.length) return;

    setLoading(true);
    try {
      let scanRes;
      if (selectedFiles.length) {
        const formData = new FormData();
        selectedFiles.forEach((file) => {
          formData.append("files", file, file.webkitRelativePath || file.name);
        });
        formData.append("folder_name", selectedFolderName || "uploaded_project");
        scanRes = await fetch(endpoints.scanUpload, {
          method: "POST",
          body: formData
        });
      } else {
        scanRes = await fetch(endpoints.scan, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ project_path: trimmedPath })
        });
      }
      if (!scanRes.ok) {
        const errorPayload = await scanRes.json().catch(() => ({}));
        throw new Error(errorPayload.detail || "Failed project scan");
      }

      await refreshGraph();
      const projectRef = selectedFolderName || trimmedPath;
      setExplanation(`Project scan complete for: ${projectRef}`);
    } catch (error) {
      setExplanation(`Project scan failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  const setDirectoryAttrs = (element) => {
    if (!element) return;
    element.setAttribute("webkitdirectory", "");
    element.setAttribute("directory", "");
  };

  const handleFolderPick = (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;

    const selectedFolder = (files[0].webkitRelativePath || "").split("/")[0] || "";
    if (selectedFolder) {
      setSelectedFiles(files);
      setSelectedFolderName(selectedFolder);
      setProjectPath("");
      setExplanation(`Selected folder: ${selectedFolder}. Click "Scan Project" to upload and scan.`);
    }

    event.target.value = "";
  };

  return (
    <div className="query-bar">
      <input
        type="text"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Ask about attack paths..."
      />
      <button className="cyber-btn" onClick={handleRunQuery} disabled={loading}>
        {loading ? "Loading..." : "Ask"}
      </button>
      <input
        type="text"
        value={projectPath}
        onChange={(event) => setProjectPath(event.target.value)}
        placeholder="Project folder path (e.g. C:\\repo\\service)"
      />
      <button
        className="cyber-btn"
        onClick={() => folderInputRef.current?.click()}
        disabled={loading}
      >
        Select Project Folder
      </button>
      <input
        type="file"
        ref={(element) => {
          folderInputRef.current = element;
          setDirectoryAttrs(element);
        }}
        multiple
        onChange={handleFolderPick}
        style={{ display: "none" }}
      />
      <button className="cyber-btn" onClick={handleScanProject} disabled={loading}>
        {loading ? "Loading..." : "Scan Project"}
      </button>
      <button
        className="cyber-btn"
        onClick={async () => {
          setLoading(true);
          try {
            const mockRes = await fetch(endpoints.useMock, { method: "POST" });
            if (!mockRes.ok) {
              throw new Error("Failed to switch mock graph");
            }
            await refreshGraph();
            setExplanation("Mock data activated.");
          } catch (error) {
            setExplanation("Unable to activate mock data.");
          } finally {
            setLoading(false);
          }
        }}
        disabled={loading}
      >
        {loading ? "Loading..." : "Use Mock Data"}
      </button>
    </div>
  );
};

export default QueryBar;
