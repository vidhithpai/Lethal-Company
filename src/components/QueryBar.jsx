import { useCallback, useEffect, useRef, useState } from "react";
import { endpoints, normalizeGraph } from "../api";
import useStore from "../store/useStore";

// ms each path stays highlighted before switching to the next
const ANIM_INTERVAL_MS = 2000;

// Intents that trigger multi-path animation rather than a single-path lookup
const MULTI_PATH_INTENTS = new Set([
  "show_attack_paths",
  "show_high_risk",
]);

const QueryBar = () => {
  const [query, setQuery]                       = useState("");
  const [projectPath, setProjectPath]           = useState("");
  const [selectedFiles, setSelectedFiles]       = useState([]);
  const [selectedFolderName, setSelectedFolderName] = useState("");
  const folderInputRef = useRef(null);
  const animTimerRef   = useRef(null);   // holds the setInterval id

  const loading            = useStore((s) => s.loading);
  const isAnimating        = useStore((s) => s.isAnimating);
  const animationIndex     = useStore((s) => s.animationIndex);
  const totalPaths         = useStore((s) => s.totalPaths);
  const setLoading         = useStore((s) => s.setLoading);
  const setPath            = useStore((s) => s.setPath);
  const setGraph           = useStore((s) => s.setGraph);
  const setExplanation     = useStore((s) => s.setExplanation);
  const setIsAnimating     = useStore((s) => s.setIsAnimating);
  const setAnimationStatus = useStore((s) => s.setAnimationStatus);
  const bumpZoom           = useStore((s) => s.bumpZoom);

  // ── Stop any running animation ─────────────────────────────────────────────
  const stopAnimation = useCallback(() => {
    if (animTimerRef.current) {
      clearInterval(animTimerRef.current);
      animTimerRef.current = null;
    }
    setIsAnimating(false);
    setAnimationStatus(0, 0);
  }, [setIsAnimating, setAnimationStatus]);

  // cleanup on unmount
  useEffect(() => () => stopAnimation(), [stopAnimation]);

  // ── Start multi-path animation ─────────────────────────────────────────────
  const startAnimation = useCallback((paths, riskFilter) => {
    stopAnimation();

    // Filter by risk if the AI requested it
    let filtered = riskFilter
      ? paths.filter((p) => p.risk === riskFilter)
      : paths;

    if (!filtered.length) filtered = paths.slice(0, 20);
    if (!filtered.length) return;

    let idx = 0;

    // Show first path immediately
    setPath(filtered[0].path);
    setIsAnimating(true);
    setAnimationStatus(1, filtered.length);
    bumpZoom();

    animTimerRef.current = setInterval(() => {
      idx = (idx + 1) % filtered.length;
      setPath(filtered[idx].path);
      setAnimationStatus(idx + 1, filtered.length);
      bumpZoom();
    }, ANIM_INTERVAL_MS);
  }, [stopAnimation, setPath, setIsAnimating, setAnimationStatus, bumpZoom]);

  // ── Refresh graph data ─────────────────────────────────────────────────────
  const refreshGraph = async () => {
    const res = await fetch(endpoints.graph);
    if (!res.ok) throw new Error("Failed to refresh graph");
    const payload = await res.json();
    setGraph(normalizeGraph(payload));
    setPath([]);
  };

  // ── Main query handler ─────────────────────────────────────────────────────
  const handleRunQuery = async () => {
    const q = query.trim();
    if (!q) return;

    stopAnimation();
    setLoading(true);

    try {
      // 1. Ask AI for intent + explanation
      const askRes = await fetch(endpoints.ask, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ query: q }),
      });
      if (!askRes.ok) throw new Error("Failed to ask query");
      const askData = await askRes.json().catch(() => ({}));

      const { intent, target_node, risk_filter, explanation } = askData;
      setExplanation(explanation || "");

      // 2. Multi-path animation for broad queries
      if (MULTI_PATH_INTENTS.has(intent)) {
        const pathEndpoint =
          intent === "show_high_risk" ? endpoints.highRiskPaths : endpoints.attackPaths;
        const pathsRes = await fetch(pathEndpoint);
        if (pathsRes.ok) {
          const pathsData = await pathsRes.json().catch(() => ({ paths: [] }));
          const allPaths  = pathsData.paths || [];
          if (allPaths.length) {
            setLoading(false);
            startAnimation(allPaths, risk_filter || null);
            return;
          }
        }
        // fall through to single-path if no paths returned
      }

      // 3. Single-path highlight for targeted queries
      const sinkTarget = target_node || "database";
      const pathRes = await fetch(
        `${endpoints.graphPath}?target=${encodeURIComponent(sinkTarget)}`
      );
      if (!pathRes.ok) throw new Error("Failed to fetch path");
      const pathData = await pathRes.json();
      const singlePath = pathData.path || [];

      setPath(singlePath);
      if (singlePath.length) bumpZoom();

    } catch {
      setPath([]);
      setExplanation("Query failed. Backend may be unavailable.");
    } finally {
      setLoading(false);
    }
  };

  // ── Scan handlers (unchanged) ──────────────────────────────────────────────
  const handleScanProject = async () => {
    const trimmedPath = projectPath.trim();
    if (!trimmedPath && !selectedFiles.length) return;

    stopAnimation();
    setLoading(true);
    try {
      let scanRes;
      if (selectedFiles.length) {
        const formData = new FormData();
        selectedFiles.forEach((file) => {
          formData.append("files", file, file.webkitRelativePath || file.name);
        });
        formData.append("folder_name", selectedFolderName || "uploaded_project");
        scanRes = await fetch(endpoints.scanUpload, { method: "POST", body: formData });
      } else {
        scanRes = await fetch(endpoints.scan, {
          method:  "POST",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ project_path: trimmedPath }),
        });
      }
      if (!scanRes.ok) {
        const err = await scanRes.json().catch(() => ({}));
        throw new Error(err.detail || "Failed project scan");
      }
      await refreshGraph();
      setExplanation(`Scan complete: ${selectedFolderName || trimmedPath}`);
    } catch (err) {
      setExplanation(`Scan failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const setDirectoryAttrs = (el) => {
    if (!el) return;
    el.setAttribute("webkitdirectory", "");
    el.setAttribute("directory", "");
  };

  const handleFolderPick = (e) => {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;
    const folderName = (files[0].webkitRelativePath || "").split("/")[0] || "";
    if (folderName) {
      setSelectedFiles(files);
      setSelectedFolderName(folderName);
      setProjectPath("");
      setExplanation(`Folder "${folderName}" selected. Click Scan Project.`);
    }
    e.target.value = "";
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleRunQuery();
  };

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="query-bar-wrap">
      <div className="query-bar">
        {/* AI query input */}
        <input
          id="query-input"
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask about attack paths… e.g. 'show SQL injection paths'"
        />
        <button className="cyber-btn" onClick={handleRunQuery} disabled={loading}>
          {loading ? "Loading…" : "Ask"}
        </button>

        {/* Scan by path */}
        <input
          id="project-path-input"
          type="text"
          value={projectPath}
          onChange={(e) => setProjectPath(e.target.value)}
          placeholder="Project folder path…"
        />
        <button
          className="cyber-btn"
          onClick={() => folderInputRef.current?.click()}
          disabled={loading}
        >
          Select Folder
        </button>
        <input
          type="file"
          ref={(el) => { folderInputRef.current = el; setDirectoryAttrs(el); }}
          multiple
          onChange={handleFolderPick}
          style={{ display: "none" }}
        />
        <button className="cyber-btn" onClick={handleScanProject} disabled={loading}>
          {loading ? "Scanning…" : "Scan Project"}
        </button>

        {/* Mock data */}
        <button
          className="cyber-btn"
          disabled={loading}
          onClick={async () => {
            stopAnimation();
            setLoading(true);
            try {
              const res = await fetch(endpoints.useMock, { method: "POST" });
              if (!res.ok) throw new Error();
              await refreshGraph();
              setExplanation("Mock data activated.");
            } catch {
              setExplanation("Unable to activate mock data.");
            } finally {
              setLoading(false);
            }
          }}
        >
          {loading ? "Loading…" : "Use Mock Data"}
        </button>
      </div>

      {/* Animation status pill — only visible while animating */}
      {isAnimating && (
        <div className="anim-status">
          <span className="anim-dot" />
          <span className="anim-label">
            Animating path
            <strong> {animationIndex} </strong>
            of
            <strong> {totalPaths}</strong>
          </span>
          <button className="anim-stop" onClick={stopAnimation}>■ Stop</button>
        </div>
      )}
    </div>
  );
};

export default QueryBar;
