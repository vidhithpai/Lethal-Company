import { useState, useRef, useCallback } from "react";

export default function RepoAnalyzer({
  onAnalyze,
  isLoading,
  loadingMessage,
  onClose,
  hasActiveGraph = false,
}) {
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [projectName, setProjectName] = useState("");
  const [isDragging, setIsDragging] = useState(false);
  const [validationError, setValidationError] = useState("");

  const folderInputRef = useRef(null);
  const fileInputRef = useRef(null);

  // Helper to extract files from drop event (supporting directories)
  const extractFilesFromDrop = async (dataTransfer) => {
    const items = dataTransfer.items;
    const files = [];

    if (items && items.length > 0 && items[0].webkitGetAsEntry) {
      const entries = [];
      for (let i = 0; i < items.length; i++) {
        const entry = items[i].webkitGetAsEntry();
        if (entry) entries.push(entry);
      }

      const traverse = async (entry, path = "") => {
        if (entry.isFile) {
          const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
          Object.defineProperty(file, "webkitRelativePath", {
            value: path ? `${path}/${file.name}` : file.name,
            writable: false,
          });
          files.push(file);
        } else if (entry.isDirectory) {
          const reader = entry.createReader();
          const readAll = async () => {
            const batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
            if (batch.length > 0) {
              for (const child of batch) {
                await traverse(child, path ? `${path}/${entry.name}` : entry.name);
              }
              await readAll();
            }
          };
          await readAll();
        }
      };

      for (const entry of entries) {
        await traverse(entry);
      }
      return files;
    }

    // Fallback to dataTransfer.files
    return Array.from(dataTransfer.files || []);
  };

  const handleFilesSelected = (files) => {
    if (!files || files.length === 0) {
      setValidationError("Please select a valid folder or source files.");
      return;
    }

    setValidationError("");
    setSelectedFiles(files);

    // Derive project name
    const firstRel = files[0].webkitRelativePath;
    let name = "uploaded_project";
    if (firstRel && firstRel.includes("/")) {
      name = firstRel.split("/")[0];
    } else if (files[0].name) {
      name = files[0].name.replace(/\.[^/.]+$/, "");
    }
    setProjectName(name);
  };

  const handleDrop = async (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (isLoading) return;

    try {
      const files = await extractFilesFromDrop(e.dataTransfer);
      if (files && files.length > 0) {
        handleFilesSelected(files);
      } else {
        setValidationError("No readable files found in dropped folder.");
      }
    } catch (err) {
      console.error("Drop extraction error:", err);
      setValidationError("Failed to read dropped files. Try using the folder picker button.");
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDragging) setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleFolderInputChange = (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      handleFilesSelected(files);
    }
  };

  const handleFileInputChange = (e) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) {
      handleFilesSelected(files);
    }
  };

  const handleClear = (e) => {
    e.stopPropagation();
    setSelectedFiles([]);
    setProjectName("");
    setValidationError("");
    if (folderInputRef.current) folderInputRef.current.value = "";
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const handleSubmit = async () => {
    if (!selectedFiles || selectedFiles.length === 0 || isLoading) return;
    try {
      await onAnalyze(selectedFiles);
    } catch (err) {
      setValidationError(err.message || "Analysis failed.");
    }
  };

  // Compute total size
  const totalSizeBytes = selectedFiles.reduce((acc, f) => acc + (f.size || 0), 0);
  const formattedSize =
    totalSizeBytes > 1024 * 1024
      ? `${(totalSizeBytes / (1024 * 1024)).toFixed(1)} MB`
      : `${Math.max(1, Math.round(totalSizeBytes / 1024))} KB`;

  return (
    <div className={hasActiveGraph ? "repo-modal-backdrop" : "repo-landing-container"}>
      {/* Background ambient glow effect */}
      <div className="repo-ambient-glow repo-glow-top" />
      <div className="repo-ambient-glow repo-glow-bottom" />

      <div className="repo-card">
        {/* Modal close button if an existing graph is loaded */}
        {hasActiveGraph && onClose && (
          <button
            type="button"
            className="repo-close-btn"
            onClick={onClose}
            aria-label="Close"
          >
            ✕
          </button>
        )}

        {/* Hidden inputs */}
        <input
          ref={folderInputRef}
          type="file"
          webkitdirectory="true"
          directory="true"
          multiple
          style={{ display: "none" }}
          onChange={handleFolderInputChange}
        />
        <input
          ref={fileInputRef}
          type="file"
          multiple
          style={{ display: "none" }}
          onChange={handleFileInputChange}
        />

        {/* ── Header ──────────────────────────────────────────────────────── */}
        <div className="repo-header">
          <div className="repo-eyebrow">
            <svg
              className="repo-sparkle-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83" />
            </svg>
            <span>VULNGRAPH</span>
          </div>

          <div className="repo-icon-box">
            <svg
              className="repo-graph-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.8"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="6" cy="6" r="3" />
              <circle cx="6" cy="18" r="3" />
              <circle cx="18" cy="12" r="3" />
              <path d="M6 9v6M9 6.5l6 4M9 17.5l6-4" />
            </svg>
          </div>

          <h1 className="repo-title">Analyze your repository</h1>
          <p className="repo-subtitle">
            Upload a local project folder to parse ASTs, resolve cross-file dependencies,
            trace data flows, and build an interactive 3D security graph — right in your browser.
          </p>
        </div>

        {/* ── Prominent Upload Area ─────────────────────────────────────────── */}
        <div
          className={`repo-dropzone ${isDragging ? "dragging" : ""} ${selectedFiles.length > 0 ? "has-files" : ""}`}
          onDrop={handleDrop}
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onClick={() => {
            if (!isLoading) folderInputRef.current?.click();
          }}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") {
              folderInputRef.current?.click();
            }
          }}
        >
          {selectedFiles.length === 0 ? (
            <div className="repo-dropzone-empty">
              <div className="repo-upload-icon-wrap">
                <svg
                  className="repo-folder-icon"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="1.75"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  <line x1="12" y1="11" x2="12" y2="17" />
                  <polyline points="9 14 12 11 15 14" />
                </svg>
              </div>

              <div className="repo-dropzone-text">
                <span className="dropzone-primary">
                  {isDragging ? "Drop your project folder here" : "Upload Project Folder"}
                </span>
                <span className="dropzone-secondary">
                  Drag and drop a folder here, or <span className="browse-link">browse from disk</span>
                </span>
              </div>

              <div className="repo-type-badges">
                <span className="badge">.java</span>
                <span className="badge">.py</span>
                <span className="badge">.js</span>
                <span className="badge">.ts</span>
                <span className="badge">.xml</span>
                <span className="badge">.json</span>
              </div>
            </div>
          ) : (
            <div className="repo-selected-box">
              <div className="selected-info-left">
                <div className="selected-icon-wrap">
                  <svg
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  >
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  </svg>
                </div>
                <div className="selected-text-wrap">
                  <div className="selected-project-name">{projectName}</div>
                  <div className="selected-project-stats">
                    {selectedFiles.length} files discovered · {formattedSize}
                  </div>
                </div>
              </div>

              <button
                type="button"
                className="selected-change-btn"
                onClick={handleClear}
                disabled={isLoading}
              >
                Change
              </button>
            </div>
          )}
        </div>

        {/* Validation or Error Message */}
        {validationError && (
          <div className="repo-error-banner">
            <svg
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            <span>{validationError}</span>
          </div>
        )}

        {/* ── Action Button: Analyze Repository ────────────────────────────── */}
        <div className="repo-action-wrap">
          <button
            type="button"
            className={`repo-analyze-btn ${selectedFiles.length > 0 && !isLoading ? "active" : "disabled"}`}
            disabled={selectedFiles.length === 0 || isLoading}
            onClick={handleSubmit}
          >
            {isLoading ? (
              <>
                <span className="repo-spinner" />
                <span>{loadingMessage || "Analyzing Repository..."}</span>
              </>
            ) : (
              <>
                <svg
                  className="analyze-sparkle"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 3l1.912 5.885L20 10.798l-4.756 3.456 1.816 5.886L12 16.684l-5.06 3.456 1.816-5.886L4 10.798l6.088-1.913L12 3z" />
                </svg>
                <span>Analyze Repository</span>
              </>
            )}
          </button>
        </div>

        {/* ── Footer ───────────────────────────────────────────────────────── */}
        <p className="repo-footer-note">
          Local analysis only · Deterministic AST security graphs · No data leaves your machine
        </p>
      </div>
    </div>
  );
}
