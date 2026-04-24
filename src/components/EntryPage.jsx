import { useState } from "react";

const EntryPage = ({ loading, onUseDemo, onUploadFolder }) => {
  const [folderStatus, setFolderStatus] = useState("No project folder selected");

  const setDirectoryAttrs = (element) => {
    if (!element) return;
    element.setAttribute("webkitdirectory", "");
    element.setAttribute("directory", "");
  };

  const handleFolderPick = (event) => {
    const files = Array.from(event.target.files || []);
    if (!files.length) return;

    const root = (files[0].webkitRelativePath || "").split("/")[0] || "project-folder";
    setFolderStatus(`${root} (${files.length} files selected)`);
    onUploadFolder(files, root);
    event.target.value = "";
  };

  return (
    <div className="entry-page">
      <div className="entry-card">
        <h1>VulnGraph</h1>
        <p>Choose input source (folder ingest or demo data).</p>
        <div className="entry-actions">
          <label className="cyber-btn folder-btn">
            {loading ? "Uploading..." : "Enter Project Folder"}
            <input
              type="file"
              ref={setDirectoryAttrs}
              multiple
              onChange={handleFolderPick}
              disabled={loading}
            />
          </label>
          <button className="cyber-btn" onClick={onUseDemo} disabled={loading}>
            Use Demo Data
          </button>
        </div>
        <small className="folder-status">{folderStatus}</small>
      </div>
    </div>
  );
};

export default EntryPage;
