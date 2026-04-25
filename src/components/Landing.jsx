const Landing = ({ onUpload, onLoadSample }) => {
  const setDirectoryAttrs = (element) => {
    if (!element) return;
    element.setAttribute("webkitdirectory", "");
    element.setAttribute("directory", "");
  };

  return (
    <div className="landing">
      <div className="landing-grid" />
      <div className="landing-card">
        <p className="landing-tag">Threat Flow Visualizer</p>
        <h1>VulnGraph</h1>
        <p className="landing-subtitle">
          Analyze attack surfaces, trace exploit paths, and inspect vulnerable
          code flow in an interactive graph.
        </p>
        <div className="landing-actions">
          <label className="cyber-btn">
            Upload Codebase
            <input
              type="file"
              ref={setDirectoryAttrs}
              multiple
              onChange={onUpload}
            />
          </label>
          <button className="cyber-btn secondary" onClick={onLoadSample}>
            Load Sample Graph
          </button>
        </div>
      </div>
    </div>
  );
};

export default Landing;
