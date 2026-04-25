import useStore from "../store/useStore";

const Sidebar = ({ onUpload }) => {
  const graph = useStore((state) => state.graph);
  const loadSampleGraph = useStore((state) => state.loadSampleGraph);
  const setDirectoryAttrs = (element) => {
    if (!element) return;
    element.setAttribute("webkitdirectory", "");
    element.setAttribute("directory", "");
  };

  const handleLoadSample = async () => {
    try {
      await loadSampleGraph();
    } catch (error) {
      console.error("Failed to load sample graph:", error);
    }
  };

  return (
    <aside className="sidebar panel">
      <h2>Data Source</h2>
      <label className="cyber-btn">
        Upload Codebase
        <input
          type="file"
          ref={setDirectoryAttrs}
          multiple
          onChange={onUpload}
        />
      </label>
      <button className="cyber-btn secondary" onClick={handleLoadSample}>
        Load Sample Graph
      </button>

      <div className="stats">
        <h3>Graph Stats</h3>
        <p>Nodes: {graph.nodes.length}</p>
        <p>Edges: {graph.edges.length}</p>
      </div>
    </aside>
  );
};

export default Sidebar;
