import useStore from "../store/useStore";
import { endpoints } from "../api";

const SidePanel = () => {
  const graph = useStore((state) => state.graph);
  const path = useStore((state) => state.path);
  const selectedNode = useStore((state) => state.selectedNode);
  const explanation = useStore((state) => state.explanation);
  const patchNodeLocal = useStore((state) => state.patchNodeLocal);

  const pathEdges = new Set();
  for (let i = 0; i < path.length - 1; i += 1) {
    pathEdges.add(`${path[i]}->${path[i + 1]}`);
  }

  const cves = graph.links.filter((link) => {
    const source = link.source.id || link.source;
    const target = link.target.id || link.target;
    return pathEdges.has(`${source}->${target}`);
  });

  const patchNode = async () => {
    if (!selectedNode) return;
    patchNodeLocal(selectedNode.id);

    try {
      await fetch(endpoints.patchNode(selectedNode.id), {
        method: "POST"
      });
    } catch (error) {
      // Keep local patch state even when backend is unavailable.
    }
  };

  return (
    <aside className="side-panel">
      <h2>AI Explanation</h2>
      <p className="explanation">{explanation || "Ask a query to analyze an attack route."}</p>

      <h3>CVEs on Path</h3>
      <ul className="cve-list">
        {cves.length ? (
          cves.map((item, idx) => (
            <li key={`${item.cve}-${idx}`}>
              <span>{item.cve}</span>
              <strong>{item.severity}</strong>
            </li>
          ))
        ) : (
          <li className="muted">No active attack path selected.</li>
        )}
      </ul>

      <div className="selected-box">
        <h3>Selected Node</h3>
        <p>{selectedNode ? `${selectedNode.label} (${selectedNode.id})` : "None"}</p>
        <button className="cyber-btn" onClick={patchNode} disabled={!selectedNode}>
          Patch this node
        </button>
      </div>
    </aside>
  );
};

export default SidePanel;
