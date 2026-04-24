import useStore from "../store/useStore";

const NodePanel = () => {
  const selectedNode = useStore((state) => state.selectedNode);
  const explanation = useStore((state) => state.explanation);

  return (
    <aside className="node-panel panel">
      <h2>Node Details</h2>
      {selectedNode ? (
        <div className="terminal-block">
          <p>
            <span>id:</span> {selectedNode.id}
          </p>
          <p>
            <span>type:</span> {selectedNode.type || "unknown"}
          </p>
          <p>
            <span>file:</span> {selectedNode.file || "n/a"}
          </p>
          <p>
            <span>function:</span> {selectedNode.function || "n/a"}
          </p>
          <p>
            <span>description:</span>{" "}
            {selectedNode.description || "No vulnerability description."}
          </p>
        </div>
      ) : (
        <p className="muted">Click a node to inspect vulnerability details.</p>
      )}

      <h3>Attack Path Explanation</h3>
      <div className="terminal-block">
        <p>{explanation || "Run a query to generate an attack path explanation."}</p>
      </div>
    </aside>
  );
};

export default NodePanel;
