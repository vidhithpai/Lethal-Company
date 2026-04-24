import { useState } from "react";
import useStore from "../store/useStore";

const QueryBar = () => {
  const [query, setQuery] = useState("");
  const loading = useStore((state) => state.loading);
  const setLoading = useStore((state) => state.setLoading);
  const setAttackPath = useStore((state) => state.setAttackPath);
  const setExplanation = useStore((state) => state.setExplanation);

  const handleRunQuery = async () => {
    setLoading(true);
    try {
      const askRes = await fetch("http://localhost:8000/api/query/ask", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query })
      });

      const askData = await askRes.json().catch(() => ({}));
      const targetNode = askData.target_node || "database";
      const pathRes = await fetch(
        `http://localhost:8000/api/graph/path?target=${encodeURIComponent(targetNode)}`
      );
      const pathData = await pathRes.json();

      const path = pathData.path || ["internet", "firewall", "webserver", "appserver", "database"];
      setAttackPath(path);
      setExplanation(
        askData.explanation ||
          `Likely path to ${targetNode}: ${path.join(" -> ")}`
      );
    } catch (error) {
      const mockPath = ["internet", "firewall", "webserver", "appserver", "database"];
      setAttackPath(mockPath);
      setExplanation(
        `Backend unavailable. Showing mock path for "${query || "database"}": ${mockPath.join(
          " -> "
        )}`
      );
    } finally {
      setLoading(false);
    }
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
    </div>
  );
};

export default QueryBar;
