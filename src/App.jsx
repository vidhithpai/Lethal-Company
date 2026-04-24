import { useEffect } from "react";
import GraphCanvas from "./components/GraphCanvas";
import QueryBar from "./components/QueryBar";
import SidePanel from "./components/SidePanel";
import { endpoints, normalizeGraph } from "./api";
import useStore from "./store/useStore";

const App = () => {
  const loading = useStore((state) => state.loading);
  const setLoading = useStore((state) => state.setLoading);
  const setGraph = useStore((state) => state.setGraph);
  const setSelectedNode = useStore((state) => state.setSelectedNode);
  const setExplanation = useStore((state) => state.setExplanation);

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

  return (
    <div className="app-root">
      <QueryBar />
      <div className="main-layout">
        <div className="graph-wrap">
          <GraphCanvas onNodeClick={setSelectedNode} />
        </div>
        <SidePanel />
      </div>
    </div>
  );
};

export default App;
