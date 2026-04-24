import { useState } from "react";
import EntryPage from "./components/EntryPage";
import GraphCanvas from "./components/GraphCanvas";
import QueryBar from "./components/QueryBar";
import SidePanel from "./components/SidePanel";
import useStore, { MOCK_GRAPH } from "./store/useStore";

const App = () => {
  const [screen, setScreen] = useState("entry");
  const loading = useStore((state) => state.loading);
  const setLoading = useStore((state) => state.setLoading);
  const setGraphData = useStore((state) => state.setGraphData);
  const setSelectedNode = useStore((state) => state.setSelectedNode);
  const setExplanation = useStore((state) => state.setExplanation);

  const enterWithDemo = () => {
    setGraphData(MOCK_GRAPH);
    setExplanation("Demo graph loaded. Folder mode will replace this later.");
    setScreen("graph");
  };

  const enterWithFolder = async (files, folderName) => {
    setLoading(true);
    try {
      const formData = new FormData();
      files.forEach((file) => formData.append("files", file));
      formData.append("folder_name", folderName);

      await fetch("http://localhost:8000/api/project/upload", {
        method: "POST",
        body: formData
      });

      const graphRes = await fetch("http://localhost:8000/api/graph");
      if (graphRes.ok) {
        const graphPayload = await graphRes.json();
        setGraphData({
          nodes: graphPayload.nodes || [],
          links: graphPayload.links || []
        });
        setExplanation(`Loaded graph for folder "${folderName}".`);
      } else {
        setGraphData(MOCK_GRAPH);
        setExplanation(`Folder "${folderName}" sent. Backend graph unavailable; showing demo graph.`);
      }
      setScreen("graph");
    } catch (error) {
      setGraphData(MOCK_GRAPH);
      setExplanation(
        `Folder "${folderName}" selected but backend is unavailable. Demo graph loaded as fallback.`
      );
      setScreen("graph");
    } finally {
      setLoading(false);
    }
  };

  if (screen === "entry") {
    return (
      <EntryPage loading={loading} onUseDemo={enterWithDemo} onUploadFolder={enterWithFolder} />
    );
  }

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
