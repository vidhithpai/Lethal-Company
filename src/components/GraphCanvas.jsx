import { useEffect, useMemo, useRef, useState } from "react";
import ForceGraph2D from "react-force-graph-2d";
import useStore from "../store/useStore";

const nodeColorByType = (type) => {
  if (type === "external") return "#9aa4b2";
  if (type === "network") return "#4ea1ff";
  if (type === "server") return "#9b7bff";
  if (type === "data") return "#ff5f6d";
  return "#6f7c8f";
};

const GraphCanvas = ({ onNodeClick }) => {
  const graphData = useStore((state) => state.graphData);
  const attackPath = useStore((state) => state.attackPath);
  const containerRef = useRef(null);
  const [size, setSize] = useState({ width: 300, height: 300 });

  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      setSize({
        width: Math.max(320, Math.floor(entry.contentRect.width)),
        height: Math.max(320, Math.floor(entry.contentRect.height))
      });
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const pathEdges = useMemo(() => {
    const edges = new Set();
    for (let i = 0; i < attackPath.length - 1; i += 1) {
      edges.add(`${attackPath[i]}->${attackPath[i + 1]}`);
    }
    return edges;
  }, [attackPath]);

  const clampNodePositions = () => {
    const nodes = graphData?.nodes || [];
    const padding = 24;
    const minX = -size.width / 2 + padding;
    const maxX = size.width / 2 - padding;
    const minY = -size.height / 2 + padding;
    const maxY = size.height / 2 - padding;

    nodes.forEach((node) => {
      node.x = Math.min(maxX, Math.max(minX, node.x ?? 0));
      node.y = Math.min(maxY, Math.max(minY, node.y ?? 0));
    });
  };

  return (
    <div className="graph-canvas" ref={containerRef}>
      <ForceGraph2D
        width={size.width}
        height={size.height}
        graphData={graphData}
        nodeLabel={(node) => `${node.label || node.id} (${node.type || "Node"})`}
        onNodeClick={(node) => onNodeClick(node)}
        onEngineTick={clampNodePositions}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const label = node.label || node.id;
          const fontSize = 12 / globalScale;

          ctx.beginPath();
          ctx.arc(node.x, node.y, node.patched ? 8 : 6, 0, 2 * Math.PI, false);
          ctx.fillStyle = node.patched ? "#2fd66f" : nodeColorByType(node.type);
          ctx.fill();

          ctx.font = `${fontSize}px monospace`;
          ctx.fillStyle = "#d0d7e3";
          ctx.fillText(label, node.x + 10, node.y + 4);
        }}
        linkWidth={(link) => {
          const source = link.source.id || link.source;
          const target = link.target.id || link.target;
          return pathEdges.has(`${source}->${target}`) ? 3.5 : 1.2;
        }}
        linkColor={(link) => {
          const source = link.source.id || link.source;
          const target = link.target.id || link.target;
          return pathEdges.has(`${source}->${target}`) ? "#ff4d4f" : "#425066";
        }}
        linkDirectionalParticles={(link) => {
          const source = link.source.id || link.source;
          const target = link.target.id || link.target;
          return pathEdges.has(`${source}->${target}`) ? 4 : 0;
        }}
        linkDirectionalParticleWidth={2}
        linkDirectionalParticleColor={() => "#ff4d4f"}
        backgroundColor="rgba(0,0,0,0)"
        cooldownTicks={80}
      />
    </div>
  );
};

export default GraphCanvas;
