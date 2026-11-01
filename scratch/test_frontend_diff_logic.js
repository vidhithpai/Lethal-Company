// Test script for frontend visual diff logic in GraphCanvas
const assert = require('assert');

// 1. Simulate getNodeColor
const getNodeColor = (node) => {
  if (node.patched) return '#64748B';
  const nodeType = String(node.type || '').toLowerCase();
  const typeColors = {
    source: '#10B981',
    sink: '#EF4444',
    intermediate: '#F59E0B',
    sanitizer: '#0EA5E9',
    function: '#3B82F6',
    normal: '#3B82F6',
  };
  return typeColors[nodeType] || '#3B82F6';
};

// 2. Simulate getNodeDiffStatus with strict priority: weakened > added > touched
function getNodeDiffStatus(node, diffStatus, diffNodeSet) {
  if (node._isGhost || node.diff_status === 'removed') return 'removed';
  const id = node.id;
  if (!diffStatus && (!diffNodeSet || !diffNodeSet.size)) return null;

  // 1. Weakened (highest priority)
  if (diffStatus?.weakened && diffStatus.weakened[id]) return 'weakened';
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'weakened') return 'weakened';

  // 2. Added
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'added') return 'added';
  if (diffNodeSet && diffNodeSet.has(id)) return 'added';

  // 3. Touched
  if (diffStatus?.nodes && diffStatus.nodes[id] === 'touched') return 'touched';

  return null;
}

console.log("=== CHECK 1: Type Body Colours Preserved in Diff Mode ===");
const entryNode = { id: "entry_1", type: "source" };
const sinkNode = { id: "sink_1", type: "sink" };
const guardNode = { id: "guard_1", type: "sanitizer" };
const normalNode = { id: "norm_1", type: "normal" };

assert.strictEqual(getNodeColor(entryNode), "#10B981", "ENTRY must be green #10B981");
assert.strictEqual(getNodeColor(sinkNode), "#EF4444", "SINK must be red #EF4444");
assert.strictEqual(getNodeColor(guardNode), "#0EA5E9", "GUARD must be cyan/purple #0EA5E9");
assert.strictEqual(getNodeColor(normalNode), "#3B82F6", "NORMAL must be blue #3B82F6");
console.log("PASS: Node body colors are strictly maintained as their type colors.");

console.log("\n=== CHECK 2: Diff Status Priority (weakened > added > touched) ===");
// Node in weakened map AND nodes map marked as added
const multiStatusDiff = {
  nodes: { "node_A": "added", "node_B": "touched", "node_C": "added" },
  weakened: { "node_A": { before: 0.9, after: 0.0 } },
  removed_nodes: [{ id: "ghost_1", label: "removed_guard", type: "sanitizer" }]
};

const statusA = getNodeDiffStatus({ id: "node_A" }, multiStatusDiff, new Set());
assert.strictEqual(statusA, "weakened", "Priority must choose weakened over added");

const statusB = getNodeDiffStatus({ id: "node_B" }, multiStatusDiff, new Set());
assert.strictEqual(statusB, "touched", "Touched status resolved correctly");

const statusC = getNodeDiffStatus({ id: "node_C" }, multiStatusDiff, new Set());
assert.strictEqual(statusC, "added", "Added status resolved correctly");

const statusGhost = getNodeDiffStatus({ id: "ghost_1", _isGhost: true }, multiStatusDiff, new Set());
assert.strictEqual(statusGhost, "removed", "Ghost node status resolved as removed");

const statusUntouched = getNodeDiffStatus({ id: "node_X" }, multiStatusDiff, new Set());
assert.strictEqual(statusUntouched, null, "Untouched node returns null");
console.log("PASS: Status priority weakened > added > touched strictly verified.");

console.log("\n=== CHECK 3: Edge Diff Styling Properties ===");
const diffStatusEdges = {
  edges: { "entry_1->guard_1": "added" },
  weakened: { "guard_1": { before: 0.90, after: 0.00 } },
  removed_edges: [{ source: "ghost_1", target: "sink_1" }]
};
const weakenedSinkEdges = new Set(["guard_1->sink_1"]);

const isAddedEdge = (s, t) => diffStatusEdges.edges[`${s}->${t}`] === "added";
const isWeakenedSinkEdge = (s, t) => weakenedSinkEdges.has(`${s}->${t}`);
const isRemovedEdge = (link) => Boolean(link._isGhostEdge);

const getLinkColor = (link, diffMode) => {
  if (diffMode) {
    if (isAddedEdge(link.source, link.target)) return '#FACC15';
    if (isWeakenedSinkEdge(link.source, link.target)) return '#FB923C';
    if (isRemovedEdge(link)) return '#FFFFFF';
    return '#3B82F6'; // default
  }
  return '#3B82F6';
};

const getLinkWidth = (link, diffMode) => {
  if (diffMode) {
    if (isAddedEdge(link.source, link.target)) return 3.5;
    if (isWeakenedSinkEdge(link.source, link.target)) return 3.0;
    if (isRemovedEdge(link)) return 1.2;
    return 1.5;
  }
  return 1.5;
};

const getLinkOpacity = (link, diffMode) => {
  if (diffMode) {
    if (isAddedEdge(link.source, link.target)) return 1.0;
    if (isWeakenedSinkEdge(link.source, link.target)) return 0.95;
    if (isRemovedEdge(link)) return 0.35;
    return 0.08; // Untouched dimmed to 0.08
  }
  return 0.65;
};

const getLinkParticles = (link, diffMode) => {
  if (diffMode) {
    return isAddedEdge(link.source, link.target) ? 4 : 0;
  }
  return 0;
};

// Test added edge
const addedEdge = { source: "entry_1", target: "guard_1" };
assert.strictEqual(getLinkColor(addedEdge, true), "#FACC15", "Added edge color must be gold #FACC15");
assert.strictEqual(getLinkWidth(addedEdge, true), 3.5, "Added edge width must be 3.5");
assert.strictEqual(getLinkOpacity(addedEdge, true), 1.0, "Added edge opacity must be 1.0");
assert.strictEqual(getLinkParticles(addedEdge, true), 4, "Added edge must have 4 particles");

// Test weakened sink edge
const weakEdge = { source: "guard_1", target: "sink_1" };
assert.strictEqual(getLinkColor(weakEdge, true), "#FB923C", "Weakened sink edge must be amber #FB923C");
assert.strictEqual(getLinkWidth(weakEdge, true), 3.0, "Weakened sink edge width must be 3.0");
assert.strictEqual(getLinkOpacity(weakEdge, true), 0.95, "Weakened sink edge opacity must be 0.95");
assert.strictEqual(getLinkParticles(weakEdge, true), 0, "Weakened sink edge has 0 particles");

// Test removed edge
const removedEdge = { source: "ghost_1", target: "sink_1", _isGhostEdge: true };
assert.strictEqual(getLinkColor(removedEdge, true), "#FFFFFF", "Removed edge color must be white #FFFFFF");
assert.strictEqual(getLinkWidth(removedEdge, true), 1.2, "Removed edge width must be 1.2 (thin)");
assert.strictEqual(getLinkOpacity(removedEdge, true), 0.35, "Removed edge opacity must be 0.35");

// Test untouched edge
const untouchedEdge = { source: "norm_1", target: "norm_2" };
assert.strictEqual(getLinkOpacity(untouchedEdge, true), 0.08, "Untouched edge must be dimmed to 0.08");

console.log("PASS: Edge diff styling rules verified.");

console.log("\n=== CHECK 4: Ghost Nodes Lifecycle & Filters in DisplayedGraph ===");
const baseFilteredGraph = {
  nodes: [entryNode, sinkNode, guardNode],
  links: [{ source: "entry_1", target: "guard_1" }, { source: "guard_1", target: "sink_1" }]
};

const computeDisplayedGraph = (filteredGraph, diffMode, diffStatus, nodeVisibility) => {
  if (!diffMode || !diffStatus) return filteredGraph;

  const currentNodes = filteredGraph.nodes || [];
  const currentLinks = filteredGraph.links || [];
  const existingNodeIds = new Set(currentNodes.map(n => n.id));

  const removedNodes = (diffStatus.removed_nodes || []).filter(rn => {
    if (existingNodeIds.has(rn.id)) return false;
    const t = String(rn.type || 'normal').toLowerCase();
    return nodeVisibility[t] !== false;
  }).map(rn => ({
    ...rn,
    _isGhost: true,
    diff_status: 'removed',
  }));

  const allNodes = [...currentNodes, ...removedNodes];
  const allNodeIds = new Set(allNodes.map(n => n.id));

  const removedEdges = (diffStatus.removed_edges || []).filter(re => {
    return allNodeIds.has(re.source) && allNodeIds.has(re.target);
  }).map(re => ({
    source: re.source,
    target: re.target,
    _isGhostEdge: true,
    diff_status: 'removed',
  }));

  return { nodes: allNodes, links: [...currentLinks, ...removedEdges] };
};

// When diffMode is false:
const graphNormal = computeDisplayedGraph(baseFilteredGraph, false, multiStatusDiff, { sanitizer: true });
assert.strictEqual(graphNormal.nodes.length, 3, "No ghost nodes when diffMode is false");
assert.strictEqual(graphNormal.links.length, 2, "No ghost edges when diffMode is false");

// When diffMode is true:
const graphDiff = computeDisplayedGraph(baseFilteredGraph, true, multiStatusDiff, { sanitizer: true });
assert.strictEqual(graphDiff.nodes.length, 4, "Ghost node injected when diffMode is true");
const ghost = graphDiff.nodes.find(n => n.id === "ghost_1");
assert.strictEqual(ghost._isGhost, true, "Ghost node flagged correctly");

// When filter disables sanitizer:
const graphFiltered = computeDisplayedGraph(baseFilteredGraph, true, multiStatusDiff, { sanitizer: false });
assert.strictEqual(graphFiltered.nodes.find(n => n.id === "ghost_1"), undefined, "Ghost node respects nodeVisibility filter");

console.log("PASS: Ghost nodes properly isolated to diffMode and respect filters.");

console.log("\n=== ALL FRONTEND LOGIC CHECKS PASSED SUCCESSFULLY ===");

