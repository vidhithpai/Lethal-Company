import { useState, useMemo, useEffect } from "react";
import useStore from "../../store/useStore";
import { endpoints } from "../../services/api";

/**
 * Build a nested directory tree from a flat list of file paths.
 * Each node has { name, path, type: 'file'|'dir', children, nodeCount }
 */
function buildDirTree(nodes) {
  const root = { name: 'root', path: '', type: 'dir', children: {}, nodeCount: 0 };

  for (const node of nodes) {
    const filePath = node.file || '';
    if (!filePath) continue;

    // Normalize: strip absolute prefix, keep relative-looking path
    // Find the shortest sensible relative path
    const parts = filePath.replace(/\\/g, '/').split('/').filter(Boolean);
    // Drop system prefix like /tmp/vulngraph_uploads/projectname or /app/...
    // Keep from the first part that looks like a project folder
    const meaningfulIdx = parts.findIndex((p, i) => 
      i > 0 && !['tmp','app','home','usr','var','private',
                   'vulngraph_uploads','uploads'].includes(p)
    );
    const relativeParts = meaningfulIdx >= 0 
      ? parts.slice(meaningfulIdx) 
      : parts.slice(-Math.min(parts.length, 5));

    if (relativeParts.length === 0) continue;

    // Walk the tree and insert
    let cur = root;
    for (let i = 0; i < relativeParts.length; i++) {
      const part = relativeParts[i];
      const isFile = i === relativeParts.length - 1;
      if (!cur.children[part]) {
        cur.children[part] = {
          name: part,
          path: relativeParts.slice(0, i + 1).join('/'),
          fullPath: filePath,     // only set on files
          type: isFile ? 'file' : 'dir',
          children: {},
          nodeCount: 0,
          nodeTypes: {},
        };
      }
      cur.children[part].nodeCount += 1;
      if (isFile) {
        const t = node.type || 'normal';
        cur.children[part].nodeTypes[t] = 
          (cur.children[part].nodeTypes[t] || 0) + 1;
      }
      cur = cur.children[part];
    }
  }

  // Convert children objects to sorted arrays
  function sortTree(node) {
    const childArr = Object.values(node.children);
    // Dirs first, then files, both alphabetical
    childArr.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });
    node.childArr = childArr.map(sortTree);
    return node;
  }

  return sortTree(root);
}

// Icon map by file extension
function FileIcon({ name }) {
  const ext = name.split('.').pop()?.toLowerCase();
  const icons = { java:'☕', py:'🐍', js:'𝐉', jsx:'⚛', ts:'𝐓',
                   tsx:'⚛', json:'{}', md:'📄', yml:'⚙', yaml:'⚙',
                   xml:'📋', html:'🌐', css:'🎨', sh:'$_' };
  return <span style={{ fontSize: 11, marginRight: 4 }}>
    {icons[ext] || '📄'}
  </span>;
}

// Risk dot: shows what node types exist in this file
function NodeTypeDots({ nodeTypes }) {
  const colors = { source:'#10B981', sink:'#EF4444',
                   sanitizer:'#8B5CF6', normal:'#3B82F6' };
  return (
    <span style={{ display:'flex', gap:2, marginLeft:'auto' }}>
      {Object.entries(nodeTypes || {}).map(([t, count]) => (
        <span key={t} title={`${count} ${t}`}
              style={{ width:6, height:6, borderRadius:'50%',
                       background: colors[t] || '#6B7280' }} />
      ))}
    </span>
  );
}

// Recursive tree node renderer
function TreeNode({ node, depth, onFileClick, selectedFile }) {
  const [open, setOpen] = useState(depth < 2);
  const isSelected = selectedFile === node.fullPath;

  if (node.type === 'file') {
    return (
      <div
        onClick={() => onFileClick(node)}
        style={{
          display: 'flex', alignItems: 'center',
          padding: `3px ${6 + depth * 14}px 3px ${6 + depth * 14}px`,
          cursor: 'pointer', borderRadius: 4,
          background: isSelected ? 'rgba(88,166,255,0.12)' : 'transparent',
          color: isSelected ? '#E6EDF3' : '#8B949E',
          fontSize: 12,
        }}
      >
        <FileIcon name={node.name} />
        <span style={{ flex:1, overflow:'hidden',
                        textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
          {node.name}
        </span>
        <NodeTypeDots nodeTypes={node.nodeTypes} />
      </div>
    );
  }

  return (
    <div>
      <div
        onClick={() => setOpen(o => !o)}
        style={{
          display: 'flex', alignItems: 'center', gap: 4,
          padding: `3px 6px 3px ${6 + depth * 14}px`,
          cursor: 'pointer', color: '#6E7681', fontSize: 12,
          userSelect: 'none',
        }}
      >
        <span style={{ fontSize: 10 }}>{open ? '▾' : '▸'}</span>
        <span style={{ fontSize: 11 }}>📁</span>
        <span style={{ flex:1, color: '#C9D1D9' }}>{node.name}</span>
        <span style={{ fontSize: 10, color:'#4B5563' }}>
          {node.nodeCount}
        </span>
      </div>
      {open && node.childArr?.map(child => (
        <TreeNode key={child.path} node={child} depth={depth + 1}
                  onFileClick={onFileClick} selectedFile={selectedFile} />
      ))}
    </div>
  );
}

// Simple syntax highlighter (colour keywords, strings, comments)
function CodeViewer({ content, language, highlightLine }) {
  if (!content) return (
    <div style={{ padding:16, color:'#4B5563', fontSize:12 }}>
      Select a file to view its source code.
    </div>
  );

  const lines = content.split('\n');
  return (
    <div style={{ fontFamily:'monospace', fontSize:11, lineHeight:1.6,
                  overflow:'auto', height:'100%', padding:'8px 0' }}>
      {lines.map((line, i) => (
        <div key={i}
             style={{
               display:'flex',
               background: highlightLine === i + 1
                 ? 'rgba(239,68,68,0.15)' : 'transparent',
             }}>
          <span style={{ minWidth:36, textAlign:'right', paddingRight:10,
                          color:'#4B5563', userSelect:'none', flexShrink:0 }}>
            {i + 1}
          </span>
          <pre style={{ margin:0, whiteSpace:'pre-wrap',
                         wordBreak:'break-all', color:'#E6EDF3' }}>
            {line}
          </pre>
        </div>
      ))}
    </div>
  );
}

// ── Main ExplorerPanel ─────────────────────────────────────────────────────────
const DEFAULT_NODE_FILTERS = {
  source: true, sink: true, sanitizer: true, normal: true,
};
const DEFAULT_EDGE_FILTERS = {
  call: true, cross_file_call: true, reaching_def_flow: true,
  dataflow: true, same_file_call: true, extends: true,
  implements: true, imports: true,
};
const NODE_TYPE_META = [
  { key:'source',    label:'Entry / Source', color:'#10B981' },
  { key:'sink',      label:'Sink',           color:'#EF4444' },
  { key:'sanitizer', label:'Guard',          color:'#8B5CF6' },
  { key:'normal',    label:'Method',         color:'#3B82F6' },
];
const EDGE_TYPE_META = [
  { key:'call',              label:'Calls',          color:'#3B82F6' },
  { key:'cross_file_call',   label:'Cross-file',     color:'#06B6D4' },
  { key:'reaching_def_flow', label:'Taint Flow',     color:'#8B5CF6' },
  { key:'extends',           label:'Extends',        color:'#F59E0B' },
  { key:'implements',        label:'Implements',     color:'#EC4899' },
  { key:'imports',           label:'Imports',        color:'#6B7280' },
];
const FOCUS_HOPS = [
  { label:'All', value:null }, { label:'1 hop', value:1 },
  { label:'2 hops', value:2 }, { label:'3 hops', value:3 },
  { label:'5 hops', value:5 },
];

export default function ExplorerPanel({ collapsed, onToggle }) {
  const [activeTab,     setActiveTab]     = useState('explorer');
  const [nodeFilters,   setNodeFilters]   = useState(DEFAULT_NODE_FILTERS);
  const [edgeFilters,   setEdgeFilters]   = useState(DEFAULT_EDGE_FILTERS);
  const [focusHops,     setFocusHops]     = useState(null);
  const [selectedFile,  setSelectedFile]  = useState(null);  // {name, fullPath}
  const [fileContent,   setFileContent]   = useState(null);  // {content, language}
  const [fileLoading,   setFileLoading]   = useState(false);
  const [showCode,      setShowCode]      = useState(false);

  const setNodeVisibility = useStore(s => s.setNodeVisibility);
  const setEdgeVisibility = useStore(s => s.setEdgeVisibility);
  const setFocusDepth     = useStore(s => s.setFocusDepth);
  const graph             = useStore(s => s.graph);
  const selectedNode      = useStore(s => s.selectedNode);
  const setSelectedNode   = useStore(s => s.setSelectedNode);

  // Build directory tree from graph nodes
  const dirTree = useMemo(() =>
    buildDirTree(graph?.nodes || []),
  [graph?.nodes]);

  // When a node is selected from graph, switch to its file
  useEffect(() => {
    if (selectedNode?.file && activeTab === 'explorer') {
      loadFile({ fullPath: selectedNode.file, name: selectedNode.file.split('/').pop() });
    }
  }, [selectedNode]);

  async function loadFile(fileNode) {
    if (!fileNode?.fullPath) return;
    setSelectedFile(fileNode.fullPath);
    setFileLoading(true);
    setShowCode(true);
    try {
      const res = await fetch(endpoints.fileSource(fileNode.fullPath));
      if (res.ok) {
        const data = await res.json();
        setFileContent(data);
      } else {
        setFileContent({ content: '// File not readable on server', language: 'txt' });
      }
    } catch {
      setFileContent({ content: '// Could not load file', language: 'txt' });
    } finally {
      setFileLoading(false);
    }
  }

  const toggleNode = (key) => {
    const next = { ...nodeFilters, [key]: !nodeFilters[key] };
    setNodeFilters(next);
    setNodeVisibility(next);
  };
  const toggleEdge = (key) => {
    const next = { ...edgeFilters, [key]: !edgeFilters[key] };
    setEdgeFilters(next);
    setEdgeVisibility(next);
  };
  const handleFocusHop = (val) => {
    setFocusHops(val);
    setFocusDepth(val);
  };

  const nodes = graph?.nodes || [];
  const nodeCounts = NODE_TYPE_META.reduce((acc, m) => {
    acc[m.key] = nodes.filter(n =>
      String(n.type||'').toLowerCase() === m.key).length;
    return acc;
  }, {});

  const highlightLine = selectedNode?.file === selectedFile
    ? selectedNode.line : null;

  // ── Styles ─────────────────────────────────────────────────────────────────
  const W = collapsed ? 0 : (showCode ? 480 : 220);
  const S = {
    outer: {
      width: W, minWidth: W, height:'100%', display:'flex',
      flexDirection:'column', overflow:'hidden', flexShrink:0,
      borderRight:'1px solid #21262D', background:'#0D1117',
      transition:'width 0.2s ease, min-width 0.2s ease',
      position:'relative',
    },
    collapseBtn: {
      position:'absolute', right:-14, top:'50%',
      transform:'translateY(-50%)', zIndex:200,
      background:'#21262D', border:'1px solid #30363D',
      borderRadius:4, color:'#8B949E', cursor:'pointer',
      padding:'3px 5px', fontSize:11,
    },
    tabs: {
      display:'flex', borderBottom:'1px solid #21262D', flexShrink:0,
    },
    tab: (a) => ({
      flex:1, padding:'9px 0', textAlign:'center', fontSize:11,
      fontWeight: a ? 600 : 400,
      color: a ? '#E6EDF3' : '#6E7681', cursor:'pointer',
      background:'none', border:'none',
      borderBottom: a ? '2px solid #58A6FF' : '2px solid transparent',
    }),
    body: { flex:1, overflowY:'auto', minWidth:0 },
    treePane: { width:220, flexShrink:0, borderRight:'1px solid #21262D',
                 overflowY:'auto', height:'100%' },
    codePane: { flex:1, overflowY:'auto', height:'100%',
                 background:'#0D1117', minWidth:0 },
    splitRow: { display:'flex', flex:1, overflow:'hidden', minHeight:0 },
    secTitle: { fontSize:10, fontWeight:600, color:'#6E7681',
                 textTransform:'uppercase', letterSpacing:'0.08em',
                 margin:'12px 10px 6px' },
    filterRow: (a) => ({
      display:'flex', alignItems:'center', gap:8,
      padding:'5px 10px', cursor:'pointer',
      background: a ? 'rgba(88,166,255,0.06)' : 'transparent',
    }),
    dot: (c) => ({ width:8, height:8, borderRadius:'50%', background:c, flexShrink:0 }),
    dash: (c, a) => ({ width:18, height:3, background: a ? c : '#374151',
                        borderRadius:2, flexShrink:0, opacity: a ? 1 : 0.4 }),
    lbl: (a) => ({ fontSize:12, color: a ? '#E6EDF3' : '#6E7681', flex:1 }),
    tog: (a) => ({ width:10, height:10, borderRadius:'50%',
                   background: a ? '#58A6FF' : '#30363D', flexShrink:0 }),
    hopRow: { display:'flex', flexWrap:'wrap', gap:4, padding:'0 10px 12px' },
    hopBtn: (a) => ({
      padding:'3px 10px', borderRadius:4, fontSize:11, cursor:'pointer',
      background: a ? '#1F6FEB' : '#21262D',
      color: a ? '#fff' : '#8B949E',
      border:'1px solid ' + (a ? '#1F6FEB' : '#30363D'),
    }),
  };

  return (
    <div style={S.outer}>
      <button style={S.collapseBtn} onClick={onToggle}>
        {collapsed ? '›' : '‹'}
      </button>

      {!collapsed && (
        <>
          {/* Tabs */}
          <div style={S.tabs}>
            <button style={S.tab(activeTab==='explorer')}
                    onClick={() => setActiveTab('explorer')}>Explorer</button>
            <button style={S.tab(activeTab==='filters')}
                    onClick={() => setActiveTab('filters')}>Filters</button>
          </div>

          {/* ── EXPLORER TAB ── */}
          {activeTab === 'explorer' && (
            <div style={S.splitRow}>
              {/* Dir tree */}
              <div style={S.treePane}>
                <div style={S.secTitle}>
                  Project files ({nodes.length} nodes)
                </div>
                {dirTree.childArr?.length === 0 && (
                  <div style={{ fontSize:11, color:'#4B5563', padding:'8px 12px' }}>
                    Scan a project to see its file structure.
                  </div>
                )}
                {dirTree.childArr?.map(child => (
                  <TreeNode key={child.path} node={child} depth={0}
                            onFileClick={loadFile}
                            selectedFile={selectedFile} />
                ))}
              </div>

              {/* Code viewer */}
              {showCode && (
                <div style={S.codePane}>
                  {/* Code pane header */}
                  <div style={{
                    padding:'6px 10px', borderBottom:'1px solid #21262D',
                    display:'flex', alignItems:'center', gap:8,
                    flexShrink:0,
                  }}>
                    <span style={{ fontSize:11, color:'#8B949E',
                                   flex:1, overflow:'hidden',
                                   textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {selectedFile?.split('/').pop() || ''}
                    </span>
                    {fileContent?.line_count && (
                      <span style={{ fontSize:10, color:'#4B5563' }}>
                        {fileContent.line_count} lines
                      </span>
                    )}
                    <button onClick={() => setShowCode(false)}
                            style={{ background:'none', border:'none',
                                     color:'#6E7681', cursor:'pointer',
                                     fontSize:14, padding:'0 2px' }}>×</button>
                  </div>
                  {fileLoading ? (
                    <div style={{ padding:16, color:'#4B5563', fontSize:12 }}>
                      Loading…
                    </div>
                  ) : (
                    <CodeViewer
                      content={fileContent?.content}
                      language={fileContent?.language}
                      highlightLine={highlightLine}
                    />
                  )}
                </div>
              )}
            </div>
          )}

          {/* ── FILTERS TAB ── */}
          {activeTab === 'filters' && (
            <div style={S.body}>
              <div style={S.secTitle}>Node types</div>
              {NODE_TYPE_META.map(m => (
                <div key={m.key} style={S.filterRow(nodeFilters[m.key])}
                     onClick={() => toggleNode(m.key)}>
                  <div style={S.dot(nodeFilters[m.key] ? m.color : '#374151')} />
                  <span style={S.lbl(nodeFilters[m.key])}>{m.label}</span>
                  <span style={{ fontSize:10, color:'#4B5563', marginRight:6 }}>
                    {nodeCounts[m.key] || 0}
                  </span>
                  <div style={S.tog(nodeFilters[m.key])} />
                </div>
              ))}

              <div style={S.secTitle}>Edge types</div>
              {EDGE_TYPE_META.map(m => (
                <div key={m.key} style={S.filterRow(edgeFilters[m.key])}
                     onClick={() => toggleEdge(m.key)}>
                  <div style={S.dash(m.color, edgeFilters[m.key])} />
                  <span style={S.lbl(edgeFilters[m.key])}>{m.label}</span>
                  <div style={S.tog(edgeFilters[m.key])} />
                </div>
              ))}

              <div style={S.secTitle}>Focus depth</div>
              <div style={S.hopRow}>
                {FOCUS_HOPS.map(h => (
                  <button key={h.label}
                          style={S.hopBtn(focusHops === h.value)}
                          onClick={() => handleFocusHop(h.value)}>
                    {h.label}
                  </button>
                ))}
              </div>

              <div style={S.secTitle}>Color legend</div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr',
                             gap:6, padding:'0 10px 12px' }}>
                {NODE_TYPE_META.map(m => (
                  <div key={m.key}
                       style={{ display:'flex', alignItems:'center',
                                gap:5, fontSize:11, color:'#8B949E' }}>
                    <div style={S.dot(m.color)} />
                    {m.label}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
