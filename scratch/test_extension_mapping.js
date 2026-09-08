// test_extension_mapping.js
const http = require('http');
const path = require('path');

function normalizeHostPath(filePath) {
  if (!filePath) return '';
  let p = String(filePath).replace(/\\/g, '/').trim();
  const m = p.match(/^(\/host|\/mnt)\/([a-zA-Z])\/(.*)$/);
  if (m) {
    return `${m[2].toUpperCase()}:/${m[3]}`;
  }
  return p;
}

function isSameFile(file1, file2) {
  if (!file1 || !file2) return false;
  const n1 = normalizeHostPath(file1).toLowerCase();
  const n2 = normalizeHostPath(file2).toLowerCase();
  if (n1 === n2) return true;

  const clean1 = n1.replace(/^[a-z]:\//, '/').replace(/^\/+/, '');
  const clean2 = n2.replace(/^[a-z]:\//, '/').replace(/^\/+/, '');
  if (clean1 === clean2) return true;
  if (clean1.endsWith('/' + clean2) || clean2.endsWith('/' + clean1)) return true;

  const segs1 = n1.split('/').filter(Boolean);
  const segs2 = n2.split('/').filter(Boolean);
  if (segs1.length > 0 && segs2.length > 0) {
    const b1 = segs1[segs1.length - 1];
    const b2 = segs2[segs2.length - 1];
    if (b1 !== b2) return false;
    if (segs1.length >= 2 && segs2.length >= 2) {
      return segs1[segs1.length - 2] === segs2[segs2.length - 2];
    }
    return true;
  }
  return false;
}

async function test() {
  console.log('--- 1. Testing isSameFile ---');
  const docFile = 'c:\\Users\\KRYPTON\\Documents\\Projects\\MajorProject\\Final\\Lethal-Company\\demo_project\\app.py';
  const dockerFile = '/host/c/Users/KRYPTON/Documents/Projects/MajorProject/Final/Lethal-Company/demo_project/app.py';
  const relFile = 'demo_project/app.py';
  const otherFile = 'c:\\Users\\KRYPTON\\Documents\\Projects\\MajorProject\\Demorep\\other\\app.py';

  console.log('docFile vs dockerFile:', isSameFile(docFile, dockerFile)); // expected true
  console.log('docFile vs relFile:', isSameFile(docFile, relFile));       // expected true
  console.log('docFile vs otherFile:', isSameFile(docFile, otherFile));   // expected false
  if (!isSameFile(docFile, dockerFile) || !isSameFile(docFile, relFile) || isSameFile(docFile, otherFile)) {
    throw new Error('isSameFile validation failed!');
  }

  console.log('\n--- 2. Fetching /api/graph from backend ---');
  const graphResp = await fetch('http://localhost:8001/api/graph');
  const graphData = await graphResp.json();
  const nodes = graphData.nodes || [];
  console.log('Total nodes from backend:', nodes.length);

  const docNodes = nodes.filter(n => isSameFile(docFile, n.file));
  console.log('Nodes matching demo_project/app.py:', docNodes.length);

  const ranges = { source: [], sink: [], sanitizer: [], critical_sink: [], new_path: [] };
  const showGuards = true;

  for (const node of docNodes) {
    const rawLine = typeof node.line === 'number' ? node.line : parseInt(node.line, 10);
    const lineNo = rawLine > 0 ? rawLine - 1 : 0;
    const ntype = String(node.type || '').toLowerCase();
    const isSource = (ntype === 'source' || ntype === 'entry');
    const isSink = (ntype === 'sink');
    const isGuard = (ntype === 'sanitizer' || ntype === 'guard');
    const isCritical = isSink && ((node.residual_risk != null && node.residual_risk > 0.7) || String(node.risk).toUpperCase() === 'CRITICAL');

    const entry = { line: rawLine, lineNo, id: node.id, label: node.label, type: node.type, cwe: node.cwe };
    if (isCritical) ranges.critical_sink.push(entry);
    else if (isSink) ranges.sink.push(entry);
    else if (isSource) ranges.source.push(entry);
    else if (isGuard && showGuards) ranges.sanitizer.push(entry);
  }

  console.log('\n--- 3. Decoration Ranges for demo_project/app.py ---');
  console.log('ENTRY / SOURCE (Green):', ranges.source.length);
  ranges.source.forEach(s => console.log(`  ● Line ${s.line} (0-idx ${s.lineNo}): ${s.label || s.id}`));
  console.log('SINK / CRITICAL SINK (Red):', ranges.sink.length + ranges.critical_sink.length);
  [...ranges.sink, ...ranges.critical_sink].forEach(s => console.log(`  ● Line ${s.line} (0-idx ${s.lineNo}): [${s.cwe || 'SINK'}] ${s.label || s.id}`));
  console.log('GUARD / SANITIZER (Purple):', ranges.sanitizer.length);
  ranges.sanitizer.forEach(g => console.log(`  ● Line ${g.line} (0-idx ${g.lineNo}): ${g.label || g.id}`));

  if (ranges.source.length === 0 || (ranges.sink.length + ranges.critical_sink.length) === 0 || ranges.sanitizer.length === 0) {
    throw new Error('Decorations failed: Missing sources, sinks, or guards!');
  }

  console.log('\n=== ALL DECORATION & LINE MAPPINGS VERIFIED SUCCESSFULLY! ===');
}

test().catch(err => {
  console.error('TEST ERROR:', err);
  process.exit(1);
});
