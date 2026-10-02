#!/usr/bin/env node
// Graph topology analyzer for guided tour design.
const fs = require('fs');

const inPath = process.argv[2];
const outPath = process.argv[3];
if (!inPath || !outPath) {
  console.error('usage: node ua-tour-analyze.js <input.json> <output.json>');
  process.exit(1);
}

let data;
try {
  data = JSON.parse(fs.readFileSync(inPath, 'utf8'));
} catch (e) {
  console.error('failed to read input: ' + e.message);
  process.exit(1);
}

const nodes = data.nodes || [];
const edges = data.edges || [];
const layers = data.layers || [];

const byId = new Map();
for (const n of nodes) byId.set(n.id, n);

const fanIn = new Map();
const fanOut = new Map();
for (const n of nodes) { fanIn.set(n.id, 0); fanOut.set(n.id, 0); }
for (const e of edges) {
  if (fanOut.has(e.source)) fanOut.set(e.source, fanOut.get(e.source) + 1);
  if (fanIn.has(e.target)) fanIn.set(e.target, fanIn.get(e.target) + 1);
}

function nameOf(id) { const n = byId.get(id); return n ? n.name : id; }
function summaryOf(id) { const n = byId.get(id); return n ? (n.summary || '') : ''; }

// A. Fan-in ranking
const fanInRanking = [...fanIn.entries()]
  .map(([id, v]) => ({ id, fanIn: v, name: nameOf(id) }))
  .sort((a, b) => b.fanIn - a.fanIn || a.id.localeCompare(b.id))
  .slice(0, 20);

// B. Fan-out ranking
const fanOutRanking = [...fanOut.entries()]
  .map(([id, v]) => ({ id, fanOut: v, name: nameOf(id) }))
  .sort((a, b) => b.fanOut - a.fanOut || a.id.localeCompare(b.id))
  .slice(0, 20);

// C. Entry point candidates
const CODE_NAMES = new Set(['index.ts','index.js','main.ts','main.js','app.ts','app.js','server.ts','server.js','mod.rs','main.go','main.py','main.rs','manage.py','app.py','wsgi.py','asgi.py','run.py','__main__.py','Application.java','Main.java','Program.cs','config.ru','index.php','App.swift','Application.kt','main.cpp','main.c']);
const fanOutVals = [...fanOut.values()].sort((a,b)=>b-a);
const p90 = fanOutVals.length ? fanOutVals[Math.max(0, Math.floor(fanOutVals.length*0.1)-1)] : 0;
const fanInVals = [...fanIn.values()].sort((a,b)=>a-b);
const p25 = fanInVals.length ? fanInVals[Math.max(0, Math.floor(fanInVals.length*0.25)-1)] : 0;

const entryCandidates = [];
for (const n of nodes) {
  let score = 0;
  const fp = n.filePath || '';
  const depth = fp.split('/').length;
  if (n.type === 'document') {
    if (n.name === 'README.md' && depth === 1) score += 5;
    else if (n.name.endsWith('.md') && depth === 1) score += 2;
  } else if (n.type === 'file' || n.type === 'config' || n.type === 'service') {
    if (CODE_NAMES.has(n.name)) score += 3;
    if (depth <= 2) score += 1;
    if (fanOut.get(n.id) >= p90 && p90 > 0) score += 1;
    if (fanIn.get(n.id) <= p25) score += 1;
  }
  if (score > 0) entryCandidates.push({ id: n.id, score, name: n.name, summary: n.summary || '' });
}
entryCandidates.sort((a,b)=> b.score - a.score || a.id.localeCompare(b.id));
const topEntry = entryCandidates.slice(0, 5);

// D. BFS from top code entry point (skip documents)
const FORWARD = new Set(['imports','calls','depends_on','configures']);
const hasRealFwd = (id) => edges.some(e => e.source === id && FORWARD.has(e.type) && byId.has(e.target));
const realFwdCount = (id) => edges.filter(e => e.source === id && FORWARD.has(e.type) && byId.has(e.target)).length;
// prefer code FILE candidates with real dependency edges, ranked by fan-in (centrality)
let bfsStart = null;
const fileCandidates = topEntry.filter(c => { const n = byId.get(c.id); return n && n.type === 'file'; });
const withFwd = fileCandidates.filter(c => hasRealFwd(c.id));
if (withFwd.length) {
  withFwd.sort((a,b) => (fanIn.get(b.id)||0) - (fanIn.get(a.id)||0));
  bfsStart = withFwd[0].id;
} else {
  const fileFwd = nodes.filter(n => n.type === 'file' && hasRealFwd(n.id))
    .map(n => ({ id: n.id, fo: realFwdCount(n.id), fi: fanIn.get(n.id)||0 }))
    .sort((a,b) => b.fo - a.fo || b.fi - a.fi);
  bfsStart = fileFwd.length ? fileFwd[0].id : null;
}
let bfs = { startNode: null, order: [], depthMap: {}, byDepth: {} };
if (bfsStart) {
  const adj = new Map();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) {
    if (FORWARD.has(e.type) && adj.has(e.source)) {
      adj.get(e.source).push(e.target);
    }
  }
  const start = bfsStart;
  const depthMap = {}; depthMap[start] = 0;
  const order = [start];
  const queue = [start];
  while (queue.length) {
    const cur = queue.shift();
    for (const nxt of (adj.get(cur) || [])) {
      if (!(nxt in depthMap) && byId.has(nxt)) {
        depthMap[nxt] = depthMap[cur] + 1;
        order.push(nxt);
        queue.push(nxt);
      }
    }
  }
  const byDepth = {};
  for (const id of order) {
    const d = String(depthMap[id]);
    (byDepth[d] = byDepth[d] || []).push(id);
  }
  bfs = { startNode: start, order, depthMap, byDepth };
}

// E. Non-code file inventory
const nonCodeFiles = { documentation: [], infrastructure: [], data: [], config: [] };
for (const n of nodes) {
  const rec = { id: n.id, name: n.name, type: n.type, summary: n.summary || '' };
  if (n.type === 'document') nonCodeFiles.documentation.push(rec);
  else if (['service','pipeline','resource'].includes(n.type)) nonCodeFiles.infrastructure.push(rec);
  else if (['table','schema','endpoint'].includes(n.type)) nonCodeFiles.data.push(rec);
  else if (n.type === 'config') nonCodeFiles.config.push(rec);
}

// F. Tightly coupled clusters (bidirectional pairs + expansion)
const edgeSet = new Set(edges.map(e => e.source + '\u0000' + e.target));
const pairs = [];
for (const e of edges) {
  if (edgeSet.has(e.target + '\u0000' + e.source) && e.source < e.target) {
    pairs.push([e.source, e.target]);
  }
}
const seen = new Set();
const clusters = [];
for (const [a, b] of pairs) {
  const key = [a, b].sort().join('|');
  if (seen.has(key)) continue;
  seen.add(key);
  const cluster = new Set([a, b]);
  // expand: nodes connecting to 2+ members
  let changed = true;
  while (changed) {
    changed = false;
    for (const n of nodes) {
      if (cluster.has(n.id)) continue;
      let conn = 0;
      for (const m of cluster) {
        if (edgeSet.has(n.id + '\u0000' + m) || edgeSet.has(m + '\u0000' + n.id)) conn++;
      }
      if (conn >= 2 && cluster.size < 5) { cluster.add(n.id); changed = true; }
    }
  }
  clusters.push([...cluster]);
}
// dedupe overlapping clusters, keep distinct
const finalClusters = [];
const usedKeys = new Set();
for (const c of clusters) {
  const k = c.slice().sort().join('|');
  if (usedKeys.has(k)) continue;
  usedKeys.add(k);
  let edgeCount = 0;
  for (const x of c) for (const y of c) if (x !== y && edgeSet.has(x + '\u0000' + y)) edgeCount++;
  finalClusters.push({ nodes: c, edgeCount });
}
finalClusters.sort((a, b) => b.edgeCount - a.edgeCount);
const topClusters = finalClusters.slice(0, 10);

// H. Node summary index
const nodeSummaryIndex = {};
for (const n of nodes) nodeSummaryIndex[n.id] = { name: n.name, type: n.type, summary: n.summary || '' };

const out = {
  scriptCompleted: true,
  entryPointCandidates: topEntry,
  fanInRanking,
  fanOutRanking,
  bfsTraversal: bfs,
  nonCodeFiles,
  clusters: topClusters,
  layers: { count: layers.length, list: layers },
  nodeSummaryIndex,
  totalNodes: nodes.length,
  totalEdges: edges.length
};

fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
console.log('wrote ' + outPath);
process.exit(0);
