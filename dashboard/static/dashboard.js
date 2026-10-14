/* RL C2-Evasion Dashboard — Plotly visualizations.
 *
 * Talks to /api/normalized/<report> which returns a canonical structure:
 *   { name, family, meta, n_flows, n_mechs, mechanisms[], cells[],
 *     framing[], framing_by_mech[], oracle{}, actions[], warnings[] }
 */
const API = '/api';
let currentData = null;

const DARK = {
  paper_bgcolor: '#1E293B',
  plot_bgcolor: '#1E293B',
  font: { color: '#F8FAFC', size: 11 },
};
const CAT_COLOR = {
  strong: '#38BDF8',
  weak: '#A78BFA',
  no_effect: '#64748B',
  breaks_semantics: '#F97316',
};
const RESPONSIVE = { responsive: true, displayModeBar: false };

// --------------------------------------------------------------------------
// Boot
// --------------------------------------------------------------------------
async function init() {
  try {
    const reports = await fetch(`${API}/reports`).then(r => r.json());
    const select = document.getElementById('reportSelect');

    // Prioritize P17 reports, then newest -> oldest.
    reports.sort((a, b) => {
      const pa = a.name.startsWith('p17') ? 0 : 1;
      const pb = b.name.startsWith('p17') ? 0 : 1;
      if (pa !== pb) return pa - pb;
      return b.name.localeCompare(a.name);
    });

    reports.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.name;
      opt.textContent = `${r.name}  [${r.family}]`;
      select.appendChild(opt);
    });

    select.addEventListener('change', loadReport);
    document.getElementById('framingFilter').addEventListener('change', renderCharts);
    document.getElementById('mechFilter').addEventListener('change', renderCharts);

    if (reports.length > 0) {
      select.value = reports[0].name;
      await loadReport();
    } else {
      showError('No reports found in snort_validation/reports/.');
    }
  } catch (e) {
    showError(`Failed to load report list: ${e}`);
  }
}

async function loadReport() {
  const name = document.getElementById('reportSelect').value;
  try {
    const resp = await fetch(`${API}/normalized/${encodeURIComponent(name)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    currentData = await resp.json();
    hideError();
    buildMechFilter(currentData);
    renderMeta(currentData);
    renderCharts();
  } catch (e) {
    currentData = null;
    showError(`Failed to load report "${name}": ${e}`);
  }
}

// --------------------------------------------------------------------------
// Filtering
// --------------------------------------------------------------------------
function framingMatches(framing) {
  const sel = document.getElementById('framingFilter').value;
  if (sel === 'all' || !framing) return true;
  const f = String(framing).toLowerCase();
  const isC2 = f.includes('http') || f.includes('c2') || f.includes('neris');
  const isDht = f.includes('dht') || f.includes('p2p') || f.includes('dns') ||
                f.includes('udp') || f.includes('irc') || f.includes('bot');
  if (sel === 'c2') return isC2;
  if (sel === 'dht') return isDht;
  return true;
}

function mechMatches(mech) {
  const sel = document.getElementById('mechFilter').value;
  return sel === 'all' || mech === sel;
}

function buildMechFilter(data) {
  const sel = document.getElementById('mechFilter');
  sel.innerHTML = '<option value="all">All mechanisms</option>';
  const mechs = [...new Set((data.mechanisms || []).map(m => m.mech))].sort();
  mechs.forEach(m => {
    const opt = document.createElement('option');
    opt.value = m;
    opt.textContent = m;
    sel.appendChild(opt);
  });
}

function filteredCells(data) {
  return (data.cells || []).filter(c => framingMatches(c.framing) && mechMatches(c.mech));
}

function filteredMechanisms(data) {
  let mechs = (data.mechanisms || []).slice();
  if (document.getElementById('mechFilter').value !== 'all') {
    mechs = mechs.filter(m => m.mech === document.getElementById('mechFilter').value);
  }
  // When a framing filter is active and per-framing data exists, rescale the
  // bar using framing_by_mech so the numbers reflect the selected framing.
  const sel = document.getElementById('framingFilter').value;
  if (sel !== 'all' && (data.framing_by_mech || []).length) {
    const key = sel === 'c2' ? 'c2_http' : 'p2p_dht';
    const totalByFraming = {};
    data.framing_by_mech.forEach(r => { totalByFraming[r.mech] = r[key] || 0; });
    mechs = mechs.map(m => {
      const ev = totalByFraming[m.mech] || 0;
      const denom = (data.framing || []).filter(f => framingMatches(f.label))
        .reduce((s, f) => s + f.count, 0) || m.total;
      const rate = denom ? ev / denom : 0;
      return { ...m, evaded: ev, rate: rate,
               category: rate >= 0.5 ? 'strong' : rate > 0 ? 'weak' : 'no_effect' };
    });
  }
  return mechs;
}

// --------------------------------------------------------------------------
// Render orchestration
// --------------------------------------------------------------------------
function renderCharts() {
  if (!currentData) return;
  renderMechBar(currentData);
  renderHeatmap(currentData);
  renderFramingPie(currentData);
  renderOracleBar(currentData);
  renderFramingByMech(currentData);
  renderActions(currentData);
  renderBars(currentData);
}

function renderMeta(data) {
  const bar = document.getElementById('metaBar');
  const bits = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') bits.push(`<span>${k}: <b>${v}</b></span>`); };
  add('report', data.name);
  add('family', data.family);
  Object.entries(data.meta || {}).forEach(([k, v]) => add(k, v));
  add('n_flows', data.n_flows);
  add('n_mechs', data.n_mechs);
  bar.innerHTML = bits.join('');
  if ((data.warnings || []).length) {
    bar.innerHTML += `<span style="color:#F97316">&#9888; ${data.warnings.join('; ')}</span>`;
  }
}

// --------------------------------------------------------------------------
// Charts
// --------------------------------------------------------------------------
function renderMechBar(data) {
  const mechs = filteredMechanisms(data).sort((a, b) => b.rate - a.rate);
  const el = 'mechBar';
  if (!mechs.length) return emptyChart(el, 'No mechanism data for this report / filter.');

  const trace = {
    x: mechs.map(d => d.mech),
    y: mechs.map(d => +(d.rate * 100).toFixed(2)),
    type: 'bar',
    text: mechs.map(d => `${d.evaded}/${d.total}`),
    textposition: 'outside',
    marker: { color: mechs.map(d => CAT_COLOR[d.category] || '#38BDF8') },
    customdata: mechs.map(d => [d.evaded, d.caught, d.invalid, d.category]),
    hovertemplate: '%{x}<br>evasion %{y:.1f}%<br>evaded %{customdata[0]} / caught %{customdata[1]}' +
                   '<br>invalid %{customdata[2]}<br>%{customdata[3]}<extra></extra>',
  };
  const layout = Object.assign({}, DARK, {
    xaxis: { tickangle: -45, automargin: true },
    yaxis: { title: 'Evasion Rate (%)', range: [0, 108] },
    margin: { l: 50, r: 20, t: 20, b: 120 },
    bargap: 0.25,
  });
  Plotly.newPlot(el, [trace], layout, RESPONSIVE);
}

function renderHeatmap(data) {
  const el = 'heatmap';
  const note = document.getElementById('heatmapNote');
  const cells = filteredCells(data).filter(c => c.mech !== undefined && c.mech !== null);
  if (!cells.length) {
    note.textContent = 'No per-flow cell data in this report (sweep summary only).';
    return emptyChart(el, 'No cell matrix available.');
  }

  // Build a STABLE UNIQUE key per distinct flow. Short labels can collide
  // (many flows share e.g. '20110810-neris:53/udp'), so we key on flow_key
  // (the full flow_id from the backend) and disambiguate duplicate labels.
  const rawKey = c => {
    if (c.flow_key) return `k_${c.flow_key}`;
    if (c.flow_idx !== undefined && c.flow_idx !== null) return `idx_${c.flow_idx}`;
    return `id_${c.flow_id}`;
  };
  const keyToIdx = {};
  const keyToLabel = {};
  let next = 0;
  cells.forEach(c => {
    const k = rawKey(c);
    if (!(k in keyToIdx)) {
      keyToIdx[k] = next;
      const base = c.flow_id || `flow_${next}`;
      keyToLabel[k] = base;
      next++;
    }
  });
  // Detect duplicate labels and suffix them so the axis stays readable.
  const labelCounts = {};
  Object.values(keyToLabel).forEach(l => { labelCounts[l] = (labelCounts[l] || 0) + 1; });
  const seen = {};
  const flows = [];  // ordered list of {key, label}
  Object.keys(keyToIdx).forEach(k => {
    const base = keyToLabel[k];
    let label = base;
    if (labelCounts[base] > 1) {
      seen[base] = (seen[base] || 0) + 1;
      label = `${base} #${seen[base]}`;
    }
    flows.push({ key: k, label });
  });
  flows.sort((a, b) => a.label.localeCompare(b.label, undefined, { numeric: true }));

  const mechs = [...new Set(cells.map(c => c.mech))].sort();
  const lookup = {};
  cells.forEach(c => { lookup[`${c.mech}|${rawKey(c)}`] = c; });

  const z = mechs.map(m => flows.map(f => {
    const c = lookup[`${m}|${f.key}`];
    if (!c || c.evaded === null || c.evaded === undefined) return null;
    return c.evaded ? 1 : 0;
  }));

  const trace = {
    z, x: flows.map(f => f.label), y: mechs, type: 'heatmap', zmin: 0, zmax: 1,
    colorscale: [[0, '#0F172A'], [0.5, '#1E3A5F'], [1, '#38BDF8']],
    showscale: false, hoverongaps: false,
    hovertemplate: '%{y} &middot; %{x}<br>%{z}<extra></extra>',
  };
  const layout = Object.assign({}, DARK, {
    xaxis: { title: 'Flow', tickangle: -45, automargin: true, tickfont: { size: 9 } },
    yaxis: { title: 'Mechanism', automargin: true, tickfont: { size: 9 } },
    margin: { l: 130, r: 20, t: 20, b: 90 },
  });
  const nEv = cells.filter(c => c.evaded).length;
  note.textContent = `${mechs.length} mechanisms × ${flows.length} flows · 1 = evaded, 0 = caught, blank = n/a · ${nEv} evasions`;
  Plotly.newPlot(el, [trace], layout, RESPONSIVE);
}

function renderFramingPie(data) {
  const el = 'framingPie';
  let framing = (data.framing || []).filter(f => framingMatches(f.label));
  if (!framing.length) {
    // fall back to framing_by_mech column totals is misleading; instead hide.
    return emptyChart(el, 'No framing breakdown in this report.');
  }
  const trace = {
    labels: framing.map(f => f.label),
    values: framing.map(f => f.count),
    type: 'pie',
    textinfo: 'label+percent',
    marker: { colors: ['#38BDF8', '#F97316', '#A78BFA', '#22C55E', '#EAB308'] },
    hole: 0.35,
  };
  const layout = Object.assign({}, DARK, {
    showlegend: true, margin: { l: 20, r: 20, t: 20, b: 20 },
  });
  Plotly.newPlot(el, [trace], layout, RESPONSIVE);
}

function renderOracleBar(data) {
  const el = 'oracleBar';
  const o = data.oracle || {};
  const oraclePct = o.oracle_rate !== undefined ? o.oracle_rate * 100
    : (o.oracle_pct !== undefined ? o.oracle_pct : null);
  const bestPct = o.best_single_rate !== undefined ? o.best_single_rate * 100 : null;

  if (oraclePct === null && bestPct === null) {
    return emptyChart(el, 'No oracle / best-single metrics in this report.');
  }
  const xs = [], ys = [], colors = [], texts = [];
  if (oraclePct !== null) { xs.push('Oracle'); ys.push(+oraclePct.toFixed(2)); colors.push('#F97316'); texts.push(`${o.oracle_flows ?? ''}/${data.n_flows ?? ''}`); }
  if (bestPct !== null) {
    xs.push(`Best single${o.best_single_mech ? ' (' + o.best_single_mech + ')' : ''}`);
    ys.push(+bestPct.toFixed(2)); colors.push('#38BDF8');
    texts.push(`${o.best_single ?? ''}/${data.n_flows ?? ''}`);
  }
  const trace = {
    x: xs, y: ys, type: 'bar', text: texts, textposition: 'outside',
    marker: { color: colors },
    hovertemplate: '%{x}<br>%{y:.1f}%<extra></extra>',
  };
  const layout = Object.assign({}, DARK, {
    yaxis: { title: 'Evasion Rate (%)', range: [0, 108] },
    margin: { l: 50, r: 20, t: 20, b: 60 },
  });
  Plotly.newPlot(el, [trace], layout, RESPONSIVE);
}

function renderFramingByMech(data) {
  const card = document.getElementById('framingByMechCard');
  const fbm = data.framing_by_mech || [];
  if (!fbm.length) { card.style.display = 'none'; return; }
  card.style.display = 'block';
  const sel = document.getElementById('framingFilter').value;
  const traces = [];
  if (sel === 'all' || sel === 'c2') {
    traces.push({
      x: fbm.map(r => r.mech), y: fbm.map(r => r.c2_http), name: 'C2-HTTP',
      type: 'bar', marker: { color: '#38BDF8' },
    });
  }
  if (sel === 'all' || sel === 'dht') {
    traces.push({
      x: fbm.map(r => r.mech), y: fbm.map(r => r.p2p_dht), name: 'DHT P2P',
      type: 'bar', marker: { color: '#F97316' },
    });
  }
  const layout = Object.assign({}, DARK, {
    barmode: 'group', xaxis: { tickangle: -45, automargin: true },
    yaxis: { title: 'Flows evaded' }, legend: { orientation: 'h' },
    margin: { l: 50, r: 20, t: 20, b: 120 },
  });
  Plotly.newPlot('framingByMech', traces, layout, RESPONSIVE);
}

function renderActions(data) {
  const card = document.getElementById('actionsCard');
  const acts = (data.actions || []).filter(a => mechMatches(a.action));
  if (!acts.length) { card.style.display = 'none'; return; }
  card.style.display = 'block';

  // Choose a metric that exists across the action rows.
  const metric = ['mean_reward', 'rewards_semantics_ok', 'applies', 'unmasked', 'selectable', 'cost']
    .find(k => acts.some(a => typeof a[k] === 'number'));
  const label = { mean_reward: 'mean reward', rewards_semantics_ok: 'semantics-ok rewards',
                  applies: 'applies', unmasked: 'unmasked', selectable: 'selectable', cost: 'cost' }[metric];

  const trace = {
    x: acts.map(a => a.action), y: acts.map(a => a[metric]), type: 'bar',
    marker: { color: acts.map(a => (a.verdict === 'dead_zero' || a.breaks_semantics > 0) ? '#F97316' : '#38BDF8') },
    hovertemplate: `%{x}<br>${label} %{y}<extra></extra>`,
  };
  const layout = Object.assign({}, DARK, {
    xaxis: { tickangle: -45, automargin: true },
    yaxis: { title: label }, margin: { l: 50, r: 20, t: 20, b: 120 },
  });
  document.getElementById('actionsNote').textContent = `metric: ${label}`;
  Plotly.newPlot('actionsBar', [trace], layout, RESPONSIVE);
}

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------
function renderBars(data) {
  const card = document.getElementById('barsCard');
  const bars = (data.bars || []).filter(b => b && b.value !== null && b.value !== undefined);
  if (!bars.length) { card.style.display = 'none'; return; }
  card.style.display = 'block';
  const trace = {
    x: bars.map(b => b.label),
    y: bars.map(b => b.value),
    type: 'bar',
    text: bars.map(b => (b.evaded !== undefined && b.detected !== undefined)
      ? `${b.evaded} ev / ${b.detected} det` : ''),
    textposition: 'outside',
    marker: { color: '#38BDF8' },
    customdata: bars.map(b => [b.evaded, b.detected]),
    hovertemplate: '%{x}<br>value %{y}<extra></extra>',
  };
  const layout = Object.assign({}, DARK, {
    xaxis: { tickangle: -30, automargin: true },
    yaxis: { automargin: true },
    margin: { l: 50, r: 20, t: 20, b: 90 },
  });
  Plotly.newPlot('barsChart', [trace], layout, RESPONSIVE);
}

function emptyChart(el, msg) {
  Plotly.newPlot(el, [], Object.assign({}, DARK, {
    xaxis: { visible: false }, yaxis: { visible: false },
    margin: { l: 20, r: 20, t: 20, b: 20 },
    annotations: [{ text: msg, showarrow: false, font: { color: '#94A3B8', size: 12 },
                   xref: 'paper', yref: 'paper', x: 0.5, y: 0.5 }],
  }), RESPONSIVE);
}

function showError(msg) {
  const el = document.getElementById('error');
  el.textContent = msg;
  el.style.display = 'block';
}
function hideError() {
  document.getElementById('error').style.display = 'none';
}

init();
