/* NetGuard UI: plain JavaScript, no build step.
 * This file only renders the JSON produced by the C binary (via the Flask
 * API). It contains no compiler or analysis logic. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const state = {
  result: null,          // last compile JSON
  compiledSource: "",
  compiledSyntax: "fw",
  tab: "nfa",
  minMode: "action",
  zoom: 1,
  viz: null,
};

/* ------------------------------------------------------------ navigation */
function showSection(name) {
  if (!document.getElementById("sec-" + name)) name = "editor";
  $$(".section").forEach((s) => s.classList.toggle("active", s.id === "sec-" + name));
  $$("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.sec === name));
  if (name === "automata") renderGraph();
}
window.addEventListener("hashchange", () => showSection(location.hash.slice(1)));

/* ------------------------------------------------------------ theme */
$("#themeBtn").addEventListener("click", () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  root.dataset.theme = dark ? "light" : "dark";
  try { localStorage.setItem("ng-theme", root.dataset.theme); } catch (e) { /* storage unavailable */ }
});
try { const t = localStorage.getItem("ng-theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }

/* ------------------------------------------------------------ API */
/* Served by Flask: same origin.  Opened directly as a file: talk to the local
 * server (default http://127.0.0.1:5000, override with ?api=http://host:port). */
const API_BASE = (() => {
  const q = new URLSearchParams(location.search).get("api");
  if (q) return q.replace(/\/$/, "");
  return location.protocol === "file:" ? "http://127.0.0.1:5000" : "";
})();

async function api(path, body) {
  path = API_BASE + path;
  const opts = body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {};
  let res;
  try {
    res = await fetch(path, opts);
  } catch (e) {
    return { ok: false, error: "Cannot reach the NetGuard server at " + (API_BASE || location.origin) +
      ". Start it with:  make && python web/app.py  and open http://127.0.0.1:5000 (" + e.message + ")" };
  }
  try {
    return await res.json();
  } catch (e) {
    return { ok: false, error: "Server returned HTTP " + res.status };
  }
}

/* ------------------------------------------------------------ editor */
const src = $("#source");
const gutter = $("#gutter");

function updateGutter() {
  const n = src.value.split("\n").length;
  const marks = {};
  if (state.result && src.value === state.compiledSource) {
    for (const d of state.result.diagnostics || []) {
      if (marks[d.line] !== "err") marks[d.line] = d.level === "error" ? "err" : "warn";
    }
  }
  let html = "";
  for (let i = 1; i <= n; i++) html += marks[i] ? `<span class="${marks[i]}">${i}</span>\n` : i + "\n";
  gutter.innerHTML = html;
  gutter.scrollTop = src.scrollTop;
}
src.addEventListener("input", updateGutter);
src.addEventListener("scroll", () => { gutter.scrollTop = src.scrollTop; });
src.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); compile(); }
  if (e.key === "Tab") {
    e.preventDefault();
    const s = src.selectionStart;
    src.setRangeText("    ", s, src.selectionEnd, "end");
    updateGutter();
  }
});

function jumpTo(line, col) {
  location.hash = "#editor";
  const lines = src.value.split("\n");
  let pos = 0;
  for (let i = 0; i < line - 1 && i < lines.length; i++) pos += lines[i].length + 1;
  const end = pos + (lines[line - 1] || "").length;
  src.focus();
  src.setSelectionRange(pos + Math.max(0, (col || 1) - 1), end);
  src.scrollTop = Math.max(0, (line - 4) * 20);
}

let examples = [];
async function loadExamples() {
  const r = await api("/api/examples");
  if (!r.ok) return;
  examples = r.examples;
  const sel = $("#exampleSel");
  const groups = [["Demo", (n) => !/^(classbench_|uci_)/.test(n)], ["ClassBench (real-firewall seeds)", (n) => n.startsWith("classbench_")],
                  ["UCI (real traffic)", (n) => n.startsWith("uci_")]];
  for (const [label, test] of groups) {
    const items = examples.filter((ex) => test(ex.name));
    if (!items.length) continue;
    const og = document.createElement("optgroup");
    og.label = label;
    for (const ex of items) {
      const o = document.createElement("option");
      o.value = ex.name;
      o.textContent = ex.name;
      og.appendChild(o);
    }
    sel.appendChild(og);
  }
  const first = examples.find((e) => e.name === "firewall_anomalies.fw") || examples[0];
  if (first) { setExample(first); sel.value = first.name; compile(); }
}
const DATASET_NOTES = {
  classbench_: "ClassBench filter set (Taylor & Turner, IEEE INFOCOM 2005): rule geometry generated from seeds of real firewalls (fw), ACLs (acl) and IP chains (ipc). ClassBench rules have no actions, so ALLOW/DENY were assigned by tools/import_classbench.py with a fixed seed (7, P(DENY)=0.3).",
  uci_: "Policy induced from the UCI \"Internet Firewall Data\" log (65,532 real firewall records) by tools/import_uci.py: one rule per destination port seen at least 20 times, action = that port's majority logged action.",
};
function setExample(ex) {
  const key = Object.keys(DATASET_NOTES).find((k) => ex.name.startsWith(k));
  $("#datasetNote").hidden = !key;
  $("#datasetNote").textContent = key ? DATASET_NOTES[key] : "";
  src.value = ex.source;
  $("#syntaxSel").value = ex.syntax;
  updateGutter();
}
$("#exampleSel").addEventListener("change", (e) => {
  const ex = examples.find((x) => x.name === e.target.value);
  if (ex) { setExample(ex); compile(); }
});
$("#compileBtn").addEventListener("click", compile);

/* ------------------------------------------------------------ compile */
async function compile() {
  const btn = $("#compileBtn");
  btn.disabled = true;
  btn.textContent = "Compiling...";
  const syntax = $("#syntaxSel").value;
  const source = src.value;
  const r = await api("/api/compile", { source, syntax });
  btn.disabled = false;
  btn.textContent = "Compile";
  if (r.error && !r.diagnostics) {
    state.result = null;
    $("#statusPill").className = "pill err";
    $("#statusPill").textContent = "Server error";
    $("#diagnostics").innerHTML = `<div class="error-box">${esc(r.error)}</div>`;
    return;
  }
  state.result = r;
  state.compiledSource = source;
  state.compiledSyntax = syntax;
  state.zoom = 1;
  renderAll();
}

function renderAll() {
  const r = state.result;
  const pill = $("#statusPill");
  const nerr = r.diagnostics.filter((d) => d.level === "error").length;
  const nwarn = r.diagnostics.length - nerr;
  pill.className = "pill " + (r.ok ? "ok" : "err");
  pill.textContent = r.ok ? (nwarn ? `Compiled · ${nwarn} warning${nwarn > 1 ? "s" : ""}` : "Compiled")
                          : `${nerr} error${nerr > 1 ? "s" : ""}`;
  renderStrip();
  updateGutter();
  renderDiagnostics();
  renderTokens();
  renderIR();
  renderPartitions();
  renderAutomataStats();
  renderGraph();
  renderAnalysis();
  renderPacketForm();
  renderOptimized();
  renderValidation();
}

function renderStrip() {
  const r = state.result;
  if (!r.ok || !r.nfa) {
    $("#pipelineStrip").innerHTML = "";
    $("#timing").textContent = "";
    return;
  }
  const steps = [
    ["Rules", r.policy.rules.length],
    ["Symbols", r.partition.alphabet],
    ["NFA", r.nfa.states],
    ["DFA", r.dfa.states],
    ["Min", r.min_dfa_modes.action.states],
  ];
  $("#pipelineStrip").innerHTML = steps.map(([k, v]) => `<span class="step">${k} <b>${v}</b></span>`).join('<span class="arrow">→</span>') +
    (r.optimization ? `<span class="arrow">·</span><span class="step">Optimized <b>${r.optimization.original_rules} → ${r.optimization.optimized_rules}</b></span>` : "");
  $("#timing").textContent = `compiled in ${r.stats.phase_ms.total.toFixed(2)} ms (C, clock())`;
}

function renderDiagnostics() {
  const box = $("#diagnostics");
  const ds = state.result.diagnostics;
  if (!ds.length) { box.innerHTML = '<div class="empty">No errors or warnings.</div>'; return; }
  box.innerHTML = ds.map((d, i) => `
    <button class="diag ${d.level}" data-i="${i}" type="button">
      <span class="lvl">${esc(d.level)}</span>
      <span class="pos">${d.line}:${d.col} · ${esc(d.phase)}</span>
      <span>${esc(d.message)}</span>
      ${d.hint ? `<span class="hint">Hint: ${esc(d.hint)}</span>` : ""}
    </button>`).join("");
  box.querySelectorAll(".diag").forEach((el) => el.addEventListener("click", () => {
    const d = ds[+el.dataset.i];
    jumpTo(d.line, d.col);
  }));
}

/* ------------------------------------------------------------ tokens */
function renderTokens() {
  const hide = $("#hideNl").checked;
  const toks = state.result.tokens.filter((t) => !(hide && t.type === "NEWLINE"));
  $("#tokCount").textContent = `${state.result.tokens.length} tokens`;
  $("#tokens").innerHTML = `<table><thead><tr><th class="num">#</th><th class="num">Line</th><th class="num">Col</th><th>Type</th><th>Lexeme</th></tr></thead><tbody>${
    toks.map((t, i) => `<tr><td class="num muted">${i + 1}</td><td class="num">${t.line}</td><td class="num">${t.col}</td><td><span class="tok ${esc(t.type)}">${esc(t.type)}</span></td><td class="mono">${esc(t.lexeme)}</td></tr>`).join("")
  }</tbody></table>`;
}
$("#hideNl").addEventListener("change", () => state.result && renderTokens());

/* ------------------------------------------------------------ IR */
function renderIR() {
  const p = state.result.policy;
  $("#policyMeta").innerHTML = [
    `Policy <b>${esc(p.name)}</b>`, `Syntax <b>.${esc(p.syntax)}</b>`, `Rules <b>${p.rules.length}</b>`,
    `Actions <b>${p.actions.map(esc).join(", ")}</b>`, `Default <b>${esc(p.default)}</b>`,
    `Fields <b>${p.fields.map((f) => esc(f.name)).join(" · ")}</b>`,
  ].map((c) => `<span class="chip">${c}</span>`).join("");
  if (!p.rules.length) { $("#irTable").innerHTML = '<div class="empty">No valid rules.</div>'; return; }
  const head = p.fields.map((f) => `<th>${esc(f.name)}</th>`).join("");
  const rows = p.rules.map((r) => `<tr>
      <td><b>${esc(r.id)}</b><div class="int">line ${r.line}</div></td>
      <td><span class="badge act">${esc(r.action)}</span></td>
      ${r.cond.map((c) => `<td>${c.any ? '<span class="muted">ANY</span>' : (c.lo === c.hi ? esc(c.lo_text) : esc(c.lo_text) + " – " + esc(c.hi_text))}
         <div class="int">[${c.lo}, ${c.hi}]</div></td>`).join("")}
      <td class="mono small">${esc(r.text)}</td></tr>`).join("");
  $("#irTable").innerHTML = `<table><thead><tr><th>Rule</th><th>Action</th>${head}<th>Source</th></tr></thead><tbody>${rows}</tbody></table>`;
}

/* ------------------------------------------------------------ partitions */
const PALETTE = ["#c7d2fe", "#bbf7d0", "#fde68a", "#fbcfe8", "#a5f3fc", "#ddd6fe", "#fed7aa", "#d9f99d", "#bae6fd", "#fecdd3"];
function colorFor(rules) {
  if (!rules.length) return "#e5e7eb";
  let h = 0;
  for (const c of rules.join(",")) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return PALETTE[h % PALETTE.length];
}

function renderPartitions() {
  const r = state.result;
  const box = $("#partitions");
  if (!r.partition) { $("#cells").innerHTML = ""; box.innerHTML = '<div class="empty">Fix the errors and compile to see the partition.</div>'; return; }
  const pt = r.partition;
  $("#cells").innerHTML = pt.fields.map((f) => `<span class="chip">${esc(f.name)} <b>${f.nsyms}</b> symbols</span>`).join("") +
    `<span class="chip">Union alphabet <b>${pt.alphabet}</b></span><span class="chip">Cells (product) <b>${Number(pt.cells).toLocaleString()}</b></span>`;
  box.innerHTML = pt.fields.map((f, k) => {
    const isIp = r.policy.fields[k].is_ip;
    const segs = f.intervals.map((iv) => {
      const size = iv.hi - iv.lo + 1;
      const w = isIp ? Math.log2(size + 1) : size;
      const label = iv.lo === iv.hi ? iv.lo_text : iv.lo_text + "–" + iv.hi_text;
      return `<div class="seg-iv" style="flex-grow:${w};background:${colorFor(iv.rules_covering)}"
        data-tip="<b>${esc(f.name)} · symbol ${iv.sym}</b> (global ${iv.gsym})<br><code>${esc(label)}</code><br>${size.toLocaleString()} value(s)<br>covered by: ${iv.rules_covering.length ? esc(iv.rules_covering.join(", ")) : "no rule (DEFAULT)"}">
        ${f.intervals.length <= 12 ? esc(String(iv.sym)) : ""}</div>`;
    }).join("");
    const first = f.intervals[0], last = f.intervals[f.intervals.length - 1];
    const rows = f.intervals.map((iv) => `<tr><td class="num">${iv.sym}</td><td class="num muted">${iv.gsym}</td><td class="mono">${esc(iv.lo_text)}</td><td class="mono">${esc(iv.hi_text)}</td><td class="int">[${iv.lo}, ${iv.hi}]</td><td>${iv.rules_covering.length ? esc(iv.rules_covering.join(", ")) : '<span class="muted">none</span>'}</td></tr>`).join("");
    return `<div class="field-part">
      <h3>${esc(f.name)} <span class="muted small">${f.nsyms} intervals · ${isIp ? "log-scaled widths" : "proportional widths"}</span></h3>
      <div class="bar">${segs}</div>
      <div class="bar-scale"><span>${esc(first.lo_text)}</span><span>${esc(last.hi_text)}</span></div>
      <details><summary>Symbol table</summary>
        <div class="table-wrap" style="margin-top:8px"><table><thead><tr><th class="num">Sym</th><th class="num">Global</th><th>From</th><th>To</th><th>Integers</th><th>Rules covering</th></tr></thead><tbody>${rows}</tbody></table></div>
      </details></div>`;
  }).join("");
}

const tooltip = $("#tooltip");
document.addEventListener("mousemove", (e) => {
  const t = e.target.closest ? e.target.closest("[data-tip]") : null;
  if (!t) { tooltip.style.display = "none"; return; }
  tooltip.innerHTML = t.dataset.tip;
  tooltip.style.display = "block";
  const x = Math.min(e.clientX + 14, window.innerWidth - tooltip.offsetWidth - 8);
  tooltip.style.left = x + "px";
  tooltip.style.top = (e.clientY + 16) + "px";
});

/* ------------------------------------------------------------ automata */
function renderAutomataStats() {
  const r = state.result;
  if (!r.nfa) { $("#autoStats").innerHTML = ""; return; }
  const m = r.min_dfa_modes;
  const stats = [
    ["NFA states", r.nfa.states], ["ε-edges", r.nfa.eps_edges], ["symbol edges", r.nfa.sym_edges],
    ["DFA states", r.dfa.states], ["DFA final states", r.dfa.final_states],
    ["Min DFA (by action)", m.action.states], ["Min DFA (by rule)", m.rule.states],
  ];
  $("#autoStats").innerHTML = stats.map(([k, v]) => `<div class="stat"><div class="v">${v}</div><div class="k">${k}</div></div>`).join("");
}

async function getViz() {
  if (state.viz) return state.viz;
  if (typeof Viz === "undefined") throw new Error("Viz.js could not be loaded from jsDelivr (offline?). The DOT source is shown instead.");
  state.viz = await Viz.instance();
  return state.viz;
}

let graphToken = 0;
async function renderGraph() {
  const box = $("#graph");
  const note = $("#graphNote");
  const r = state.result;
  if (!$("#sec-automata").classList.contains("active")) return;
  if (!r || !r.nfa) { box.innerHTML = '<div class="empty">Compile a valid policy to see the automata.</div>'; note.textContent = ""; return; }
  const g = state.tab === "nfa" ? r.nfa : state.tab === "dfa" ? r.dfa : r.min_dfa_modes[state.minMode];
  $("#minMode").style.visibility = state.tab === "min" ? "visible" : "hidden";
  const descr = {
    nfa: `Thompson ε-NFA: ${r.nfa.states} states, ${r.nfa.eps_edges} ε-edges (dashed), ${r.nfa.sym_edges} symbol edges. Double circles accept a rule.`,
    dfa: `Subset construction: ${r.dfa.states} states including the SINK (not drawn). Final states show the decision and the winning rule (lowest index).`,
    min: state.minMode === "action"
      ? `Hopcroft, initial partition by action: ${g.states} states. This is the minimal classifier; it no longer knows which rule decided.`
      : `Hopcroft, initial partition by winning rule: ${g.states} states. Keeps rule identity for explanations.`,
  }[state.tab];
  note.textContent = descr;
  if (g.too_large) {
    box.innerHTML = `<div class="empty">This graph has more than 200 nodes, so the compiler did not export it (too_large). Use <code>netguard dot FILE --stage ${state.tab}</code> to get the full DOT.</div>`;
    return;
  }
  const token = ++graphToken;
  try {
    const viz = await getViz();
    if (token !== graphToken) return;
    const svg = viz.renderSVGElement(g.dot);
    svg.removeAttribute("width");
    svg.removeAttribute("height");
    const vb = svg.viewBox.baseVal;
    svg.style.width = (vb && vb.width ? vb.width * state.zoom : 800) + "px";
    if (state.zoom === 1) svg.style.maxWidth = "100%";   /* "fit": never wider than the panel */
    box.innerHTML = "";
    box.appendChild(svg);
  } catch (e) {
    box.innerHTML = `<div class="error-box">${esc(e.message)}</div><pre class="code">${esc(g.dot)}</pre>`;
  }
}
$$("#autoTabs .tab").forEach((b) => b.addEventListener("click", () => {
  state.tab = b.dataset.tab;
  $$("#autoTabs .tab").forEach((x) => x.classList.toggle("active", x === b));
  state.zoom = 1;
  renderGraph();
}));
$$("#minMode .tab").forEach((b) => b.addEventListener("click", () => {
  state.minMode = b.dataset.mode;
  $$("#minMode .tab").forEach((x) => x.classList.toggle("active", x === b));
  renderGraph();
}));
$("#zoomIn").addEventListener("click", () => { state.zoom *= 1.25; renderGraph(); });
$("#zoomOut").addEventListener("click", () => { state.zoom /= 1.25; renderGraph(); });
$("#zoomReset").addEventListener("click", () => { state.zoom = 1; renderGraph(); });

/* ------------------------------------------------------------ analysis */
function renderAnalysis() {
  const r = state.result;
  if (!r.analysis) {
    $("#counts").innerHTML = "";
    $("#ruleCards").innerHTML = '<div class="empty">Analysis runs once the policy compiles without errors.</div>';
    return;
  }
  const c = r.analysis.counts;
  $("#counts").innerHTML = [["ok", "ok"], ["shadowed", "shadowed"], ["partial", "partially overlapped"], ["redundant", "redundant"]]
    .map(([k, label]) => `<div class="stat ${k}"><div class="v">${c[k]}</div><div class="k">${label}</div></div>`).join("") +
    `<div class="stat"><div class="v">${c.conflicting}</div><div class="k">conflicting</div></div>` +
    `<div class="stat"><div class="v">${c.high_severity}</div><div class="k">high severity</div></div>`;
  renderRuleCards();
}

function renderRuleCards() {
  const r = state.result;
  const filter = $("#statusFilter").value;
  const texts = Object.fromEntries(r.policy.rules.map((x) => [x.id, x]));
  const list = r.analysis.rules.filter((a) => filter === "all" || a.status === filter);
  if (!list.length) { $("#ruleCards").innerHTML = '<div class="empty">No rules with this status.</div>'; return; }
  $("#ruleCards").innerHTML = list.map((a) => {
    const rule = texts[a.id];
    const rows = [];
    if (a.subtype) rows.push(["Subtype", esc(a.subtype)]);
    if (a.contained_by) rows.push(["Contained by", esc(a.contained_by)]);
    if (a.covered_by.length && a.status === "shadowed") rows.push(["Covered by", esc(a.covered_by.join(", "))]);
    if (a.beaten_by.length) rows.push(["Beaten by", esc(a.beaten_by.join(", "))]);
    if (a.decided_after_removal_by) rows.push(["Decided without it by", esc(a.decided_after_removal_by.join(", "))]);
    rows.push(["DFA final states", `${a.win_states} won · ${a.lose_states} lost`]);
    if (a.example) rows.push(["Example packet", `<span class="mono small">${esc(a.example.packet.text)}</span> → ${esc(a.example.decided_by)}`]);
    return `<article class="card">
      <div class="card-head"><span class="rid">${esc(a.id)}</span>
        <span class="badge ${a.status}">${esc(a.status)}</span>
        ${a.severity !== "none" ? `<span class="badge sev-${a.severity}">${esc(a.severity)}</span>` : ""}
        <span class="badge act">${esc(a.action)}</span>
        <a href="#" class="small" data-line="${rule.line}">line ${rule.line}</a></div>
      <div class="src">${esc(rule.text)}</div>
      <dl class="kv">${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl>
      <p>${esc(a.explanation)}</p></article>`;
  }).join("");
  $$("#ruleCards [data-line]").forEach((el) => el.addEventListener("click", (e) => { e.preventDefault(); jumpTo(+el.dataset.line, 1); }));
}
$("#statusFilter").addEventListener("change", () => state.result && state.result.analysis && renderRuleCards());

/* ------------------------------------------------------------ packet tester */
const FW_DEFAULTS = { proto: "TCP", src_ip: "10.1.2.3", dst_ip: "8.8.8.8", dst_port: "22" };

function renderPacketForm() {
  const r = state.result;
  const form = $("#pktForm");
  if (!r.ok || !r.nfa) {
    form.innerHTML = '<div class="muted">Compile a valid policy first.</div>';
    $("#pktResult").innerHTML = "";
    return;
  }
  const fields = r.policy.fields;
  const prev = {};
  form.querySelectorAll("[data-field]").forEach((el) => { prev[el.dataset.field] = el.value; });
  form.innerHTML = fields.map((f) => {
    const v = prev[f.name] ?? FW_DEFAULTS[f.name] ?? String(f.lo);
    if (f.name === "proto") {
      return `<label>${esc(f.name)}<select data-field="proto">${["TCP", "UDP", "ICMP", "0", "47", "255"].map((p) => `<option ${p === v ? "selected" : ""}>${p}</option>`).join("")}</select></label>`;
    }
    const hint = f.is_ip ? "dotted IPv4" : `${f.lo} .. ${f.hi}`;
    return `<label>${esc(f.name)}<input type="text" data-field="${esc(f.name)}" value="${esc(v)}" placeholder="${esc(hint)}"></label>`;
  }).join("") + '<button class="primary" type="submit">Classify</button>';
}

$("#pktForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const parts = $$("#pktForm [data-field]").map((el) => `${el.dataset.field}=${el.value.trim()}`);
  const out = $("#pktResult");
  out.innerHTML = '<div class="muted">Classifying...</div>';
  const r = await api("/api/classify", { source: state.compiledSource, syntax: state.compiledSyntax, packet: parts.join(" ") });
  if (!r.ok) { out.innerHTML = `<div class="error-box">${esc(r.error || "Classification failed")}</div>`; return; }
  const cls = /^allow$/i.test(r.decision) ? "allow" : /^deny$/i.test(r.decision) ? "deny" : "other";
  out.innerHTML = `
    <div class="decision">
      <div class="big ${cls}">${esc(r.decision)}</div>
      <div><div>Decided by <b>${esc(r.decided_by)}</b>${r.winner_text ? ` <span class="mono small muted">${esc(r.winner_text)}</span>` : " (no rule matched)"}</div>
        <div class="small muted">${esc(r.packet.text)}</div></div>
      <span class="check ${r.oracle_agrees ? "good" : "bad"}">Oracle: ${esc(r.oracle.decision)} by ${esc(r.oracle.decided_by)} ${r.oracle_agrees ? "✓ agrees" : "✗ DISAGREES"}</span>
    </div>
    <div class="diff tester">
      <div class="panel"><h3>Matched rules</h3>
        <p class="small">All matching rules: <b>${r.matched.length ? esc(r.matched.join(", ")) : "none"}</b>${r.other_matched.length ? `<br>Also matched but lower priority: <b>${esc(r.other_matched.join(", "))}</b>` : ""}</p>
        <h3 style="margin-top:12px">Why earlier rules did not match</h3>
        ${r.failures.length ? `<ul class="fail-list">${r.failures.map((f) => `<li>${esc(f.text)}</li>`).join("")}</ul>` : '<p class="small muted">No earlier rules: the first rule decided.</p>'}
      </div>
      <div class="panel"><h3>Symbol trace</h3>
        <div class="table-wrap"><table><thead><tr><th>Field</th><th>Value</th><th class="num">Sym</th><th>Interval</th><th>Min-DFA</th><th>DFA</th></tr></thead><tbody>
        ${r.trace.map((t) => `<tr><td>${esc(t.field)}</td><td class="mono">${esc(t.value_text)}</td><td class="num">${t.sym}<div class="int">g${t.gsym}</div></td><td class="mono small">${esc(t.interval)}</td><td class="mono">M${t.from} → M${t.to}</td><td class="mono">D${t.dfa_from} → D${t.dfa_to}</td></tr>`).join("")}
        </tbody></table></div></div>
    </div>`;
});

/* ------------------------------------------------------------ optimized */
function renderOptimized() {
  $("#aiBox").innerHTML = "";
  $("#aiModePill").innerHTML = "";
  const r = state.result;
  const o = r.optimization;
  if (!o) {
    $("#optSummary").innerHTML = "";
    $("#origList").innerHTML = '<div class="empty">Not available until the policy compiles.</div>';
    $("#optSource").textContent = "";
    $("#removalLog").innerHTML = "";
    return;
  }
  const reasons = Object.fromEntries(o.removed.map((x) => [x.id, x]));
  $("#optSummary").innerHTML = `<span class="chip">Original <b>${o.original_rules}</b> rules</span><span class="chip">Optimized <b>${o.optimized_rules}</b> rules</span>
    <span class="chip">Removed <b>${o.removed.length}</b></span><span class="chip">Equivalent <b>${r.equivalence.equivalent ? "yes ✓" : "NO"}</b></span>`;
  $("#origList").innerHTML = r.policy.rules.map((rule) => {
    const rm = reasons[rule.id];
    return `<div class="orig-rule ${rm ? "removed" : "kept"}"><b>${esc(rule.id)}</b><span class="t">${esc(rule.text)}</span>
      ${rm ? `<span class="why">step ${rm.step}: ${esc(rm.phase)}</span>` : ""}</div>`;
  }).join("") + `<div class="orig-rule kept"><b></b><span class="t">DEFAULT ${esc(r.policy.default)}</span></div>`;
  $("#optSource").textContent = o.optimized_source;
  $("#removalLog").innerHTML = o.removed.length
    ? o.removed.map((x) => `<li><b>${esc(x.id)}</b> <span class="badge ${x.phase === "shadowed" ? "shadowed" : "redundant"} phase">${esc(x.phase)}</span><div class="small">${esc(x.reason)}</div></li>`).join("")
    : '<li class="muted">Nothing to remove: every rule is needed.</li>';
}
$("#downloadBtn").addEventListener("click", () => {
  const o = state.result && state.result.optimization;
  if (!o) return;
  const blob = new Blob([o.optimized_source], { type: "text/plain" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = (state.result.policy.name || "policy") + "_optimized." + state.compiledSyntax;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

/* ------------------------------------------------------------ validation */
function renderValidation() {
  const r = state.result;
  const box = $("#equivBox");
  $("#verifyBox").innerHTML = "";
  if (!r.equivalence) { box.innerHTML = '<div class="empty">Not available until the policy compiles.</div>'; return; }
  const e = r.equivalence;
  const cx = e.counterexample;
  box.innerHTML = `<div class="result-box ${e.equivalent ? "good" : "bad"}">
    <div class="headline">${e.equivalent ? "✓ Optimized policy is EQUIVALENT to the original" : "✗ NOT equivalent"}</div>
    <div class="small muted">${esc(e.method)} · ${e.product_pairs_explored} product state pairs explored · ${r.optimization.original_rules} → ${r.optimization.optimized_rules} rules</div>
    ${cx ? `<p>Counterexample: <span class="mono">${esc(cx.packet.text)}</span><br>original → <b>${esc(cx.original_action)}</b>, optimized → <b>${esc(cx.optimized_action)}</b> (oracle: ${esc(cx.oracle_original)} / ${esc(cx.oracle_optimized)})</p>` : ""}
  </div>`;
}

$("#verifyBtn").addEventListener("click", async () => {
  const out = $("#verifyBox");
  if (!state.result || !state.result.ok) { out.innerHTML = '<div class="error-box">Compile a valid policy first.</div>'; return; }
  const btn = $("#verifyBtn");
  btn.disabled = true;
  out.innerHTML = '<div class="muted" style="margin-top:10px">Running...</div>';
  const r = await api("/api/verify", { source: state.compiledSource, syntax: state.compiledSyntax, n: +$("#verifyN").value, seed: +$("#verifySeed").value });
  btn.disabled = false;
  if (!r.ok) { out.innerHTML = `<div class="error-box">${esc(r.error || "verification failed")}</div>`; return; }
  const meters = [
    ["Minimized DFA vs oracle", r.min_dfa_vs_oracle],
    ["Unminimized DFA (decision + winner) vs oracle", r.dfa_vs_oracle],
    ["Optimized policy vs original (oracle)", r.optimized_vs_original],
    ["Optimized min-DFA vs original oracle", r.optimized_min_dfa_vs_original],
  ];
  out.innerHTML = `<div class="result-box ${r.all_agree ? "good" : "bad"}" style="margin-top:10px">
    <div class="headline">${r.all_agree ? `✓ All ${r.n.toLocaleString()} random packets agreed` : "✗ Disagreements found"}</div>
    <div class="small muted">seed ${r.seed} · packets biased toward rule boundaries ±1 · ${r.original_rules} original / ${r.optimized_rules} optimized rules</div>
    <div class="bars">${meters.map(([k, m]) => `<div class="meter"><span>${k}</span><div class="track"><div class="fill" style="width:${(100 * m.agree) / r.n}%"></div></div><span class="n">${m.agree.toLocaleString()} / ${r.n.toLocaleString()}</span></div>`).join("")}</div>
    ${r.mismatches.length ? `<ul class="fail-list">${r.mismatches.map((m) => `<li>${esc(m.packet.text)}: oracle ${esc(m.oracle)}, min-DFA ${esc(m.min_dfa)}</li>`).join("")}</ul>` : ""}
  </div>`;
});

/* ------------------------------------------------------------ boot */
showSection(location.hash.slice(1) || "editor");
updateGutter();
/* ------------------------------------------------------------ AI merge */
function lineDiff(a, b) {
  /* Mark lines of b that do not appear in a (and vice versa); display only. */
  const la = a.trimEnd().split("\n"), lb = b.trimEnd().split("\n");
  const norm = (x) => x.replace(/#.*/, "").replace(/\s+/g, " ").trim();
  const sa = new Set(la.map(norm)), sb = new Set(lb.map(norm));
  const side = (lines, other, cls) => lines.map((l) => `<div class="dl ${!norm(l) || other.has(norm(l)) ? "" : cls}">${esc(l) || "&nbsp;"}</div>`).join("");
  return [side(la, sb, "del"), side(lb, sa, "add")];
}

function renderAttempt(a) {
  let body;
  if (!a.parsed) {
    body = `<div class="small">Does not parse:</div><ul class="fail-list">${a.diagnostics.filter((d) => d.level === "error")
      .map((d) => `<li>${d.line}:${d.col} ${esc(d.message)}</li>`).join("")}</ul>`;
  } else if (a.equivalent) {
    body = `<div class="small">Proven equivalent to the ORIGINAL policy by the product automaton (${a.product_pairs_explored} state pairs explored) · ${a.rules} rules</div>`;
  } else if (a.counterexample) {
    const cx = a.counterexample;
    body = `<div class="small">Counterexample packet: <span class="mono">${esc(cx.text)}</span></div>
      <div class="small">original → <b>${esc(a.action_original)}</b> (${esc(cx.decided_by_original)}) · AI policy → <b>${esc(a.action_suggested)}</b> (${esc(cx.decided_by_suggested)})</div>`;
  } else {
    body = `<div class="small">${esc(a.error || "not comparable")}</div>`;
  }
  const ok = a.parsed && a.equivalent;
  return `<li class="attempt ${ok ? "good" : "bad"}"><div class="att-head">Attempt ${a.attempt} ${ok ? "✅ EQUIVALENT" : a.parsed ? "❌ NOT EQUIVALENT" : "❌ DOES NOT PARSE"}</div>${body}
    <details><summary>AI policy text</summary><pre class="code">${esc(a.text)}</pre></details></li>`;
}

$("#aiBtn").addEventListener("click", async () => {
  const box = $("#aiBox");
  if (!state.result || !state.result.ok) { box.innerHTML = '<div class="error-box">Compile a valid policy first.</div>'; return; }
  const btn = $("#aiBtn");
  btn.disabled = true;
  btn.textContent = "Asking Gemini and proving...";
  $("#aiModePill").innerHTML = "";
  const r = await api("/api/ai-merge", { source: state.compiledSource, syntax: state.compiledSyntax, replay: $("#aiReplay").checked });
  btn.disabled = false;
  btn.textContent = "AI merge (Gemini)";
  if (r.mode) {
    $("#aiModePill").innerHTML = r.mode === "live"
      ? `<span class="pill ok">LIVE GEMINI · ${esc(r.model)}</span>`
      : r.cache && r.cache.real
        ? `<span class="pill ok">RECORDED GEMINI REPLY</span> <span class="muted tiny">${esc(r.fallback_reason || "")}</span>`
        : `<span class="pill warnp">DEMO CACHE</span> <span class="muted tiny">${esc(r.fallback_reason || "")}</span>`;
  }
  if (!r.ok) { box.innerHTML = `<div class="error-box">${esc(r.error || "AI merge failed")}</div>`; return; }
  const finalAttempt = r.attempts[r.attempts.length - 1];
  const [left, right] = lineDiff(r.optimizer_text, r.ai_text || "");
  box.innerHTML = `
    ${r.mode === "demo" ? `<div class="note"><b>${r.cache.real ? "Recorded Gemini reply (replayed; re-proven live by NetGuard just now)" : "DEMO (cached AI response)"}</b> · ${esc(r.cache.provenance)}</div>` : ""}
    ${r.warning ? `<div class="error-box">${esc(r.warning)}</div>` : ""}
    <div class="stat-row">
      <div class="stat"><div class="v">${r.rules_before}</div><div class="k">Original rules</div></div>
      <div class="stat"><div class="v">${r.rules_after_optimizer}</div><div class="k">After NetGuard optimizer</div></div>
      <div class="stat ${r.accepted ? "ok" : ""}"><div class="v">${r.rules_after_ai ?? "—"}</div><div class="k">AI proposal (proven)</div></div>
    </div>
    <div class="result-box ${r.accepted ? "good" : "bad"}"><div class="headline">${r.accepted ? "✅ AI policy accepted" : "Optimizer policy kept"}</div><div class="small">${esc(r.verdict)}</div></div>
    <h3 style="margin-top:14px">Attempts</h3>
    <ol class="timeline">${r.attempts.map(renderAttempt).join("")}</ol>
    ${finalAttempt && finalAttempt.parsed ? `<div class="diff" style="margin-top:12px">
      <div class="panel"><h3>Optimizer (${r.rules_after_optimizer} rules)</h3><div class="code dlines">${left}</div></div>
      <div class="panel"><h3>AI, last attempt (${finalAttempt.rules} rules)
        ${r.accepted ? '<button id="useAiBtn" class="ghost small" type="button">Use AI policy</button>' : ""}</h3><div class="code dlines">${right}</div></div>
    </div>` : ""}`;
  const use = $("#useAiBtn");
  if (use) use.addEventListener("click", () => {
    src.value = r.final_text;
    $("#syntaxSel").value = state.compiledSyntax;
    $("#exampleSel").value = "";
    $("#datasetNote").hidden = true;
    location.hash = "#editor";
    compile();
  });
});

loadExamples();
