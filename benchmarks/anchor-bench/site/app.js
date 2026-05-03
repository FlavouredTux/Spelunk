const data = window.ANCHOR_BENCH_DATA;
const entries = [...data.entries].sort((a, b) => b.utility - a.utility);

const pct = (v) => `${(v * 100).toFixed(1)}%`;
const money = (v) => v == null ? "-" : `$${v.toFixed(4)}`;
const seconds = (v) => v == null ? "-" : `${v.toFixed(1)}s`;
const fmtCount = (v) => Number.isInteger(v) ? String(v) : v.toFixed(1);

function initSummary() {
  document.getElementById("best-model").textContent = entries[0]?.model ?? "-";
  document.getElementById("best-utility").textContent = entries[0] ? pct(entries[0].utility) : "-";
  document.getElementById("best-accuracy").textContent = entries[0] ? pct(entries[0].accuracy) : "-";
  document.getElementById("total-hallucinations").textContent = String(entries.reduce((s, e) => s + e.hallucinated, 0));
  document.getElementById("model-count").textContent = String(entries.length);
  document.getElementById("target-count").textContent = String(Math.max(...entries.map((e) => e.targets), 0));
  document.getElementById("bench-name").textContent = data.benchmark.replace("anchor-bench.", "");
  document.getElementById("data-note").textContent = data.note;
  document.getElementById("generated-at").textContent = new Date(data.generated_at).toLocaleString();
}

function renderTable() {
  const body = document.getElementById("leaderboard-body");
  body.innerHTML = "";
  entries.forEach((e, i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${i + 1}</td>
      <td class="model-cell">${e.model}<br><span class="muted">${e.provider ?? ""}</span></td>
      <td>${e.mode}</td>
      <td>${pct(e.accuracy)}${e.trials > 1 ? ` ± ${pct(e.accuracy_stddev ?? 0)}` : ""}</td>
      <td>${pct(e.name_accuracy ?? e.accuracy)}${e.trials > 1 ? ` ± ${pct(e.name_accuracy_stddev ?? 0)}` : ""}</td>
      <td class="${e.utility >= 0 ? "score-pos" : "score-neg"}">${pct(e.utility)}${e.trials > 1 ? ` ± ${pct(e.utility_stddev ?? 0)}` : ""}</td>
      <td>${fmtCount(e.correct)}</td>
      <td>${fmtCount(e.wrong)}</td>
      <td>${fmtCount(e.hallucinated)}</td>
      <td>${money(e.cost_usd)}</td>
      <td>${seconds(e.latency_s)}</td>
    `;
    body.appendChild(tr);
  });
}

function renderSpendAccuracyChart() {
  const root = document.getElementById("spend-accuracy-chart");
  root.innerHTML = "";
  const width = 920;
  const height = 330;
  const pad = { left: 64, right: 210, top: 28, bottom: 54 };
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const maxCost = Math.max(0.001, ...entries.map((e) => e.cost_usd ?? 0));
  const costMax = maxCost * 1.18;
  const x = (v) => pad.left + ((v ?? 0) / costMax) * plotW;
  const y = (v) => pad.top + (1 - Math.max(0, Math.min(1, v))) * plotH;
  const costTicks = [0, costMax / 2, costMax];
  const accTicks = [0, 0.25, 0.5, 0.75, 1];

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "scatter-svg");
  svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Money on the x-axis, accuracy on the y-axis");

  const add = (tag, attrs, text) => {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    if (text != null) el.textContent = text;
    svg.appendChild(el);
    return el;
  };

  accTicks.forEach((t) => {
    const yy = y(t);
    add("line", { class: "scatter-grid", x1: pad.left, y1: yy, x2: pad.left + plotW, y2: yy });
    add("text", { class: "scatter-tick", x: pad.left - 12, y: yy + 4, "text-anchor": "end" }, pct(t));
  });
  costTicks.forEach((t) => {
    const xx = x(t);
    add("line", { class: "scatter-grid", x1: xx, y1: pad.top, x2: xx, y2: pad.top + plotH });
    add("text", { class: "scatter-tick", x: xx, y: pad.top + plotH + 22, "text-anchor": "middle" }, money(t));
  });

  add("line", { class: "scatter-axis", x1: pad.left, y1: pad.top, x2: pad.left, y2: pad.top + plotH });
  add("line", { class: "scatter-axis", x1: pad.left, y1: pad.top + plotH, x2: pad.left + plotW, y2: pad.top + plotH });
  add("text", { class: "scatter-title", x: 12, y: pad.top + 12, transform: `rotate(-90 12 ${pad.top + 12})` }, "accuracy");
  add("text", { class: "scatter-title", x: pad.left + plotW, y: height - 12, "text-anchor": "end" }, "money spent");

  entries.forEach((e, i) => {
    const px = x(e.cost_usd ?? 0);
    const py = y(e.accuracy);
    const labelX = pad.left + plotW + 24;
    const labelY = pad.top + 28 + i * 42;
    const colorClass = e.utility >= 0 ? "good" : "bad";
    add("line", {
      class: "scatter-grid",
      x1: px,
      y1: py,
      x2: labelX - 10,
      y2: labelY - 4,
      "stroke-dasharray": "2 4",
    });
    add("circle", { class: `scatter-point ${colorClass}`, cx: px, cy: py, r: 7, "stroke-width": 1.2 });
    add("text", { class: "scatter-model", x: labelX, y: labelY }, e.model);
    const trialText = e.trials ? ` / n=${e.trials}` : "";
    add("text", { class: "scatter-meta", x: labelX, y: labelY + 16 }, `${pct(e.accuracy)} pass / ${money(e.cost_usd ?? 0)} / ${pct(e.utility)} util${trialText}`);
  });

  root.appendChild(svg);
}

function renderBands() {
  const bands = document.getElementById("bands");
  bands.innerHTML = "";
  data.hard_preview.forEach((b) => {
    const div = document.createElement("div");
    div.className = "band";
    div.innerHTML = `
      <strong>${b.band}</strong>
      <p>${b.target_mix}</p>
      <span>x${b.weight}</span>
    `;
    bands.appendChild(div);
  });
}

function setupCanvas(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(Number(canvas.getAttribute("height")) * ratio));
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  return { ctx, width: rect.width, height: Number(canvas.getAttribute("height")) };
}

function drawOutcomeChart() {
  const canvas = document.getElementById("outcome-chart");
  const { ctx, width, height } = setupCanvas(canvas);
  ctx.clearRect(0, 0, width, height);
  const totals = entries.reduce((acc, e) => {
    acc.correct += e.correct;
    acc.wrong += e.wrong;
    acc.missing += e.missing;
    acc.hallucinated += e.hallucinated;
    return acc;
  }, { correct: 0, wrong: 0, missing: 0, hallucinated: 0 });
  const parts = [
    ["Correct", totals.correct, "#788c5d"],
    ["Wrong", totals.wrong, "#c75d3a"],
    ["Missing", totals.missing, "#b89a3a"],
    ["Halluc.", totals.hallucinated, "#6a9bcc"]
  ];
  const total = Math.max(1, parts.reduce((s, p) => s + p[1], 0));
  let start = -Math.PI / 2;
  const cx = width / 2;
  const cy = height / 2 - 10;
  const r = Math.min(width, height) * 0.28;
  parts.forEach(([label, value, color]) => {
    const end = start + (value / total) * Math.PI * 2;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, start, end);
    ctx.closePath();
    ctx.fillStyle = color;
    ctx.fill();
    start = end;
  });
  ctx.fillStyle = "#ede9df";
  ctx.font = "700 18px 'JetBrains Mono', monospace";
  ctx.textAlign = "center";
  ctx.fillText(`${total}`, cx, cy + 5);
  ctx.font = "12px 'JetBrains Mono', monospace";
  ctx.fillStyle = "#87867f";
  ctx.fillText("outcomes", cx, cy + 24);

  ctx.textAlign = "left";
  parts.forEach(([label, value, color], i) => {
    const x = 18 + (i % 2) * (width / 2);
    const y = height - 52 + Math.floor(i / 2) * 24;
    ctx.fillStyle = color;
    ctx.fillRect(x, y - 10, 12, 12);
    ctx.fillStyle = "#87867f";
    ctx.font = "12px 'JetBrains Mono', monospace";
    ctx.fillText(`${label}: ${value}`, x + 18, y);
  });
}

function render() {
  initSummary();
  renderTable();
  renderSpendAccuracyChart();
  renderBands();
  drawOutcomeChart();
}

window.addEventListener("resize", () => {
  drawOutcomeChart();
});

render();
