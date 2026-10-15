const state = { rules: [], tables: [], chains: [] };

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function addCell(row, value, className = "") {
  const cell = document.createElement("td");
  cell.textContent = value ?? "—";
  if (className) cell.className = className;
  row.append(cell);
  return cell;
}

function setEmptyRow(id, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.className = "empty-cell";
  cell.textContent = message;
  row.append(cell);
  document.getElementById(id).replaceChildren(row);
}

function renderRules() {
  const preview = document.createDocumentFragment();
  for (const rule of state.rules) {
    const row = document.createElement("tr");
    addCell(row, rule.family, "code-cell");
    addCell(row, rule.table, "code-cell");
    addCell(row, rule.chain, "code-cell");
    addCell(row, rule.handle, "code-cell");
    const expression = addCell(row, JSON.stringify(rule.expr ?? []), "expression-cell");
    expression.title = expression.textContent;
    preview.append(row.cloneNode(true));
  }
  if (!state.rules.length) {
    setEmptyRow("overview-rules", "No rules in the active ruleset.");
    return;
  }
  document.getElementById("overview-rules").replaceChildren(preview);
}

function renderBreakdown(id, breakdown) {
  const list = document.getElementById(id);
  const rows = Object.entries(breakdown ?? {}).sort((left, right) => right[1] - left[1]);
  if (!rows.length) {
    const empty = document.createElement("span");
    empty.className = "statistics-empty";
    empty.textContent = "No data";
    list.replaceChildren(empty);
    return;
  }

  const content = document.createDocumentFragment();
  for (const [label, count] of rows) {
    const row = document.createElement("div");
    row.className = "statistics-row";
    const name = document.createElement("span");
    name.textContent = label;
    const value = document.createElement("strong");
    value.textContent = String(count);
    row.append(name, value);
    content.append(row);
  }
  list.replaceChildren(content);
}

function renderStatistics(statistics) {
  setText("rule-count", String(statistics.total_rules));
  setText("table-count", String(statistics.total_tables));
  setText("chain-count", String(statistics.total_chains));
  renderBreakdown("family-stats", statistics.rules_by_family);
  renderBreakdown("protocol-stats", statistics.rules_by_protocol);
  renderBreakdown("verdict-stats", statistics.rules_by_verdict);
}

function formatBytes(bytes) {
  if (bytes == null) return "Unavailable";
  let value = bytes;
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function renderSystemStatistics(statistics) {
  const loads = statistics.load_average ?? [];
  setText("system-hostname", statistics.hostname || "Unknown host");
  setText("cpu-load", loads.length
    ? loads.map((load) => load == null ? "—" : Number(load).toFixed(2)).join(" / ")
    : "Unavailable");
  setText("cpu-cores", `${statistics.cpu_cores ?? "—"} online cores`);
  for (const resource of ["memory", "disk"]) {
    const percent = statistics[`${resource}_usage_percent`];
    const used = statistics[`${resource}_used_bytes`];
    const total = statistics[`${resource}_total_bytes`];
    setText(`${resource}-percent`, percent == null ? "Unavailable" : `${Number(percent).toFixed(1)}%`);
    setText(`${resource}-detail`, `${formatBytes(used)} used of ${formatBytes(total)}`);
    document.getElementById(`${resource}-progress`).value = percent == null ? 0 : Math.max(0, Math.min(100, percent));
  }
}

function showError(message) {
  state.rules = [];
  state.tables = [];
  state.chains = [];
  setText("api-status", "API UNAVAILABLE");
  document.getElementById("gateway-tag").classList.remove("connected");
  setText("rule-count", "—");
  setText("table-count", "—");
  setText("chain-count", "—");
  renderBreakdown("family-stats", {});
  renderBreakdown("protocol-stats", {});
  renderBreakdown("verdict-stats", {});
  renderSystemStatistics({});
  setEmptyRow("overview-rules", message);
  const notice = document.getElementById("notice");
  notice.textContent = message;
  notice.hidden = false;
}

async function refresh() {
  const button = document.getElementById("refresh-button");
  const notice = document.getElementById("notice");
  button.disabled = true;
  button.textContent = "Refreshing…";
  notice.hidden = true;
  try {
    const [rulesResponse, statsResponse, systemResponse] = await Promise.all([
      fetch("/api/v1/rules", { headers: { Accept: "application/json" } }),
      fetch("/api/v1/stats", { headers: { Accept: "application/json" } }),
      fetch("/api/v1/system", { headers: { Accept: "application/json" } }),
    ]);
    const [ruleset, statistics, system] = await Promise.all([
      rulesResponse.json(), statsResponse.json(), systemResponse.json(),
    ]);
    if (!rulesResponse.ok) throw new Error(ruleset.detail || ruleset.error || `Rules request failed (${rulesResponse.status})`);
    if (!statsResponse.ok) throw new Error(statistics.detail || statistics.error || `Statistics request failed (${statsResponse.status})`);
    if (!systemResponse.ok) throw new Error(system.detail || system.error || `System statistics request failed (${systemResponse.status})`);
    const entries = ruleset.nftables ?? [];
    state.rules = entries.filter((entry) => entry.rule).map((entry) => entry.rule);
    state.tables = entries.filter((entry) => entry.table).map((entry) => entry.table);
    state.chains = entries.filter((entry) => entry.chain).map((entry) => entry.chain);
    renderStatistics(statistics);
    renderSystemStatistics(system);
    setText("api-status", "API CONNECTED");
    document.getElementById("gateway-tag").classList.add("connected");
    renderRules();
  } catch (error) {
    showError(error.message);
  } finally {
    setText("last-updated", `Updated ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`);
    button.disabled = false;
    button.textContent = "Refresh";
  }
}

document.getElementById("refresh-button").addEventListener("click", refresh);
refresh();
