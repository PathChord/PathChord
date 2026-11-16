const state = {
  generation: 0,
  listeners: [],
  events: [],
  lastEventId: sessionStorage.getItem("pathchord-last-event-id") || "",
  refreshTimer: null,
};

const $ = (id) => document.getElementById(id);
const tokenInput = $("token");
tokenInput.value = sessionStorage.getItem("pathchord-token") || "";

function authHeaders() {
  const token = tokenInput.value.trim();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function requestId() {
  return crypto.randomUUID ? crypto.randomUUID().replaceAll("-", "") : `${Date.now()}${Math.random()}`.replace(".", "");
}

function showNotice(message, type = "") {
  const notice = $("notice");
  notice.textContent = message;
  notice.className = `notice ${type}`.trim();
  notice.hidden = false;
  clearTimeout(showNotice.timer);
  showNotice.timer = setTimeout(() => { notice.hidden = true; }, 5000);
}

async function api(path, options = {}) {
  const headers = {
    Accept: "application/json",
    ...authHeaders(),
    ...(options.headers || {}),
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["X-Request-ID"] = requestId();
    headers["X-PathChord-Generation"] = String(state.generation);
  }
  const response = await fetch(path, { ...options, headers });
  let envelope;
  try { envelope = await response.json(); } catch { throw new Error(`HTTP ${response.status}`); }
  if (!response.ok || envelope.ok === false) {
    const error = envelope.error || {};
    throw new Error(error.message || error.code || `HTTP ${response.status}`);
  }
  const applied = envelope.result?.applied_generation?.value;
  if (Number.isInteger(applied)) state.generation = applied;
  return envelope.result ?? envelope;
}

function text(value, fallback = "-") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function resourceName(item) {
  if (!item.name) return item.id;
  return item.namespace && item.namespace !== "default" ? `${item.namespace}/${item.name}` : item.name;
}

function tags(values, tone = "") {
  const fragment = document.createDocumentFragment();
  const list = Array.isArray(values) ? values : Object.entries(values || {}).map(([key, value]) => `${key}=${value}`);
  if (!list.length) {
    const span = document.createElement("span");
    span.className = "muted";
    span.textContent = "None";
    return span;
  }
  list.forEach((value) => {
    const span = document.createElement("span");
    span.className = `tag ${tone}`.trim();
    span.textContent = value;
    fragment.append(span);
  });
  return fragment;
}

function stateClass(value) {
  const normalized = String(value || "").toLowerCase();
  if (["running", "fresh", "connected", "up", "active", "healthy", "enabled", "open"].includes(normalized)) return "good";
  if (["stale", "degraded", "queued", "refreshing", "draining"].includes(normalized)) return "warn";
  if (["down", "failed", "stopped", "disabled", "reset", "closed"].includes(normalized)) return "bad";
  return "";
}

function setStatus(prefix, value) {
  $(`${prefix}-state`).textContent = text(value, "Unknown");
  $(`${prefix}-dot`).className = `dot ${stateClass(value) || "neutral"}`;
}

function emptyRow(body, columns, label = "No resources") {
  body.replaceChildren();
  const row = body.insertRow();
  const cell = row.insertCell();
  cell.colSpan = columns;
  cell.className = "empty";
  cell.textContent = label;
}

function cell(row, content, className = "") {
  const value = row.insertCell();
  if (content instanceof Node) value.append(content); else value.textContent = text(content);
  if (className) value.className = className;
  return value;
}

function renderStatus(status) {
  setStatus("control", status.control_plane?.state);
  setStatus("runtime", status.runtime_snapshot?.state);
  setStatus("path", status.data_path_summary);
  state.generation = Number(status.configuration_generation || 0);
  $("metric-sessions").textContent = status.sessions ?? 0;
  $("metric-paths").textContent = status.ready_paths ?? 0;
  $("metric-streams").textContent = status.streams ?? 0;
  $("metric-targets").textContent = status.target_connections ?? 0;
  $("snapshot-time").textContent = `Configuration generation ${state.generation}; observation generation ${status.observation_generation ?? 0}`;
}

function renderNodes(result) {
  const body = $("nodes-body");
  const items = result.items || [];
  if (!items.length) return emptyRow(body, 6, "No nodes");
  body.replaceChildren();
  items.forEach((item) => {
    const row = body.insertRow();
    cell(row, resourceName(item), "mono");
    cell(row, tags(item.admin?.labels));
    cell(row, tags(item.admin?.tags || [], "blue"));
    const diagnostic = item.observed?.diagnostic;
    const stateText = item.observed?.state || "unknown";
    const quota = item.observed?.quota;
    const remaining = Number.isFinite(quota?.remaining_ratio) ? `, ${(quota.remaining_ratio * 100).toFixed(1)}% remaining` : "";
    const multiplier = item.observed?.billing?.traffic_multiplier_basis_points;
    const billing = Number.isFinite(multiplier) ? `, ×${multiplier / 10000}` : "";
    cell(row, diagnostic ? `${stateText}: ${diagnostic.message} ${(diagnostic.fields || []).join(", ")}` : `${stateText}${remaining}${billing}`, diagnostic ? "state bad" : "muted");
    cell(row, item.generation, "mono");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const button = document.createElement("button");
    button.className = "button secondary small";
    button.type = "button";
    button.textContent = "Edit";
    button.dataset.node = item.id;
    button.addEventListener("click", () => openNodeDialog(item));
    actions.append(button);
    cell(row, actions);
  });
}

function renderSessions(result) {
  const body = $("sessions-body");
  const items = result.items || [];
  if (!items.length) return emptyRow(body, 5, "No active sessions");
  body.replaceChildren();
  items.forEach((item) => {
    const row = body.insertRow();
    cell(row, item.session_id, "mono");
    cell(row, item.egress_id);
    cell(row, item.state, `state ${stateClass(item.state)}`);
    cell(row, item.ready_path_count);
    cell(row, item.admission_generation, "mono");
  });
}

function renderConnections(result) {
  const body = $("connections-body");
  const items = result.items || [];
  if (!items.length) return emptyRow(body, 5, "No live connections");
  body.replaceChildren();
  items.forEach((item) => {
    const row = body.insertRow();
    cell(row, item.connection_id, "mono");
    cell(row, `${text(item.session_id)} / ${text(item.stream_id)}`, "mono");
    cell(row, item.state, `state ${stateClass(item.state)}`);
    cell(row, item.target ?? item.target_redaction_reason ?? "Redacted", item.target ? "" : "muted");
    cell(row, `${item.bytes_sent || 0} up / ${item.bytes_received || 0} down`, "mono");
  });
}

function renderListeners(result) {
  const body = $("listeners-body");
  const items = result.items || [];
  state.listeners = items;
  if (!items.length) emptyRow(body, 5, "No listeners"); else {
    body.replaceChildren();
    items.forEach((item) => {
      const row = body.insertRow();
      cell(row, resourceName(item), "mono");
      cell(row, item.kind);
      cell(row, item.bind, "mono");
      cell(row, item.state, `state ${stateClass(item.state)}`);
      cell(row, tags(item.allowed_sources || []));
    });
  }
  const select = $("proxy-listener-select");
  select.replaceChildren();
  items.filter((item) => ["http", "socks5", "mixed"].includes(String(item.kind).toLowerCase())).forEach((item) => {
    const option = document.createElement("option");
    option.value = item.id;
    option.textContent = `${resourceName(item)} (${item.bind})`;
    select.append(option);
  });
}

function renderSubscriptions(result) {
  const body = $("subscriptions-body");
  const items = result.items || [];
  if (!items.length) return emptyRow(body, 7, "No subscriptions");
  body.replaceChildren();
  items.forEach((item) => {
    const row = body.insertRow();
    cell(row, resourceName(item), "mono");
    cell(row, item.source_type);
    cell(row, item.source?.user_agent || "clash.meta", "mono");
    cell(row, item.state, `state ${stateClass(item.state)}`);
    cell(row, item.revision, "mono");
    cell(row, item.last_error, item.last_error ? "state bad" : "muted");
    const actions = document.createElement("div");
    actions.className = "row-actions";
    const refresh = document.createElement("button");
    refresh.className = "button secondary small";
    refresh.type = "button";
    refresh.textContent = "Refresh";
    refresh.addEventListener("click", () => mutateSubscription(item.id, "refresh", item.revision));
    const remove = document.createElement("button");
    remove.className = "button danger small";
    remove.type = "button";
    remove.textContent = "Delete";
    remove.addEventListener("click", () => mutateSubscription(item.id, "delete"));
    actions.append(refresh, remove);
    cell(row, actions);
  });
}

function renderProxy(result) {
  $("proxy-enabled").textContent = result.enabled ? "Enabled" : "Disabled";
  const listener = state.listeners.find((item) => item.id === result.listener_id);
  $("proxy-listener").textContent = text(listener ? resourceName(listener) : result.listener_id, "None");
  $("proxy-effect").textContent = text(result.platform_effect);
  $("proxy-restoration").textContent = text(result.restoration_state);
}

function renderEvents() {
  const body = $("events-body");
  if (!state.events.length) return emptyRow(body, 4, "No recent events");
  body.replaceChildren();
  state.events.slice(-20).reverse().forEach((item) => {
    const row = body.insertRow();
    cell(row, item.id, "mono");
    cell(row, item.type);
    cell(row, item.resource_id, "mono");
    cell(row, item.generation?.value ?? item.generation, "mono");
  });
}

async function refreshAll(silent = false) {
  try {
    const [status, nodes, sessions, connections, listeners, subscriptions, metrics, proxy] = await Promise.all([
      api("/api/v1/status"), api("/api/v1/nodes"), api("/api/v1/sessions"),
      api("/api/v1/connections"), api("/api/v1/listeners"), api("/api/v1/subscriptions"),
      api("/api/v1/metrics/snapshot"), api("/api/v1/system-proxy"),
    ]);
    renderStatus(status); renderNodes(nodes); renderSessions(sessions); renderConnections(connections);
    renderListeners(listeners); renderSubscriptions(subscriptions); renderProxy(proxy);
    if (metrics.captured_at_ms) $("snapshot-time").textContent += `; captured ${new Date(metrics.captured_at_ms).toLocaleTimeString()}`;
    if (!silent) showNotice("Snapshot refreshed", "success");
  } catch (error) { showNotice(error.message, "error"); }
}

function scheduleRefresh() {
  clearTimeout(state.refreshTimer);
  state.refreshTimer = setTimeout(() => refreshAll(true), 250);
}

function parsePairs(value) {
  const result = {};
  value.split(",").map((entry) => entry.trim()).filter(Boolean).forEach((entry) => {
    const index = entry.indexOf("=");
    if (index > 0) result[entry.slice(0, index).trim()] = entry.slice(index + 1).trim();
  });
  return result;
}

function parseList(value) { return value.split(",").map((item) => item.trim()).filter(Boolean); }

function openNodeDialog(item) {
  $("node-id").value = item.id;
  $("node-label-set").value = "";
  $("node-label-remove").value = "";
  $("node-tag-add").value = "";
  $("node-tag-remove").value = "";
  $("node-dialog").showModal();
}

$("node-form").addEventListener("submit", async (event) => {
  if (event.submitter?.value === "cancel") return;
  event.preventDefault();
  const nodeId = $("node-id").value;
  try {
    const set = parsePairs($("node-label-set").value);
    const remove = parseList($("node-label-remove").value);
    if (Object.keys(set).length || remove.length) {
      await api(`/api/v1/nodes/${encodeURIComponent(nodeId)}/labels`, { method: "PATCH", body: JSON.stringify({ set, remove }) });
    }
    const add = parseList($("node-tag-add").value);
    const removeTags = parseList($("node-tag-remove").value);
    if (add.length || removeTags.length) {
      await api(`/api/v1/nodes/${encodeURIComponent(nodeId)}/tags`, { method: "PATCH", body: JSON.stringify({ add, remove: removeTags }) });
    }
    $("node-dialog").close();
    showNotice("Node metadata updated", "success");
    await refreshAll(true);
  } catch (error) { showNotice(error.message, "error"); }
});

$("new-subscription").addEventListener("click", () => $("subscription-dialog").showModal());
$("subscription-form").addEventListener("submit", async (event) => {
  if (event.submitter?.value === "cancel") return;
  event.preventDefault();
  try {
    await api("/api/v1/subscriptions", {
      method: "POST",
      body: JSON.stringify({
        id: $("subscription-id").value.trim(),
        display_name: $("subscription-name").value.trim(),
        enabled: $("subscription-enabled").checked,
        source: {
          type: $("subscription-type").value,
          url: $("subscription-url").value.trim(),
          credentials_ref: $("subscription-credentials").value.trim() || null,
          user_agent: $("subscription-user-agent").value || null,
        },
        refresh: {
          interval_seconds: Number($("subscription-interval").value),
          timeout_seconds: Number($("subscription-timeout").value),
          max_attempts: Number($("subscription-attempts").value),
          backoff_seconds: Number($("subscription-backoff").value),
        },
        cache: $("subscription-cache-path").value.trim() ? {
          path: $("subscription-cache-path").value.trim(),
          max_age_seconds: Number($("subscription-cache-age").value),
        } : null,
      }),
    });
    $("subscription-dialog").close();
    $("subscription-form").reset();
    showNotice("Subscription created", "success");
    await refreshAll(true);
  } catch (error) { showNotice(error.message, "error"); }
});

async function mutateSubscription(id, action, revision) {
  try {
    const path = `/api/v1/subscriptions/${encodeURIComponent(id)}${action === "refresh" ? "/refresh" : ""}`;
    await api(path, { method: action === "refresh" ? "POST" : "DELETE", body: JSON.stringify(action === "refresh" ? { revision } : {}) });
    showNotice(`Subscription ${action === "refresh" ? "refresh queued" : "deleted"}`, "success");
    await refreshAll(true);
  } catch (error) { showNotice(error.message, "error"); }
}

$("proxy-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await api("/api/v1/system-proxy/enable", { method: "POST", body: JSON.stringify({ listener_id: $("proxy-listener-select").value }) });
    showNotice("System proxy enabled", "success"); await refreshAll(true);
  } catch (error) { showNotice(error.message, "error"); }
});
$("proxy-disable").addEventListener("click", async () => {
  try {
    await api("/api/v1/system-proxy/disable", { method: "POST", body: JSON.stringify({}) });
    showNotice("System proxy disabled", "success"); await refreshAll(true);
  } catch (error) { showNotice(error.message, "error"); }
});

document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((candidate) => candidate.classList.toggle("active", candidate === tab));
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === `view-${tab.dataset.view}`));
}));

$("refresh").addEventListener("click", () => refreshAll());
tokenInput.addEventListener("change", () => {
  sessionStorage.setItem("pathchord-token", tokenInput.value.trim());
  refreshAll();
  connectEvents();
});

function handleEvent(event) {
  if (event.id) {
    state.lastEventId = event.id;
    sessionStorage.setItem("pathchord-last-event-id", event.id);
  }
  if (event.data) {
    try {
      const parsed = JSON.parse(event.data);
      if (parsed.type && parsed.type !== "metrics.snapshot") {
        state.events.push(parsed);
        if (state.events.length > 100) state.events.shift();
        renderEvents();
      }
      scheduleRefresh();
    } catch { /* keep the stream alive after an invalid optional event */ }
  }
}

let eventAbort;
async function connectEvents() {
  if (eventAbort) eventAbort.abort();
  eventAbort = new AbortController();
  try {
    const headers = { Accept: "text/event-stream", ...authHeaders() };
    if (state.lastEventId) headers["Last-Event-ID"] = state.lastEventId;
    const response = await fetch("/api/v1/events", { headers, signal: eventAbort.signal });
    if (!response.ok || !response.body) throw new Error(`Event stream HTTP ${response.status}`);
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let event = {};
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();
      for (const raw of lines) {
        const line = raw.replace(/\r$/, "");
        if (!line) { handleEvent(event); event = {}; continue; }
        if (line.startsWith("id:")) event.id = line.slice(3).trim();
        else if (line.startsWith("event:")) event.type = line.slice(6).trim();
        else if (line.startsWith("data:")) event.data = `${event.data || ""}${line.slice(5).trim()}`;
      }
    }
  } catch (error) {
    if (error.name !== "AbortError") setTimeout(connectEvents, 1500);
  }
}

renderEvents();
refreshAll(true);
connectEvents();
