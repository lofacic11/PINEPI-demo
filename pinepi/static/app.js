"use strict";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const state = {
  page: "dashboard", interfaces: [], recon: null, selectedNetworkKey: null, apError: null,
  reconSort: {key: "signal", direction: -1}, pending: false, refreshing: false,
};

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function empty(node, message) { clear(node); node.append(element("div", "empty", message)); }
function fmtBytes(value) {
  if (value === null || value === undefined) return "—";
  let amount = Number(value); const units = ["B", "KB", "MB", "GB", "TB"]; let index = 0;
  while (amount >= 1024 && index < units.length - 1) { amount /= 1024; index += 1; }
  return `${amount.toFixed(index ? 1 : 0)} ${units[index]}`;
}
function fmtDuration(value) {
  let seconds = Math.max(0, Number(value) || 0);
  const days = Math.floor(seconds / 86400); seconds %= 86400;
  const hours = Math.floor(seconds / 3600); seconds %= 3600;
  const minutes = Math.floor(seconds / 60); seconds = Math.floor(seconds % 60);
  if (days) return `${days}d ${hours}h`;
  return [hours, minutes, seconds].map((part) => String(part).padStart(2, "0")).join(":");
}
function fmtDate(value) {
  if (!value) return "—";
  const date = new Date(value); return Number.isNaN(date.valueOf()) ? value : date.toLocaleString();
}
function percentBar(id, value) { $(id).style.width = `${Math.min(100, Math.max(0, Number(value) || 0))}%`; }
function statusPill(label, tone = "") { return element("span", `pill ${tone}`.trim(), label); }
function setNotice(node, message, tone = "") { node.textContent = message; node.className = `notice ${tone}`.trim(); }
function showError(error) {
  const toast = $("#toast"); toast.textContent = error.message || "Request failed."; toast.classList.add("show");
  window.clearTimeout(showError.timer); showError.timer = window.setTimeout(() => toast.classList.remove("show"), 6000);
}
async function api(path, options = {}) {
  const init = {...options, headers: {"Content-Type": "application/json", ...(options.headers || {})}};
  let response;
  try { response = await fetch(`/api${path}`, init); }
  catch (_error) { throw new Error("PinePi is unreachable."); }
  let payload = {};
  try { payload = await response.json(); } catch (_error) { /* handled below */ }
  if (!response.ok || payload.ok === false) {
    const error = new Error(payload.error?.message || `Request failed (${response.status}).`);
    error.code = payload.error?.code || "REQUEST_FAILED"; throw error;
  }
  return payload.data;
}
function setOnline(online) {
  $("#systemDot").classList.toggle("offline", !online);
  $("#systemStatus").textContent = online ? "System online" : "System unavailable";
}
function gotoPage(id) {
  state.page = id;
  $$(".page").forEach((page) => page.classList.toggle("active", page.id === id));
  $$(".nav button").forEach((button) => button.classList.toggle("active", button.dataset.page === id));
  $("#sidebar").classList.remove("open"); $("#overlay").classList.remove("show");
  history.replaceState(null, "", `#${id}`); window.scrollTo({top: 0, behavior: "smooth"}); refreshPage();
}

function option(value, label) { const node = element("option", "", label); node.value = value; return node; }
function fillSelect(node, items, predicate, label, placeholder, forceValue = null) {
  const selected = forceValue ?? node.value; clear(node);
  const eligible = items.filter(predicate);
  if (!eligible.length) { node.append(option("", placeholder)); node.disabled = true; return; }
  eligible.forEach((item) => node.append(option(item.name, label(item))));
  node.disabled = false;
  if ([...node.options].some((item) => item.value === selected)) node.value = selected;
}

function apChannelState(item) {
  if (item?.capabilities?.ap_channels?.length) return "known";
  return item?.ap_channel_state || item?.capabilities?.ap_channel_state || "unknown";
}
function apSelectable(item) {
  if (!item.wireless || !item.ap_capable || item.reserved) return false;
  if (item.role === "ap") return true;
  const inferred = item.usable && !item.busy && apChannelState(item) === "known" && Boolean(item.capabilities?.ap_channels?.length);
  return item.ap_selectable === true || inferred;
}
function apUnavailableReason(item) {
  if (item.reserved) return "Reserved for the PinePi management access point.";
  if (item.ap_capable && item.busy && item.role !== "ap") return `Busy with ${(item.role || "another operation").replaceAll("_", " ")}.`;
  if (!item.ap_capable) return "Adapter does not support AP mode.";
  if (!item.usable) return item.reason || "Adapter is not ready.";
  if (apChannelState(item) === "unknown") return "Unable to determine supported AP channels.";
  if (apChannelState(item) === "none") return "Adapter supports AP mode but no usable AP channels are available in the current regulatory domain.";
  return item.ap_selection_reason || "Adapter is not currently selectable.";
}

async function loadInterfaces(active = {}) {
  const data = await api(`/interfaces${active.apInterface ? `?ap_interface=${encodeURIComponent(active.apInterface)}` : ""}`);
  state.interfaces = data.interfaces;
  const monitorOk = (item) => item.wireless && item.monitor_capable && !item.reserved && (item.usable || item.role === active.reconRole || item.role === active.captureRole);
  fillSelect($("#reconInterface"), data.interfaces, monitorOk, (item) => `${item.name} — ${item.description}`, "No free monitor-capable adapter", active.reconInterface);
  fillSelect($("#captureInterface"), data.interfaces, monitorOk, (item) => `${item.name} — ${item.description}`, "No free monitor-capable adapter", active.captureInterface);
  fillSelect($("#apInterface"), data.interfaces, apSelectable, (item) => `${item.name} — ${item.description}`, "No selectable AP adapter", active.apInterface);
  data.interfaces.filter((item) => item.wireless && !apSelectable(item)).forEach((item) => {
    const unavailable = option(item.name, `${item.name} — ${apUnavailableReason(item)}`); unavailable.disabled = true; $("#apInterface").append(unavailable);
  });
  updateApChannels(active.apChannel);
  const apHint = $("#apCapabilityHint");
  const unavailableAdapters = data.interfaces.filter((item) => item.wireless && !apSelectable(item));
  const diagnosticAdapter = unavailableAdapters.find((item) => item.ap_capable && item.usable && apChannelState(item) === "unknown")
    || unavailableAdapters.find((item) => item.ap_capable && item.usable && apChannelState(item) === "none")
    || unavailableAdapters.find((item) => item.ap_capable && item.busy)
    || unavailableAdapters[0];
  apHint.textContent = !$("#apInterface").value && diagnosticAdapter
    ? apUnavailableReason(diagnosticAdapter)
    : (!$("#apInterface").value ? "No ready adapter currently supports AP mode." : "");
  const uplink = $("#apUplink"); const selected = active.requestedUplink || uplink.value || "auto"; clear(uplink);
  uplink.append(option("auto", "Automatic"));
  data.uplinks.forEach((item) => uplink.append(option(item.name, `${item.name} — ${item.connectivity ? "Internet route" : "Connected"}`)));
  uplink.append(option("none", "No uplink")); if ([...uplink.options].some((item) => item.value === selected)) uplink.value = selected;
  const list = $("#uplinkList"); clear(list);
  data.uplinks.forEach((item) => {
    const row = element("div", "interface"), info = element("div"); info.append(element("strong", "", item.name), element("small", "", item.connectivity ? "Connected · default Internet route" : "Connected"));
    row.append(info, statusPill("Available")); list.append(row);
  });
}

function updateApChannels(forceValue = null) {
  const select = $("#apChannel"), adapter = state.interfaces.find((item) => item.name === $("#apInterface").value);
  const selected = forceValue ?? Number(select.value || 6); clear(select);
  const channels = [...new Set(adapter?.capabilities?.ap_channels || [])].sort((a, b) => a - b);
  if (!channels.length) { select.append(option("", "No supported AP channels")); select.disabled = true; return; }
  channels.forEach((channel) => select.append(option(String(channel), String(channel))));
  select.disabled = false;
  if (channels.includes(Number(selected))) select.value = String(selected);
}

async function loadDashboard() {
  const data = await api("/dashboard"); setOnline(true); state.interfaces = data.interfaces;
  const system = data.system;
  $("#cpuMetric").textContent = `${Math.round(system.cpu_percent)}%`; $("#cpuLabel").textContent = `${system.cpu_count || "—"} cores`; percentBar("#cpuBar", system.cpu_percent);
  $("#memoryMetric").textContent = `${Math.round(system.memory_percent)}%`; $("#memoryLabel").textContent = `${fmtBytes(system.memory_used)} / ${fmtBytes(system.memory_total)}`; percentBar("#memoryBar", system.memory_percent);
  $("#storageMetric").textContent = `${Math.round(system.storage_percent)}%`; $("#storageLabel").textContent = `${fmtBytes(system.storage_used)} / ${fmtBytes(system.storage_total)}`; percentBar("#storageBar", system.storage_percent);
  $("#temperatureMetric").textContent = system.temperature_c === null ? "N/A" : `${system.temperature_c}°C`; percentBar("#temperatureBar", system.temperature_c || 0);
  $("#uptimeMetric").textContent = fmtDuration(system.uptime_seconds);
  const interfaces = $("#interfaceList"); clear(interfaces);
  if (!data.interfaces.length) empty(interfaces, "No network interfaces detected.");
  data.interfaces.forEach((item) => {
    const row = element("div", "interface"), info = element("div");
    const stateDetail = item.pinepi_state === "ready" ? "idle" : (["initializing", "unavailable", "error"].includes(item.pinepi_state) ? item.reason : null);
    const details = [item.description, item.mode, stateDetail, item.ipv4?.[0]].filter(Boolean).join(" · ");
    info.append(element("strong", "", item.name), element("small", "", details));
    let label = "Idle", tone = "blue";
    if (item.reserved) { label = "Reserved"; tone = ""; }
    else if ((item.pinepi_state || "").startsWith("active_")) { label = "Active"; tone = ""; }
    else if (item.pinepi_state === "ready") label = "Ready";
    else if (item.pinepi_state === "initializing") { label = "Waiting"; tone = "warn"; }
    else if (["unavailable", "error"].includes(item.pinepi_state)) { label = item.pinepi_state === "error" ? "Error" : "Unavailable"; tone = "red"; }
    else if (item.pinepi_state === "online") { label = "Online"; tone = ""; }
    const pill = statusPill(label, tone); if (item.reason) pill.title = item.reason;
    row.append(info, pill); interfaces.append(row);
  });
  const operations = $("#operationList"); clear(operations);
  if (!data.operations.length) { const wrap = element("div"); wrap.append(element("div", "operation-title", "No active operation"), element("div", "subtitle", "Audit interfaces are ready."), statusPill("Idle", "blue")); operations.append(wrap); }
  data.operations.forEach((item) => {
    const row = element("div", "interface"), info = element("div"); info.append(element("strong", "", item.type), element("small", "", `${item.interface} · ${fmtDuration(item.elapsed_seconds)}`)); row.append(info, statusPill(item.state, item.state === "RUNNING" ? "" : "warn")); operations.append(row);
  });
  $("#landscapeAps").textContent = data.landscape.access_points; $("#landscapeClients").textContent = data.landscape.clients;
  $("#landscapeOpen").textContent = data.landscape.open_networks; $("#landscapeChannels").textContent = data.landscape.channels_used;
}

function renderChart(node, values) {
  clear(node); const entries = Object.entries(values || {});
  if (!entries.length) return empty(node, "No Recon data.");
  const maximum = Math.max(...entries.map((entry) => Number(entry[1])));
  entries.forEach(([label, count]) => { const row = element("div", "chart-row"), track = element("div", "chart-bar"), bar = element("span"); bar.style.width = `${(Number(count) / maximum) * 100}%`; track.append(bar); row.append(element("span", "", label), track, element("strong", "", count)); node.append(row); });
}
function networkKey(ap) { return ap.bssid || `${ap.ssid || "<hidden>"}:${ap.channel ?? ""}`; }
function networkDetails(ap, className = "") {
  const detail = element("div", `network-detail ${className}`.trim());
  detail.append(element("h3", "", ap.ssid || "<hidden>"));
  const meta = element("div", "network-meta");
  [["BSSID", ap.bssid], ["Channel", ap.channel ?? "—"], ["Signal", ap.signal === null ? "—" : `${ap.signal} dBm`], ["Security", ap.security || "Unknown"], ["First seen", ap.first_seen || "—"], ["Last seen", ap.last_seen || "—"]].forEach(([label, value]) => { const item = element("span", "", label); item.append(element("strong", "", value)); meta.append(item); });
  detail.append(meta, element("div", "section-title", "Associated observed clients"));
  const clients = (state.recon?.clients || []).filter((item) => item.bssid === ap.bssid);
  if (!clients.length) detail.append(element("div", "empty", "No client association was observable for this network."));
  clients.forEach((client) => { const row = element("div", "client"), info = element("div"); info.append(element("strong", "", client.mac), element("small", "", `Signal ${client.signal ?? "—"} dBm · last seen ${client.last_seen || "—"}`)); row.append(info); detail.append(row); });
  return detail;
}
function toggleNetwork(ap) {
  const key = networkKey(ap);
  state.selectedNetworkKey = state.selectedNetworkKey === key ? null : key;
  if (state.recon) renderReconResults(state.recon);
}
function networkCard(ap) {
  const wrapper = element("div", "network-accordion"), card = element("button", "network-card selectable-card"), head = element("div", "network-card-head"); card.type = "button";
  const expanded = state.selectedNetworkKey === networkKey(ap); card.setAttribute("aria-expanded", String(expanded));
  head.append(element("strong", "", ap.ssid || "<hidden>"), statusPill(ap.security || "Unknown", (ap.security || "").toLowerCase() === "open" ? "warn" : ""));
  const grid = element("div", "network-card-grid"); [["Channel", ap.channel ?? "—"], ["Signal", ap.signal === null ? "—" : `${ap.signal} dBm`], ["Clients", ap.client_count || 0], ["BSSID", ap.bssid]].forEach(([key, value]) => { const span = element("span", "", key); span.append(document.createElement("br"), element("strong", "", value)); grid.append(span); });
  card.append(head, grid); card.addEventListener("click", () => toggleNetwork(ap)); wrapper.append(card);
  if (expanded) wrapper.append(networkDetails(ap, "mobile-network-detail"));
  return wrapper;
}
function renderReconResults(results) {
  state.recon = results; renderChart($("#channelChart"), results.channel_usage); renderChart($("#securityChart"), results.security_distribution);
  const query = $("#reconSearch").value.toLowerCase(); const {key, direction} = state.reconSort;
  const aps = [...results.access_points].filter((item) => `${item.ssid} ${item.bssid}`.toLowerCase().includes(query)).sort((a, b) => {
    const av = a[key] ?? "", bv = b[key] ?? ""; return direction * (typeof av === "number" ? av - (Number(bv) || 0) : String(av).localeCompare(String(bv)));
  });
  const tbody = $("#reconTable"), cards = $("#reconCards"); clear(tbody); clear(cards);
  if (!aps.length) { const row = element("tr"), cell = element("td", "empty", "No access points observed."); cell.colSpan = 7; row.append(cell); tbody.append(row); empty(cards, "No access points observed."); }
  aps.forEach((ap) => {
    const row = element("tr", "selectable");
    const signal = element("div", "signal", ap.signal === null ? "—" : `${ap.signal} dBm`), mini = element("div", "bar-mini"), bar = element("span"); bar.style.width = `${Math.min(100, Math.max(0, (Number(ap.signal) + 100) * 2))}%`; mini.append(bar); signal.append(mini);
    [ap.ssid || "<hidden>", ap.bssid, ap.channel ?? "—"].forEach((value, index) => { const td = element("td", "", value); if (index === 0) { const strong = element("strong", "", value); clear(td); td.append(strong); } row.append(td); });
    const signalCell = element("td"); signalCell.append(signal); row.append(signalCell);
    const securityCell = element("td"); securityCell.append(statusPill(ap.security || "Unknown", (ap.security || "").toLowerCase() === "open" ? "warn" : "")); row.append(securityCell, element("td", "", ap.client_count || 0), element("td", "", ap.last_seen || "—"));
    const expanded = state.selectedNetworkKey === networkKey(ap); row.setAttribute("aria-expanded", String(expanded));
    row.addEventListener("click", () => toggleNetwork(ap)); tbody.append(row);
    if (expanded) { const detailRow = element("tr", "inline-detail-row"), cell = element("td"); cell.colSpan = 7; cell.append(networkDetails(ap, "desktop-network-detail")); detailRow.append(cell); tbody.append(detailRow); }
    cards.append(networkCard(ap));
  });
  const sessionId = results.session?.id; [$("#reconCsv"), $("#reconJson")].forEach((link) => link.classList.toggle("disabled", !sessionId));
  if (sessionId) { $("#reconCsv").href = `/api/recon/${encodeURIComponent(sessionId)}/export.csv`; $("#reconJson").href = `/api/recon/${encodeURIComponent(sessionId)}/export.json`; }
}
async function loadRecon() {
  const data = await api("/recon"); const status = data.status;
  await loadInterfaces({reconInterface: status.interface, reconRole: "recon"});
  $("#reconBtn").textContent = status.active ? "Stop Recon" : "Start Recon"; $("#reconBtn").className = `btn full ${status.active ? "danger" : "primary"}`;
  $("#reconInterface").disabled = status.active || !$("#reconInterface").value; $("#reconMode").disabled = status.active; $("#reconBtn").disabled = !status.active && !$("#reconInterface").value;
  setNotice($("#reconNotice"), status.active ? `Scanning on ${status.interface} · elapsed ${fmtDuration(status.elapsed_seconds)}${status.process_alive === false ? " · process stopped, cleanup pending" : ""}` : "No Recon operation is active.", status.process_alive === false ? "warning" : "");
  const selector = $("#reconSession"), selected = selector.value; clear(selector); selector.append(option("", "Latest/current"));
  data.history.forEach((session) => selector.append(option(session.id, `${fmtDate(session.started_at)} · ${session.interface} · ${session.status}`))); if ([...selector.options].some((item) => item.value === selected)) selector.value = selected;
  if (!selector.value) renderReconResults(data.results);
}

function renderApClients(clients) {
  const list = $("#apClients"); clear(list); if (!clients.length) return empty(list, "No clients connected.");
  clients.forEach((client) => { const row = element("div", "client"), info = element("div"); info.append(element("strong", "", client.mac), element("small", "", `${client.ip || "No DHCP address"} · connected ${fmtDuration(client.duration_seconds)}`)); row.append(info, element("div", "muted", `↓ ${fmtBytes(client.rx_bytes)}  ↑ ${fmtBytes(client.tx_bytes)}`)); list.append(row); });
}
function mobileHistoryCard(title, badge, fields, actions = []) {
  const card = element("div", "network-card"), head = element("div", "network-card-head"); head.append(element("strong", "", title), statusPill(badge, "blue")); const grid = element("div", "network-card-grid");
  fields.forEach(([label, value]) => { const span = element("span", "", label); span.append(document.createElement("br"), element("strong", "", value)); grid.append(span); }); card.append(head, grid);
  if (actions.length) { const wrap = element("div", "actions field-gap"); actions.forEach((action) => wrap.append(action)); card.append(wrap); } return card;
}
function renderApHistory(history) {
  const tbody = $("#apHistory"), cards = $("#apHistoryCards"); clear(tbody); clear(cards);
  if (!history.length) { const row = element("tr"), td = element("td", "empty", "No Access Point sessions."); td.colSpan = 6; row.append(td); tbody.append(row); return empty(cards, "No Access Point sessions."); }
  history.forEach((session) => {
    const link = element("a", "btn", "ZIP"); link.href = `/api/access-point/${encodeURIComponent(session.id)}/export.zip`;
    const row = element("tr"); [session.ssid, fmtDate(session.started_at), session.interface, session.effective_uplink || "None", session.status].forEach((value) => row.append(element("td", "", value))); const action = element("td"); action.append(link); row.append(action); tbody.append(row);
    const mobileLink = link.cloneNode(true); cards.append(mobileHistoryCard(session.ssid, session.status, [["Interface", session.interface], ["Uplink", session.effective_uplink || "None"], ["Started", fmtDate(session.started_at)]], [mobileLink]));
  });
}
async function loadAp() {
  const data = await api("/access-point"), status = data.status;
  await loadInterfaces({apInterface: status.interface, apChannel: status.channel, requestedUplink: status.requested_uplink});
  const running = status.active; $("#apBtn").textContent = running ? "Stop Access Point" : "Start Access Point"; $("#apBtn").className = `btn ${running ? "danger" : "primary"}`;
  ["#apInterface", "#apSsid", "#apChannel", "#apSecurity", "#apPassword", "#apUplink", "#apForwarding", "#apLogClients", "#apCaptureTraffic"].forEach((id) => { $(id).disabled = running; });
  if (!running) updateApChannels(status.channel);
  $("#apInterface").disabled = running || !$("#apInterface").value; $("#apBtn").disabled = !running && (!$("#apInterface").value || !$("#apChannel").value);
  if (!running && $("#apUplink").value === "none") { $("#apForwarding").checked = false; $("#apForwarding").disabled = true; }
  if (running) setNotice($("#apNotice"), `${status.ssid} is active on ${status.interface} · ${status.security.toUpperCase()} · uplink ${status.effective_uplink || "none"} · elapsed ${fmtDuration(status.elapsed_seconds)} · traffic ${fmtBytes(status.capture_size_bytes)}`, status.hostapd_alive && status.dnsmasq_alive ? "" : "warning");
  else if (state.apError) setNotice($("#apNotice"), state.apError, "error");
  else setNotice($("#apNotice"), "Access Point is stopped. Temporary routing and capture state are clear.");
  renderApClients(status.clients || []); renderApHistory(data.history);
}

function actionLink(label, href) { const link = element("a", "btn", label); link.href = href; return link; }
function renderCaptureHistory(history) {
  const tbody = $("#captureHistory"), cards = $("#captureCards"); clear(tbody); clear(cards);
  if (!history.length) { const row = element("tr"), td = element("td", "empty", "No stored captures."); td.colSpan = 7; row.append(td); tbody.append(row); return empty(cards, "No stored captures."); }
  history.forEach((capture) => {
    const duration = capture.ended_at ? Math.max(0, Math.floor((new Date(capture.ended_at) - new Date(capture.started_at)) / 1000)) : 0;
    const actions = element("div", "actions"), pcap = actionLink("PCAP", `/api/captures/${encodeURIComponent(capture.id)}/download`), summary = actionLink("JSON", `/api/captures/${encodeURIComponent(capture.id)}/summary.json`), remove = element("button", "btn danger", "Delete");
    const deleteAction = async () => { if (!window.confirm(`Delete capture “${capture.name}”?`)) return; try { await api(`/captures/${encodeURIComponent(capture.id)}`, {method: "DELETE"}); await loadCapture(); } catch (error) { showError(error); } };
    remove.addEventListener("click", deleteAction); actions.append(pcap, summary, remove);
    const row = element("tr"); [capture.name, fmtDate(capture.started_at), fmtDuration(duration), capture.packet_count ?? "—", fmtBytes(capture.size_bytes), capture.status].forEach((value) => row.append(element("td", "", value))); const td = element("td"); td.append(actions); row.append(td); tbody.append(row);
    const mobileRemove = element("button", "btn danger", "Delete"); mobileRemove.addEventListener("click", deleteAction);
    const mobileActions = [actionLink("PCAP", pcap.href), actionLink("JSON", summary.href), mobileRemove]; cards.append(mobileHistoryCard(capture.name, fmtBytes(capture.size_bytes), [["Duration", fmtDuration(duration)], ["Packets", capture.packet_count ?? "—"], ["Status", capture.status]], mobileActions));
  });
}
async function loadCapture() {
  const data = await api("/captures"), status = data.status; await loadInterfaces({captureInterface: status.interface, captureRole: "capture"});
  $("#captureBtn").textContent = status.active ? "Stop Capture" : "Start Capture"; $("#captureBtn").className = `btn full ${status.active ? "danger" : "primary"}`;
  ["#captureInterface", "#captureChannel", "#captureName"].forEach((id) => { $(id).disabled = status.active; });
  $("#captureInterface").disabled = status.active || !$("#captureInterface").value; $("#captureBtn").disabled = !status.active && !$("#captureInterface").value;
  setNotice($("#captureNotice"), status.active ? `Capturing on ${status.interface} · CH ${status.channel} · ${fmtBytes(status.size_bytes)} · elapsed ${fmtDuration(status.elapsed_seconds)}` : "No standalone capture is active.", status.process_alive === false ? "warning" : ""); renderCaptureHistory(data.history);
}

function logQuery() { const params = new URLSearchParams(); if ($("#logLevel").value) params.set("level", $("#logLevel").value); if ($("#logComponent").value) params.set("component", $("#logComponent").value); if ($("#logSearch").value.trim()) params.set("search", $("#logSearch").value.trim()); return params; }
async function loadLogs() {
  const params = logQuery(), rows = await api(`/logs?${params}`), list = $("#logList"); clear(list); if (!rows.length) empty(list, "No matching log entries.");
  rows.forEach((item) => { const row = element("div", "log"), stamp = element("span", "muted timestamp", fmtDate(item.timestamp)), level = element("span", "", item.level), component = element("span", "component muted", item.component); level.style.color = item.level === "ERROR" ? "#ff7c74" : item.level === "WARNING" ? "#efc25c" : "#8bd49c"; row.append(stamp, level, component, element("span", "", item.message)); list.append(row); });
  $$(".log-export").forEach((link) => { const query = logQuery(); link.href = `/api/logs/export.${link.dataset.format}?${query}`; });
}

async function refreshPage() {
  if (state.pending || state.refreshing) return;
  state.refreshing = true;
  try {
    if (state.page === "dashboard") await loadDashboard();
    if (state.page === "recon") await loadRecon();
    if (state.page === "ap") await loadAp();
    if (state.page === "capture") await loadCapture();
    if (state.page === "logs") await loadLogs();
    setOnline(true);
  } catch (error) { setOnline(false); showError(error); }
  finally { state.refreshing = false; }
}
async function perform(button, callback, onError = null) {
  if (state.pending) return; state.pending = true; button.disabled = true;
  try { await callback(); } catch (error) { if (onError) onError(error); showError(error); } finally { state.pending = false; button.disabled = false; await refreshPage(); }
}

$$('.nav button').forEach((button) => button.addEventListener("click", () => gotoPage(button.dataset.page)));
$$('[data-goto]').forEach((button) => button.addEventListener("click", () => gotoPage(button.dataset.goto)));
$("#menuBtn").addEventListener("click", () => { $("#sidebar").classList.toggle("open"); $("#overlay").classList.toggle("show"); });
$("#overlay").addEventListener("click", () => { $("#sidebar").classList.remove("open"); $("#overlay").classList.remove("show"); });
$("#apSecurity").addEventListener("change", () => $("#apPasswordField").classList.toggle("hidden", $("#apSecurity").value !== "wpa2"));
$("#apInterface").addEventListener("change", () => { updateApChannels(); $("#apCapabilityHint").textContent = ""; $("#apBtn").disabled = !$("#apInterface").value || !$("#apChannel").value; });
$("#apUplink").addEventListener("change", () => { const noUplink = $("#apUplink").value === "none"; if (noUplink) $("#apForwarding").checked = false; $("#apForwarding").disabled = noUplink; });
$("#copyApPassword").addEventListener("click", async () => { if (!$("#apPassword").value) { $("#copyStatus").textContent = "Nothing to copy."; return; } try { await navigator.clipboard.writeText($("#apPassword").value); $("#copyStatus").textContent = "Password copied."; } catch (_error) { $("#apPassword").select(); document.execCommand("copy"); $("#copyStatus").textContent = "Password copied."; } });
$("#reconBtn").addEventListener("click", () => perform($("#reconBtn"), async () => { const active = $("#reconBtn").textContent.startsWith("Stop"); await api("/recon", active ? {method: "DELETE"} : {method: "POST", body: JSON.stringify({interface: $("#reconInterface").value, mode: $("#reconMode").value})}); }));
$("#apBtn").addEventListener("click", () => perform($("#apBtn"), async () => { const active = $("#apBtn").textContent.startsWith("Stop"); state.apError = null; if (active) return api("/access-point", {method: "DELETE"}); await api("/access-point", {method: "POST", body: JSON.stringify({interface: $("#apInterface").value, ssid: $("#apSsid").value, channel: Number($("#apChannel").value), security: $("#apSecurity").value, password: $("#apPassword").value, uplink: $("#apUplink").value, forwarding: $("#apForwarding").checked && $("#apUplink").value !== "none", log_clients: $("#apLogClients").checked, capture_traffic: $("#apCaptureTraffic").checked})}); }, (error) => { state.apError = error.message || "Access Point failed to start."; }));
$("#captureBtn").addEventListener("click", () => perform($("#captureBtn"), async () => { const active = $("#captureBtn").textContent.startsWith("Stop"); await api("/captures", active ? {method: "DELETE"} : {method: "POST", body: JSON.stringify({interface: $("#captureInterface").value, channel: Number($("#captureChannel").value), name: $("#captureName").value})}); }));
$("#reconSearch").addEventListener("input", () => { if (state.recon) renderReconResults(state.recon); });
$$('#recon th[data-sort]').forEach((header) => header.addEventListener("click", () => { const key = header.dataset.sort; state.reconSort.direction = state.reconSort.key === key ? state.reconSort.direction * -1 : 1; state.reconSort.key = key; if (state.recon) renderReconResults(state.recon); }));
$("#reconSession").addEventListener("change", async () => { try { if (!$("#reconSession").value) return loadRecon(); renderReconResults(await api(`/recon/${encodeURIComponent($("#reconSession").value)}`)); } catch (error) { showError(error); } });
$("#logApply").addEventListener("click", loadLogs); $("#logSearch").addEventListener("keydown", (event) => { if (event.key === "Enter") loadLogs(); });

const initialPage = location.hash.slice(1); if (["dashboard", "recon", "ap", "capture", "logs"].includes(initialPage)) gotoPage(initialPage); else refreshPage();
window.setInterval(refreshPage, 4000);
