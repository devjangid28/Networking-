/* NetProof — frontend.
   Two modes: "demo" (sample network) and "scan" (live discovery).
   Renders topology + systems, proposes changes, and replays the flow path
   the engine derived so you can see who is affected — Packet Tracer style. */
"use strict";

const $ = (id) => document.getElementById(id);

const TYPE_COLORS = {
  router: "#6b9bd4",
  firewall: "#c49adf",
  switch: "#d9a55c",
  host: "#4cb782",
  server: "#96a4b4",
  printer: "#b98ce0",
  cloud: "#96a4b4",
  internet: "#96a4b4",
  laptop: "#5ec8b2",
  mobile: "#f0a070",
  phone: "#f0a070",
  camera: "#e07090",
};

const DTYPE_ORDER = ["router", "switch", "server", "host", "printer", "cloud"];

let MODE = "demo";
let NET = null;        // demo model + presets
let SCAN = null;       // last scan discovery (raw)
let LIVE_NET = null;   // scanned model
let AGENT_NET = null;  // /api/network?org= for the selected account
let ORGS = [];         // all accounts
let ACTIVE_ORG = null; // selected account id
let recent = [];
let report = null;
let nodeCoords = {};   // device name -> {x,y}
let deviceByZone = {}; // zone name -> device name
let scanByIp = {};     // raw scan device lookup by ip

init();

async function init() {
  try {
    NET = await (await fetch("/api/network")).json();
  } catch (e) {
    toast("Failed to load app: " + e.message, true);
    return;
  }
  wireStatic();
  buildPresets();
  wireForm();
  await setMode(resumeMode());
  wireScan();
  const dd = $("demo-dismiss");
  if (dd) dd.addEventListener("click", () => {
    try { sessionStorage.setItem("netproof-demo-dismissed", "1"); } catch (e) {}
    const banner = $("demo-banner");
    if (banner) banner.hidden = true;
  });
}

function resumeMode() {
  try { return sessionStorage.getItem("netproof-mode") || "demo"; } catch (e) { return "demo"; }
}
function saveMode(m) {
  try { sessionStorage.setItem("netproof-mode", m); } catch (e) {}
}

/* Single source of truth for what data is on screen, used by the persistent
   demo banner + mode hint so real scans can never be mistaken for sample data. */
function netSource() {
  if (MODE === "scan" && LIVE_NET && SCAN && (SCAN.devices || []).length) return "scan";
  if (MODE === "agent" && AGENT_NET && AGENT_NET.source === "agent") return "agent";
  return "demo";
}
function updateModeLabels() {
  document.querySelectorAll("#mode-switch button").forEach((b) => b.classList.toggle("active", b.dataset.mode === MODE));
  const src = netSource();
  const hint = $("mode-hint");
  if (hint) {
    hint.textContent = src === "scan"
      ? "Live — every device below came from a real scan of this LAN. No fake data."
      : src === "agent"
        ? "Agent — a managed agent reported this network; CONFIRMED entries were matched against device config."
        : "Demo — preloaded sample network. No real device has been touched.";
  }
  const banner = $("demo-banner");
  if (banner) {
    let dismissed = false;
    try { dismissed = sessionStorage.getItem("netproof-demo-dismissed") === "1"; } catch (e) {}
    banner.hidden = !(src === "demo") || dismissed;
  }
}

/* ---------------- shared rendering ---------------- */
function model() {
  if (MODE === "scan" && LIVE_NET) return LIVE_NET;
  if (MODE === "agent" && AGENT_NET) return AGENT_NET;
  return NET;
}

function renderAll() {
  const $scan = $("scan-card"), $agent = $("agent-card");
  if ($scan) $scan.hidden = MODE === "agent";
  if ($agent) $agent.hidden = MODE !== "agent";
  const devCard = $("devices-card");
  if (MODE === "scan" && SCAN && (SCAN.devices || []).length) {
    renderDevices(SCAN.devices);
    if (devCard) devCard.hidden = false;
  } else if (MODE === "agent" && AGENT_NET && AGENT_NET.source === "agent") {
    renderDevices(AGENT_NET.scan_devices || model().devices || []);
    if (devCard) devCard.hidden = false;
  } else if (devCard) {
    devCard.hidden = true;
  }
  renderNetCard();
  renderTopo();
  renderRequirements(model().requirements, null);
  fillPolicySelects();
  fillAddressLists();
  applyChangeTypeFilter();
  refreshHint();
  if (NET && NET.presets) {
    const ok = MODE === "demo";
    $("preset").disabled = !ok;
    if (!ok) { $("preset").value = "__custom"; $("preset-desc").textContent = ""; }
  }
}

function renderNetCard() {
  const m = model();
  $("net-chip").textContent = m.name || "NetProof";
  const isAgent = MODE === "agent" && AGENT_NET && AGENT_NET.source === "agent";
  $("net-title").textContent = MODE === "scan" ? "Discovered network" : (isAgent ? "Managed network" : "Network");
  $("net-desc").textContent = m.description || "Loading…";
  const zones = m.zones || [];
  $("net-zones-count").textContent = zones.length + " zones";
  const chips = zones.slice(0, 18).map((z, i) => {
    const c = ["#6b9bd4", "#c49adf", "#d9a55c", "#4cb782", "#b98ce0", "#96a4b4"];
    const prefix = z.prefix ? z.prefix.split("/")[0] : z.name;
    const label = (MODE === "scan" || isAgent)
      ? (deviceByZone[z.name] && deviceByZone[z.name] !== z.name ? `@${z.name} ${z.name}` : z.name)
      : z.name + (z.prefix ? " · " + z.prefix : "");
    return `<span class="zone-chip" style="--zc:${c[i % c.length]}"><i></i>${label}</span>`;
  }).join("");
  $("zone-chips").innerHTML = chips || `<span class="muted" style="font-size:12px">no zones</span>`;

  const cs = $("confirm-summary");
  if (!cs) return;
  if (!isAgent) { cs.hidden = true; cs.innerHTML = ""; return; }
  const conf = AGENT_NET.confirmations || { rules: {}, routes: {} };
  const reportAt = AGENT_NET.reported_at || "";
  cs.hidden = false;
  cs.innerHTML = `
    <div class="conf-row">
      <span class="conf-count">${conf.rules.confirmed || 0}<i> confirmed rules</i></span>
      <span class="conf-count">${conf.rules.inferred || 0}<i> inferred rules</i></span>
      <span class="conf-count">${conf.routes.confirmed || 0}<i> confirmed routes</i></span>
      <span class="conf-count">${conf.routes.inferred || 0}<i> inferred routes</i></span>
    </div>
    <div class="conf-meta">agent report received ${esc(reportAt)}${AGENT_NET.scan_summary ? ` · ${esc(String(AGENT_NET.scan_summary.subnet || ""))} · ${AGENT_NET.scan_summary.devices} device(s)` : ""}</div>`;
}

/* ---------------- topology ---------------- */

/* Packet-Tracer style device artwork (inline SVG, no externals needed).
   Each glyph lives in a 72x52 box and inherits `stroke="currentColor"`
   so a single stroke colour per device type works everywhere. */
const ICON_SHAPES = {
  router: `
    <path d="M21 18 L14 7 M51 18 L58 7"/>
    <circle cx="14" cy="7" r="2.3"/>
    <circle cx="58" cy="7" r="2.3"/>
    <rect x="12" y="18" width="48" height="27" rx="7" fill="#131a22"/>
    <circle cx="19" cy="30" r="1.7"/>
    <circle cx="26" cy="30" r="1.7"/>
    <circle cx="33" cy="30" r="1.7"/>
    <rect x="48" y="26" width="8" height="6" rx="1.5"/>
    <rect x="48" y="36" width="8" height="6" rx="1.5"/>`,
  firewall: `
    <path d="M21 18 L14 7 M51 18 L58 7"/>
    <circle cx="14" cy="7" r="2.3"/>
    <circle cx="58" cy="7" r="2.3"/>
    <rect x="12" y="18" width="48" height="27" rx="7" fill="#131a22"/>
    <path d="M36 20 V43"/>
    <circle cx="20" cy="30" r="1.6"/>
    <circle cx="27" cy="30" r="1.6"/>
    <rect x="48" y="26" width="8" height="6" rx="1.5"/>
    <rect x="48" y="36" width="8" height="6" rx="1.5"/>`,
  switch: `
    <rect x="7" y="26" width="58" height="18" rx="4" fill="#131a22"/>
    <rect x="12" y="30" width="4.5" height="10" rx="1"/>
    <rect x="19" y="30" width="4.5" height="10" rx="1"/>
    <rect x="26" y="30" width="4.5" height="10" rx="1"/>
    <rect x="33" y="30" width="4.5" height="10" rx="1"/>
    <rect x="40" y="30" width="4.5" height="10" rx="1"/>
    <rect x="47" y="30" width="4.5" height="10" rx="1"/>
    <circle cx="55" cy="32" r="1.4"/>
    <circle cx="55" cy="37" r="1.4"/>`,
  host: `
    <rect x="8" y="7" width="33" height="21" rx="2.5" fill="#131a22"/>
    <rect x="10.5" y="9.5" width="28" height="15" rx="1.5" fill="#0c1116" stroke="#2a3847" stroke-width="1"/>
    <path d="M24.5 28 V34 M18.5 34 H30.5"/>
    <rect x="48" y="15" width="17" height="29" rx="2.5" fill="#131a22"/>
    <circle cx="52.5" cy="20" r="1.6"/>
    <path d="M51 26 H61 M51 30 H61"/>`,
  laptop: `
    <path d="M15 33 L57 33 L51 11 L21 11 Z" fill="#131a22"/>
    <path d="M19 30.5 L53 30.5 L48 14 L24 14 Z" fill="#0c1116" stroke="#2a3847" stroke-width="1"/>
    <rect x="11" y="35" width="50" height="6" rx="2.5" fill="#131a22"/>
    <rect x="29" y="37" width="14" height="2.6" rx="1.3" fill="#2a3847"/>`,
  phone: `
    <rect x="27" y="5" width="18" height="42" rx="4.5" fill="#131a22"/>
    <rect x="29.8" y="9" width="12.4" height="31" rx="2" fill="#0c1116" stroke="#2a3847" stroke-width="1"/>
    <rect x="32" y="6.6" width="8" height="1.4" rx="0.7" fill="#3a4a5c"/>
    <circle cx="36" cy="43.5" r="1.6"/>`,
  server: `
    <rect x="20" y="7" width="32" height="38" rx="3.5" fill="#131a22"/>
    <path d="M24 14 H48 M24 17.5 H48 M24 21 H48" stroke="#2a3847" stroke-width="1.2"/>
    <circle cx="28" cy="39" r="1.4"/>
    <circle cx="33" cy="39" r="1.4"/>
    <circle cx="38" cy="39" r="1.4"/>
    <rect x="43" y="34" width="6" height="9" rx="1" fill="#0c1116"/>`,
  printer: `
    <rect x="22" y="9" width="28" height="8" rx="2" fill="#1b2530"/>
    <rect x="9" y="18" width="54" height="26" rx="4" fill="#131a22"/>
    <rect x="13" y="23" width="17" height="6" rx="1.2" fill="#0c1116" stroke="#2a3847" stroke-width="1"/>
    <rect x="34" y="25.5" width="11" height="4" rx="1"/>
    <circle cx="49" cy="27.5" r="1.4"/>
    <rect x="13" y="38.5" width="46" height="2.6" rx="1.3" fill="#2a3847"/>`,
  camera: `
    <rect x="18" y="16" width="36" height="26" rx="4" fill="#131a22"/>
    <path d="M54 22 L64 17 L64 37 L54 32 Z" fill="#131a22"/>
    <circle cx="36" cy="29" r="7" fill="#0c1116" stroke="currentColor" stroke-width="1.4"/>
    <circle cx="36" cy="29" r="3.5" fill="#131a22"/>
    <circle cx="48" cy="20" r="2" fill="currentColor"/>`,
  mobile: `
    <rect x="27" y="5" width="18" height="42" rx="4.5" fill="#131a22"/>
    <rect x="29.8" y="9" width="12.4" height="31" rx="2" fill="#0c1116" stroke="#2a3847" stroke-width="1"/>
    <rect x="32" y="6.6" width="8" height="1.4" rx="0.7" fill="#3a4a5c"/>
    <circle cx="36" cy="43.5" r="1.6"/>`,
};

function deviceIcon(type, size = 72) {
  const shapes = ICON_SHAPES[type] || ICON_SHAPES.host;
  const h = Math.round((size * 52) / 72);
  return `<svg class="dicon" width="${size}" height="${h}" viewBox="0 0 72 52" preserveAspectRatio="xMidYMid meet" style="color:${TYPE_COLORS[type] || "#96a4b4"}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${shapes}</svg>`;
}

function shortName(s) {
  s = String(s || "");
  return s.length > 18 ? s.slice(0, 16) + "…" : s;
}

function mainIp(dev) {
  const i = dev.interfaces && dev.interfaces.find((x) => x.ip);
  return i ? i.ip.replace(/\/.*/, "") : "";
}

/* Human-friendly label for a device in selects & suggestions. Scan names are
   hostnames (jiofiber.local.html), demo names are short ids; always show the
   primary IP so you never get a bare ".0" or a truncated host being useless. */
function devLabel(dev) {
  const ip = mainIp(dev);
  return ip ? `${dev.name} (${ip})` : dev.name;
}
function devTooltip(dev) {
  const ip = mainIp(dev);
  const tag = (dev.type || "").toUpperCase();
  return `${dev.name} — ${ip || "no IP"} [${tag}]`;
}
function devOrder(a, b) {
  const rank = { router: 0, firewall: 0, switch: 1, server: 2, host: 3, printer: 4, cloud: 5 };
  const ra = rank[a.type] ?? 6, rb = rank[b.type] ?? 6;
  return ra !== rb ? ra - rb : String(a.name).localeCompare(String(b.name));
}

/* Suggestions for the free-text Source/Destination/Network/Next-hop inputs so
   typing shows the REAL devices and subnets on this model — not a stale list
   a browser remembered from previous sessions. */
function fillAddressLists() {
  const m = model();
  const devices = m.devices || [];
  const zones = m.zones || [];
  const src = $("net-sources"), dst = $("net-destinations");
  const optR = $("net-routes-opt"), optIp = $("net-ips");
  if (!src || !dst) return;
  [src, dst, optR, optIp].forEach((el) => { if (el) el.innerHTML = ""; });
  const opts = (dl, val, label) => {
    const o = document.createElement("option");
    o.value = val;
    if (label) o.label = label;
    dl.appendChild(o);
  };
  opts(src, "any", "any — anywhere");
  opts(dst, "any", "any — anywhere");

  const prefixes = new Set();
  if ((MODE === "scan" || MODE === "agent") && m.scan_summary && m.scan_summary.subnet) {
    /* a scanned network is per-host zones (/32) — the ACTUAL subnet the user
       discovered is the right "whole subnet" suggestion, not a bunch of /32s */
    prefixes.add(m.scan_summary.subnet);
  } else {
    (zones || []).forEach((z) => { if (z && z.prefix) prefixes.add(z.prefix); });
  }
  [...prefixes].sort().forEach((p) => {
    opts(src, p, `${p}  ·  whole subnet`);
    opts(dst, p, `${p}  ·  whole subnet`);
    opts(optR, p, `${p}  ·  known subnet`);
  });

  const seenRoutes = new Set();
  devices.slice().sort(devOrder).forEach((d) => {
    const ifaces = (d.interfaces || []).filter((i) => i.ip);
    if (!ifaces.length) return;
    let primary = ifaces.find((i) => i.ip.includes("/")) || ifaces[0];
    const ip = primary.ip.replace(/\/.*/, "");
    const label = `${devLabel(d)}  ·  ${d.type}`;
    opts(src, ip, label);
    opts(dst, ip, label);
    opts(src, d.name, label);
    opts(dst, d.name, label);
    opts(optIp, ip, label);
    (d.routes || []).forEach((r) => {
      if (seenRoutes.has(r.network)) return;
      seenRoutes.add(r.network);
      opts(optR, r.network, `${r.network}  ·  existing route on ${d.name}`);
    });
  });
}

/* Nuke browser autocomplete memory on any datalist-backed input. Browsers
   remember past values across sessions and show them regardless of our
   datalist contents, which confuses the user when switching networks.
   Nudging the value on focus forces re-evaluation while the user types. */
function wipeBrowserMemory(inputId) {
  const el = $(inputId);
  if (!el) return;
  el.setAttribute("autocomplete", "off");
  el.addEventListener("focus", () => {
    const v = el.value;
    if (!v) return;
    el.value = "";
    el.value = v;
  });
}

/* After every scan / mode switch, rebuild the datalist with ONLY the
   current model's devices so nothing from a previous network lingers. */
let _addrListDebounce = null;
function refreshSuggestions() {
  clearTimeout(_addrListDebounce);
  _addrListDebounce = setTimeout(() => {
    fillAddressLists();
    ["f-src", "f-dst", "r-network", "r-nh"].forEach((id) => {
      const el = $(id);
      if (el) el.removeAttribute("readonly");
    });
  }, 60);
}

/* Remove every suggestion as soon as a NEW scan starts (or it fails), so the
   previous network's IPs can never leak into the new one's fields. */
function clearSuggestions() {
  ["net-sources", "net-destinations", "net-routes-opt", "net-ips"].forEach((id) => {
    const el = $(id);
    if (el) el.innerHTML = "";
  });
}

/* Prettier label for the map: live scans prefer the received hostname /
   SNMP sysName (so the router shows "jio"-style names). */
function nodeDisplayName(dev) {
  if ((MODE === "scan" && SCAN) || MODE === "agent") {
    const raw = scanByIp[mainIp(dev)];
    if (raw) {
      const nm = raw.is_target
        ? (raw.snmp && raw.snmp.sysName) || raw.hostname
        : raw.hostname || (raw.snmp && raw.snmp.sysName);
      if (nm) return nm;
    }
  }
  return dev.name;
}

function renderTopo() {
  stopTopoFlowOverlay();
  const svg = $("topo");
  svg.innerHTML = "";
  nodeCoords = {};
  hideDeviceDetail();

  const m = model();
  const devs = m.devices || [], links = m.links || [];
  const cnt = $("topo-count");
  if (cnt) cnt.textContent = (MODE === "scan" || MODE === "agent") ? devs.length + " device(s) on segment" : devs.length + " systems";

  if (!devs.length) {
    svg.innerHTML = `<foreignObject x="0" y="0" width="1200" height="600"><div class="topology-empty">No network loaded. Run a scan above, or switch to Demo.</div></foreignObject>`;
    return;
  }

  const byName = {};
  devs.forEach((d) => (byName[d.name] = d));

  let out = "";
  links.forEach((l) => {
    const a = byName[l.a_dev], b = byName[l.b_dev];
    if (!a || !b) return;
    out += `<line class="link-line" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="#2a3542" stroke-width="2" stroke-dasharray="5 6"/>`;
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
    const iface = a.interfaces.find((i) => i.connected_to && i.connected_to.split(" ")[0] === b.name);
    if (iface && iface.network) {
      out += `<text class="link-net" x="${mx}" y="${my}" text-anchor="middle" dominant-baseline="middle">${esc(iface.network.replace(/\/24$/, "").replace(/\/32$/, "/32"))}</text>`;
    }
  });

  devs.forEach((d) => {
    nodeCoords[d.name] = { x: d.x, y: d.y };
    const isCloud = d.type === "cloud" || d.type === "internet";
    out += `<g class="node" data-device="${esc(d.name)}" transform="translate(${d.x},${d.y})">`;
    out += `<rect class="sel-ring" x="-44" y="-30" width="88" height="70" rx="16"/>`;
    out += `<g transform="translate(-36,-26)">${deviceIcon(d.type, 72)}</g>`;
    if (isCloud) {
      out += `<text class="node-name" x="0" y="2" text-anchor="middle">${esc(shortName(nodeDisplayName(d)))}</text>`;
    } else {
      out += `<text class="node-name" x="0" y="34" text-anchor="middle">${esc(shortName(nodeDisplayName(d)))}</text>`;
      const ip = d.interfaces && d.interfaces.find((i) => i.ip);
      if (ip) out += `<text class="node-ip" x="0" y="46" text-anchor="middle">${esc(ip.ip.replace(/\/.*/, ""))}</text>`;
    }
    out += `</g>`;
  });

  svg.innerHTML = out;
  // Auto-size the SVG viewBox to fit all nodes with padding
  const PAD = 80;
  const xs = devs.map((d) => d.x), ys = devs.map((d) => d.y);
  const minX = Math.min(...xs) - PAD, minY = Math.min(...ys) - PAD;
  const maxX = Math.max(...xs) + PAD, maxY = Math.max(...ys) + PAD;
  const vw = maxX - minX, vh = maxY - minY;
  svg.setAttribute("viewBox", `${minX} ${minY} ${vw} ${vh}`);
  svg.style.width = "100%";
  svg.style.height = Math.max(480, vh) + "px";
  svg.appendChild(svgStyle());
  wireTopoClicks(svg);
}

function svgStyle() {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "style");
  s.textContent = `
    .node-name { fill:#e3e9f1; font:600 12.5px Inter, sans-serif; }
    .node-ip { fill:#96a4b4; font:500 9.5px "JetBrains Mono", monospace; }
    .link-net { fill:#66758a; font:500 9.5px "JetBrains Mono", monospace; }
    .node { cursor:pointer; }
    .node .sel-ring { fill:rgba(94,200,178,0.05); stroke:transparent; stroke-width:1.6; }
    .node:hover .sel-ring { stroke:rgba(94,200,178,0.45); }
    .node.selected .sel-ring { stroke:#5ec8b2; }
    .node.flash .sel-ring { stroke:#d9a55c; stroke-width:3; }
    .node.flash-block .sel-ring { stroke:#d97b6f; stroke-width:3; }
    .node.flash.sent .sel-ring { stroke:#4cb782; stroke-width:3; }
    @keyframes nodeFlash { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .node.flash .sel-ring, .node.flash-block .sel-ring { animation: nodeFlash 0.38s ease; }
  `;
  return s;
}

function svgNS(tag, attrs) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  return el;
}

/* ---------------- device detail (click a map device) ---------------- */
function kv(key, val, mono) {
  if (val === undefined || val === null || val === "") return "";
  return `<div class="dk-row"><span>${esc(key)}</span><b${mono ? ' class="mono"' : ""}>${esc(String(val))}</b></div>`;
}

function srcBadge(source) {
  if (source === "confirmed") {
    return `<span class="src-badge confirmed" title="matched against the device config the agent pulled">CONFIRMED</span>`;
  }
  return `<span class="src-badge inferred" title="inferred from discovery — not present in the device config">inferred</span>`;
}

function renderDetail(dev, raw) {
  const panel = $("dev-detail");
  const color = TYPE_COLORS[dev.type] || "#96a4b4";
  const icon = deviceIcon(dev.type, 40);
  const showSrc = MODE === "agent";
  const routes = (dev.routes || []).map((r) =>
    `<div class="dk-row"><span>route</span><b class="mono">${esc(r.network)} via ${esc(r.next_hop)}</b>${showSrc ? srcBadge(r.source) : ""}</div>`
  ).join("");
  const ifaces = (dev.interfaces || []).map((i) => {
    const text = [i.ip ? i.ip.replace(/\/.*/, "") : "", i.label || "", i.connected_to ? "→ " + i.connected_to.split(" ")[0] : ""].filter(Boolean).join(" · ");
    return kv(i.name, text, true);
  }).join("");

  let policy = "";
  if ((MODE === "scan" || MODE === "agent") && (dev.interfaces || []).length) {
    const rows = (dev.interfaces || []).reduce((acc, i) => {
      (i.filters || []).forEach((fname) => {
        const f = (model().filters || []).find((x) => x.name === fname);
        if (!f) return;
        acc.push({
          iface: i.name,
          fname: f.name,
          default: f.default,
          rules: (f.rules || [])
            .map((r) => `<div class="pol-rule"><span class="pol-act ${r.action}">${esc(r.action)}</span><span class="pol-spec">${esc([r.src, r.dst].filter(Boolean).join(" → "))}${r.proto && r.proto !== "any" ? " " + esc(r.proto) : ""}${r.dport ? "/" + esc(r.dport) : ""}</span>${showSrc ? srcBadge(r.source) : ""}</div>`)
            .join(""),
        });
      });
      return acc;
    }, []);
    if (rows.length) {
      policy = `<div class="dk-sec">enforced policy</div>` +
        rows.map((r) => `<div class="pol-filter"><span class="pol-if">${esc(r.iface)} · ${esc(r.fname)}</span><span class="pol-default">default ${esc(r.default)}</span><div class="pol-rules">${r.rules}</div></div>`).join("");
    }
  }

  let ext = "";
  if (raw) {
    ext += kv("MAC", raw.mac, true) + kv("vendor", raw.vendor);
    if (raw.hostname) ext += kv("hostname", raw.hostname, true);
    if (raw.services && raw.services.length) {
      ext += `<div class="dk-sec">open services</div><div class="dk-chips">` +
        raw.services.map((s) => `<span class="srv-chip">${s.port}/<b>${s.service}</b></span>`).join("") + `</div>`;
    }
    if (raw.snmp && (raw.snmp.sysName || raw.snmp.sysDescr)) {
      const parts = [];
      if (raw.snmp.sysName) parts.push(kv("sysName", raw.snmp.sysName, true));
      if (raw.snmp.sysDescr) parts.push(kv("sysDescr", raw.snmp.sysDescr.slice(0, 140), true));
      if (parts.length) ext += `<div class="dk-sec">SNMP</div>` + parts.join("");
    }
  }

  panel.innerHTML = `
    <div class="dd-head">
      <div class="dd-icon" style="color:${color}">${icon}</div>
      <div class="dd-title">
        <div class="dd-name">${esc(dev.name)}</div>
        <div class="dd-tags"><span class="dev-tag ${dev.type}">${dev.type}</span>${raw && raw.is_target ? '<span class="dev-tag router">target router</span>' : ""}</div>
      </div>
      <button class="dd-close" id="dd-close" title="Close">×</button>
    </div>
    <div class="dd-body">
      ${kv("IP", mainIp(dev), true)}
      ${ifaces ? `<div class="dk-sec">interfaces</div>` + ifaces : ""}
      ${routes ? `<div class="dk-sec">routes</div>` + routes : ""}
      ${policy}
      ${ext}
    </div>`;
  panel.querySelector("#dd-close").addEventListener("click", hideDeviceDetail);
  panel.hidden = false;
}

function showDeviceDetail(name) {
  const m = model();
  const dev = (m.devices || []).find((x) => x.name === name);
  if (!dev) return;
  let raw = null;
  const ip = mainIp(dev);
  if (MODE === "scan" && SCAN) raw = scanByIp[ip] || null;
  else if (MODE === "agent" && AGENT_NET) raw = (AGENT_NET.scan_devices || []).find((d) => (d.ip || "") === ip) || null;
  renderDetail(dev, raw);
}

function hideDeviceDetail() {
  const p = $("dev-detail");
  if (!p || p.hidden) return;
  p.hidden = true;
  document.querySelectorAll("g.node.selected").forEach((x) => x.classList.remove("selected"));
}

function openDeviceByIp(ip) {
  const m = model();
  const dev = (m.devices || []).find((d) => d.interfaces && d.interfaces.some((i) => i.ip && i.ip.replace(/\/.*/, "") === ip));
  if (!dev) { toast("No model node for " + ip, true); return; }
  const svg = $("topo");
  svg.querySelectorAll("g.node.selected").forEach((x) => x.classList.remove("selected"));
  const g = svg.querySelector(`g.node[data-device="${CSS.escape(dev.name)}"]`);
  if (g) {
    g.classList.add("selected");
    const rect = g.getBoundingClientRect();
    svg.getBoundingClientRect();
    window.scrollTo({ top: window.scrollY + rect.top - window.innerHeight / 2.5, behavior: "smooth" });
  }
  showDeviceDetail(dev.name);
}

function wireTopoClicks(svg) {
  svg.querySelectorAll("g.node").forEach((g) => {
    g.addEventListener("click", (ev) => {
      ev.stopPropagation();
      svg.querySelectorAll("g.node.selected").forEach((x) => x.classList.remove("selected"));
      g.classList.add("selected");
      showDeviceDetail(g.dataset.device);
    });
  });
  svg.addEventListener("click", hideDeviceDetail);
}

/* ---------------- requirements ---------------- */
function renderRequirements(reqs, result) {
  const wrap = $("req-list");
  $("req-count").textContent = reqs.length + " rules";
  if (!reqs.length) {
    wrap.innerHTML = MODE === "scan"
      ? `<div class="muted" style="font-size:12px">Nothing protected yet — tick the services under <b>Discovered systems</b> and they become requirements the engine re-checks on every proposed change.</div>`
      : `<div class="muted" style="font-size:12px">No policy requirements on this network yet — use <b>Propose a change</b> and watch the flow replay to see impact.</div>`;
    return;
  }
  const map = {};
  (result ? result.requirements : []).forEach((r) => { map[r.name] = r; });
  wrap.innerHTML = reqs.map((r) => {
    const st = map[r.name];
    const cls = st ? (st.ok && st.before === st.after ? "pass" : st.ok ? "pass" : "block") : "neutral";
    const state = st
      ? `<div class="req-state"><span class="bf">before ${st.before}</span> → after <b style="color:var(--pass)">${st.after}</b></div>`
      : `<div class="req-state">idle until you validate</div>`;
    return `<div class="req-item ${cls}"><span class="status"></span><div class="req-body">
      <div class="req-name">${esc(r.name)}</div>
      <div class="req-flow">${esc(r.src)} → ${esc(r.dst)} · ${esc(r.proto)}${r.dport ? "/" + r.dport : ""}</div>
      <div class="req-expect">must be <b>${esc(r.expect)}</b></div>${state}</div></div>`;
  }).join("");
}

/* ---------------- scan ---------------- */
function wireScan() {
  $("scan-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const target = $("scan-target").value.trim();
    if (!target) { toast("Enter the router/server IP or CIDR to scan.", true); return; }
    const btn = $("scan-btn");
    btn.disabled = true;
    btn.textContent = "Discovering… (ARP, ping sweep, service ports)";
    $("scan-note").textContent = "Scanning — this can take 10-30s depending on subnet size…";
    clearSuggestions();
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, community: $("scan-community").value.trim() || "public", ping: true }),
      });
      if (!res.ok) throw new Error((await res.json()).detail || "scan failed");
      SCAN = await res.json();
      await loadLiveModel();
      $("scan-note").textContent = `Found ${SCAN.devices.length} live system(s) on ${SCAN.network} in ${SCAN.seconds}s. ` + (SCAN.notes || []).slice(0, 2).join(" ");
      toast(`Scan complete — ${SCAN.devices.length} system(s) discovered on ${SCAN.network}`);
    } catch (e) {
      /* nothing found / scan failed: never leave the previous network's
         suggestions behind, or the UI looks like it reports the wrong net */
      $("scan-note").textContent = "No devices found on that network — nothing to show. The previous details were cleared.";
      $("devices-card").hidden = true;
      toast("Scan failed: " + e.message, true);
    }
    btn.disabled = false;
    btn.textContent = "Discover connected systems";
  });
}

async function loadLiveModel() {
  const info = await (await fetch("/api/model?mode=scan")).json();
  LIVE_NET = info;
  deviceByZone = {};
  scanByIp = {};
  (SCAN.devices || []).forEach((d) => { scanByIp[d.ip] = d; });
  (info.devices || []).forEach((d) => {
    d.interfaces && d.interfaces.forEach((i) => {
      if (i.ip) deviceByZone[i.ip.replace(/\/.*/, "")] = d.name;
    });
  });
  await setMode("scan");
  renderDevices(SCAN.devices);
  $("devices-card").hidden = false;
  refreshSuggestions();
}

/* ---------------- device list ---------------- */
let devFilter = "all";
let protectSel = new Set();   // "ip:port" keys the user ticked to turn into policy requirements
let protectBusy = false;
async function applyProtect() {
  if (protectBusy) return;
  protectBusy = true;
  const prev = [...protectSel];
  try {
    const res = await fetch("/api/model?mode=scan&protect=" + encodeURIComponent(JSON.stringify(prev)));
    if (!res.ok) throw new Error((await res.json()).detail || "model rebuild failed");
    LIVE_NET = await res.json();
    deviceByZone = {};
    (LIVE_NET.devices || []).forEach((d) => {
      d.interfaces && d.interfaces.forEach((i) => {
        if (i.ip) deviceByZone[i.ip.replace(/\/.*/, "")] = d.name;
      });
    });
    renderAll();
    toast(prev.length
      ? `Protecting ${prev.length} discovered service${prev.length > 1 ? "s" : ""} — policy requirements updated below.`
      : "Nothing protected — those services stay open (no requirements). Tick a service to protect it.");
  } catch (e) {
    toast("Protect update failed: " + e.message, true);
  } finally {
    protectBusy = false;
  }
}
function renderDevices(devices) {
  const protect = MODE === "scan";
  $("dev-count").textContent = devices.length + " systems";
  const tint = { router: "rgba(107,155,212,0.15)", switch: "rgba(217,165,92,0.15)", host: "rgba(76,183,130,0.15)", server: "rgba(150,164,180,0.15)", printer: "rgba(185,140,224,0.15)", laptop: "rgba(94,200,178,0.15)", mobile: "rgba(240,160,112,0.15)", phone: "rgba(240,160,112,0.15)", camera: "rgba(224,112,144,0.15)" };
  const list = devices.filter((d) => devFilter === "all" || d.type_guess === devFilter || (devFilter === "host" && ["host", "server"].includes(d.type_guess)) || (devFilter === "router" && d.is_target));
  $("dev-list").innerHTML = list.map((d) => {
    const cls = d.is_target ? "target" : "";
    const svcs = (d.services || []).map((s) => {
      const key = d.ip + ":" + s.port;
      if (!protect) return `<span class="srv-chip">${s.port}/<b>${s.service}</b></span>`;
      const on = protectSel.has(key);
      return `<label class="srv-tick" title="tick to add a policy requirement: ${esc(d.ip)} must stay reachable on ${s.port}/${esc(s.service)}"><input type="checkbox" data-srv="${esc(key)}" ${on ? "checked" : ""}/><span>${s.port}/${esc(s.service)}</span></label>`;
    }).join("");
    const snmp = d.snmp && d.snmp.sysDescr ? `<div class="dev-snmp">SNMP · ${esc(d.snmp.sysName || "")} ${esc(d.snmp.sysDescr).slice(0, 100)}</div>` : "";
    const mac = d.mac ? `${d.mac}` : "no MAC in ARP";
    return `<div class="dev-item clickable ${cls}" data-ip="${esc(d.ip)}">
      <div class="dev-icon" style="background:${tint[d.type_guess] || "none"}">${d.is_target ? `<span class="pulse-dot" title="target"></span>` : deviceIcon(d.type_guess, 26)}</div>
      <div class="dev-body">
        <div class="dev-head"><span class="dev-name">${esc(d.hostname || d.ip)}</span><span class="dev-tag ${d.type_guess}">${d.is_target ? "target " : ""}${d.type_guess}</span></div>
        <div class="dev-meta">${d.ip} <span class="loc">· ${mac} · ${esc(d.vendor)}</span></div>
        ${svcs ? `<div class="dev-srvs">${svcs}</div>` : ""}
        ${snmp}
      </div>
    </div>`;
  }).join("") || `<div class="muted" style="font-size:12px;padding:8px">no systems in this view</div>`;
  if (protect) {
    $("dev-list").querySelectorAll("input[data-srv]").forEach((chk) => {
      chk.addEventListener("change", () => {
        const k = chk.dataset.srv;
        if (chk.checked) protectSel.add(k); else protectSel.delete(k);
        applyProtect();
      });
    });
  }
  $("dev-list").querySelectorAll(".dev-item").forEach((el) => el.addEventListener("click", () => openDeviceByIp(el.dataset.ip)));
}

function wireDevFilters() {
  const bar = $("dev-filters");
  bar.querySelectorAll("button").forEach((b) => b.addEventListener("click", () => {
    bar.querySelectorAll("button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    devFilter = b.dataset.df;
    if (SCAN) renderDevices(SCAN.devices);
  }));
}

/* ---------------- mode ---------------- */
async function resetAll() {
  try {
    NET = await (await fetch("/api/network")).json();
  } catch (e) {
    toast("Reset failed: " + e.message, true);
    return;
  }
  SCAN = null;
  LIVE_NET = null;
  scanByIp = {};
  deviceByZone = {};
  protectSel = new Set();
  recent = [];
  report = null;
  $("recent-wrap").hidden = true;
  $("recent").innerHTML = "";
  $("result").hidden = true;
  $("result").innerHTML = "";
  $("devices-card").hidden = true;
  $("preset").value = "__custom";
  $("preset-desc").textContent = "";
  $("ch-type").value = "add_filter_rule";
  $("intent").value = "";
  $("intent-status").textContent = "Examples: “block ssh from user-pc to app-server” · “allow http from any to app-server” · “port-forward 8080 to app-server:80” · “add route 10.99.0.0/16 via 192.168.1.2 on firewall”.";
  $("f-index").value = "";
  $("f-dport").value = "";
  $("f-src").value = "";
  $("f-dst").value = "";
  $("f-action").value = "permit";
  $("f-proto").value = "tcp";
  $("r-network").value = "";
  $("r-nh").value = "";
  $("r-index").value = "";
  $("dn-public-port").value = "";
  $("dn-private-port").value = "";
  $("dn-index").value = "";
  $("dn-proto").value = "tcp";
  if ($("bgp-neighbor")) $("bgp-neighbor").value = "";
  if ($("bgp-local-as")) $("bgp-local-as").value = "";
  if ($("bgp-remote-as")) $("bgp-remote-as").value = "";
  if ($("bgp-export")) $("bgp-export").value = "";
  if ($("ospf-area")) $("ospf-area").value = "";
  if ($("ospf-network")) $("ospf-network").value = "";
  if ($("dns-zone")) $("dns-zone").value = "";
  if ($("dns-fqdn")) $("dns-fqdn").value = "";
  if ($("dns-type")) $("dns-type").value = "A";
  if ($("dns-value")) $("dns-value").value = "";
  if ($("dns-ttl")) $("dns-ttl").value = "";
  if ($("vlan-iface")) $("vlan-iface").value = "";
  if ($("vlan-id")) $("vlan-id").value = "";
  if ($("vlan-name")) $("vlan-name").value = "";
  updateVisibility();
  await setMode("demo");
  toast("Restarted — network restored to its original state.");
}

async function setMode(m) {
  MODE = m;
  saveMode(m);
  updateModeLabels();
  if (m === "scan" && !LIVE_NET) {
    // try to restore a previous scan
    try {
      const st = await (await fetch("/api/scan")).json();
      if (st.scanned) { await loadLiveModel(); return; }
    } catch (e) {}
    MODE = "demo";
    updateModeLabels();
    toast("No live scan yet — enter a router/server IP above.", true);
  }
  if (m === "agent") {
    await selectActiveOrg();
  }
  renderAll();
  refreshSuggestions();
}

/* ---------------- agent (account) mode ---------------- */
function saveActiveOrg(id) {
  ACTIVE_ORG = id || null;
  try { sessionStorage.setItem("netproof-org", id || ""); } catch (e) {}
}
function resumeActiveOrg() {
  try { return sessionStorage.getItem("netproof-org") || ""; } catch (e) { return ""; }
}

async function loadOrgs() {
  try {
    const r = await (await fetch("/api/orgs")).json();
    ORGS = r.orgs || [];
  } catch (e) {
    ORGS = [];
  }
  const sel = $("agent-org");
  if (!sel) return;
  const cur = sel.value || resumeActiveOrg();
  sel.innerHTML = `<option value="">(create an account below)</option>` +
    ORGS.map((o) => `<option value="${esc(o.id)}">${esc(o.name)}</option>`).join("");
  if (cur && ORGS.some((o) => o.id === cur)) sel.value = cur;
}

function renderAgentPanel() {
  const onboard = $("agent-onboard"), rep = $("agent-report"), tip = $("agent-tip");
  if (!onboard || !rep) return;
  if (!AGENT_NET) { onboard.hidden = true; rep.hidden = true; if (tip) tip.hidden = false; return; }

  if (AGENT_NET.source === "none" || AGENT_NET.onboarding) {
    rep.hidden = true;
    onboard.hidden = false;
    onboard.innerHTML = `
      <div class="onboard-stage">No agent report yet for <b>${esc(AGENT_NET.org || ACTIVE_ORG || "this account")}</b>.</div>
      <div class="onboard-steps">
        <div class="onboard-step"><b>1</b> Copy this account's API key below and store it on the machine inside the network.</div>
        <div class="onboard-step"><b>2</b> Run the agent there (it only talks outbound over HTTPS):</div>
      </div>
      <pre class="agent-cmd">python agent/agent.py --target &lt;router-ip&gt; \\
  --backend http://&lt;this-server&gt;:8000 \\
  --api-key &lt;KEY&gt; [--config-file device-config.json]</pre>
      <p class="muted" style="font-size:12px">The agent discovers the segment, attaches any confirmed device config, and pushes the report to <span class="mono">/api/agent/report</span>. Once it checks in, this panel fills with the network. You can also schedule it with <span class="mono">--interval 900</span>.</p>`;
  } else {
    onboard.hidden = true;
    rep.hidden = false;
    const conf = AGENT_NET.confirmations || {};
    rep.innerHTML = `
      <div class="agent-stats">
        <span><b>${AGENT_NET.scan_summary ? AGENT_NET.scan_summary.devices : (AGENT_NET.devices || []).length}</b> devices</span>
        <span><b>${conf.rules ? conf.rules.confirmed + "/" + conf.rules.inferred : "–/–"}</b> rules conf/infer</span>
        <span><b>${conf.routes ? conf.routes.confirmed + "/" + conf.routes.inferred : "–/–"}</b> routes conf/infer</span>
        <span>report ${esc(AGENT_NET.reported_at || "")}</span>
      </div>
      <p class="muted" style="font-size:12px">Subnet ${esc(String(AGENT_NET.scan_summary && AGENT_NET.scan_summary.subnet || ""))} · target ${esc(String(AGENT_NET.scan_summary && AGENT_NET.scan_summary.target || ""))}. Config-matched entries carry a <span class="src-badge confirmed">CONFIRMED</span> badge in device details.</p>`;
  }
  if (tip) tip.hidden = true;
}

async function selectActiveOrg() {
  await loadOrgs();
  const sel = $("agent-org");
  const id = sel && sel.value ? sel.value : (resumeActiveOrg() || (ORGS.length ? ORGS[0].id : ""));
  if (!id) {
    AGENT_NET = null;
    saveActiveOrg(null);
    renderAgentPanel();
    return;
  }
  saveActiveOrg(id);
  try {
    const r = await fetch("/api/network?org=" + encodeURIComponent(id));
    if (!r.ok) throw new Error((await r.json()).detail || "no account data");
    AGENT_NET = await r.json();
    deviceByZone = {};
    scanByIp = {};
    (AGENT_NET.scan_devices || []).forEach((d) => { scanByIp[d.ip] = d; });
    (AGENT_NET.devices || []).forEach((d) => {
      d.interfaces && d.interfaces.forEach((i) => {
        if (i.ip) deviceByZone[i.ip.replace(/\/.*/, "")] = d.name;
      });
    });
  } catch (e) {
    AGENT_NET = null;
  }
  if (sel && id) sel.value = id;
  renderAgentPanel();
}

async function createOrg() {
  const box = $("agent-create");
  const name = ($("agent-new-name").value || "").trim();
  if (!name) { toast("Name the account first.", true); return; }
  const btn = $("agent-create-go");
  btn.disabled = true; btn.textContent = "…";
  try {
    const res = await fetch("/api/orgs", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || "create failed");
    const org = (await res.json()).org;
    await loadOrgs();
    const sel = $("agent-org");
    if (sel) { sel.value = org.id; }
    saveActiveOrg(org.id);
    AGENT_NET = null;
    renderAgentPanel();
    toast(`Account "${org.name}" created — copy its API key now (shown only once).`);
    showKeyOnce(org.api_key);
  } catch (e) {
    toast("Create failed: " + e.message, true);
  }
  btn.disabled = false; btn.textContent = "Create";
}

function showKeyOnce(key) {
  const onboard = $("agent-onboard");
  if (!onboard) return;
  onboard.hidden = false;
  onboard.innerHTML = `
    <div class="onboard-stage">Account created + API key generated (shown once):</div>
    <pre class="agent-key">${esc(key)}</pre>
    <button type="button" class="btn btn-secondary" id="agent-copy-key">⧉ Copy key</button>
    <p class="muted" style="font-size:12px">Store it in the agent install inside the network. Paste the config snapshot path with <span class="mono">--config-file</span> to get <span class="src-badge confirmed">CONFIRMED</span> labels.</p>`;
  const cp = $("agent-copy-key");
  if (cp) cp.addEventListener("click", () => {
    try { navigator.clipboard.writeText(key); toast("API key copied"); }
    catch (e) { toast("Copy failed — select the key text manually.", true); }
  });
}

/* ---------------- change builder ---------------- */
function buildPresets() {
  const sel = $("preset");
  (NET.presets || []).forEach((p) => {
    const o = document.createElement("option");
    o.value = p.id; o.textContent = p.label; sel.appendChild(o);
  });
}

function applyPresetValue() {
  const id = $("preset").value;
  const p = (NET.presets || []).find((x) => x.id === id);
  if (!p) return;
  loadChange(p.change);
  const expect = p.expect === "blocked" ? "should BLOCK (unsafe)" : p.expect === "warning" ? "should WARN (review)" : "should PASS";
  $("preset-desc").textContent = `Expectation: ${expect}. ${p.description}`;
  toast(`Loaded “${p.label}”`);
}

function loadChange(change) {
  $("ch-type").value = change.type;
  const t = change.type;
  if (t.includes("_filter_rule")) {
    $("f-filter").value = change.filter || "";
    $("f-index").value = change.at_index ?? change.index ?? 0;
    if (change.rule) {
      $("f-action").value = change.rule.action || "permit";
      $("f-proto").value = change.rule.proto || "any";
      $("f-src").value = change.rule.src || "";
      $("f-dst").value = change.rule.dst || "";
      $("f-dport").value = change.rule.dport ?? "";
    }
  } else if (t === "add_dst_nat") {
    $("dn-device").value = change.device || "";
    $("dn-public-port").value = change.dst_nat.public_port ?? "";
    $("dn-private-ip").value = change.dst_nat.private_ip || "";
    $("dn-private-port").value = change.dst_nat.private_port ?? "";
    $("dn-proto").value = change.dst_nat.proto || "tcp";
  } else if (t === "remove_dst_nat") {
    $("dn-device").value = change.device || "";
    $("dn-index").value = change.index ?? change.at_index ?? 0;
  } else if (t === "add_bgp_peer") {
    $("bgp-device").value = change.device || "";
    if (change.peer) {
      $("bgp-neighbor").value = change.peer.neighbor || "";
      $("bgp-local-as").value = change.peer.local_as ?? "";
      $("bgp-remote-as").value = change.peer.remote_as ?? "";
      $("bgp-export").value = (change.peer.export_prefixes && change.peer.export_prefixes[0]) || "";
    }
  } else if (t === "add_ospf_network") {
    $("ospf-device").value = change.device || "";
    $("ospf-area").value = change.area_id ?? "";
    $("ospf-network").value = change.network || "";
  } else if (t === "add_dns_record") {
    $("dns-device").value = change.device || "";
    if (change.record) {
      $("dns-zone").value = change.record.zone || "";
      $("dns-fqdn").value = change.record.fqdn || "";
      $("dns-type").value = change.record.type || "A";
      $("dns-value").value = change.record.value || "";
      $("dns-ttl").value = change.record.ttl ?? "";
    }
  } else if (t === "add_vlan_assignment") {
    $("vlan-device").value = change.device || "";
    if (change.vlan) {
      $("vlan-iface").value = change.vlan.iface || "";
      $("vlan-id").value = change.vlan.vlan_id ?? "";
      $("vlan-name").value = change.vlan.name || "";
    }
  } else {
    $("r-device").value = change.device || "";
    if (t === "add_route") {
      $("r-network").value = change.route.network || "";
      $("r-nh").value = change.route.next_hop || "";
    } else {
      $("r-index").value = change.index ?? 0;
    }
  }
  updateVisibility();
  syncFields();
}

function collectChange() {
  const t = $("ch-type").value;
  if (t.includes("_filter_rule")) {
    const change = { type: t, filter: $("f-filter").value, at_index: num($("f-index")) };
    if (t !== "remove_filter_rule") {
      const rule = { action: $("f-action").value, proto: $("f-proto").value, src: $("f-src").value || "any", dst: $("f-dst").value || "any" };
      const p = num($("f-dport"));
      if (p) rule.dport = p;
      change.rule = rule;
    }
    return change;
  }
  if (t === "add_route") {
    return { type: t, device: $("r-device").value, route: { network: $("r-network").value, next_hop: $("r-nh").value } };
  }
  if (t === "add_dst_nat") {
    return {
      type: t,
      device: $("dn-device").value,
      dst_nat: {
        public_ip: "",
        public_port: num($("dn-public-port")),
        private_ip: $("dn-private-ip").value,
        private_port: num($("dn-private-port")),
        proto: $("dn-proto").value,
      },
    };
  }
  if (t === "remove_dst_nat") {
    return { type: t, device: $("dn-device").value, index: num($("dn-index")) };
  }
  if (t === "add_bgp_peer") {
    const p = {};
    p.neighbor = $("bgp-neighbor").value.trim();
    p.local_as = parseInt($("bgp-local-as").value) || 0;
    p.remote_as = parseInt($("bgp-remote-as").value) || 0;
    const exp = $("bgp-export").value.trim();
    if (exp) p.export_prefixes = [exp];
    return { type: t, device: $("bgp-device").value, peer: p };
  }
  if (t === "add_ospf_network") {
    return { type: t, device: $("ospf-device").value, area_id: parseInt($("ospf-area").value) || 0, network: $("ospf-network").value.trim() };
  }
  if (t === "add_dns_record") {
    return { type: t, device: $("dns-device").value, record: { zone: $("dns-zone").value.trim(), fqdn: $("dns-fqdn").value.trim(), type: $("dns-type").value, value: $("dns-value").value.trim(), ttl: parseInt($("dns-ttl").value) || 300 } };
  }
  if (t === "add_vlan_assignment") {
    return { type: t, device: $("vlan-device").value, vlan: { iface: $("vlan-iface").value.trim(), vlan_id: parseInt($("vlan-id").value) || 0, name: $("vlan-name").value.trim() } };
  }
  return { type: t, device: $("r-device").value, index: num($("r-index")) };
}

function fillPolicySelects() {
  const m = model();
  const filters = m.filters || [];
  const fsel = $("f-filter");
  fsel.innerHTML = "";
  if (!filters.length) fsel.innerHTML = `<option value="">(no policy points)</option>`;
  filters.forEach((f) => {
    const o = document.createElement("option");
    o.value = f.name; o.textContent = `${f.name}  ·  default ${f.default}`;
    fsel.appendChild(o);
  });

  const option = (sel, value, text, title) => {
    const o = document.createElement("option");
    o.value = value; o.textContent = text;
    if (title) o.title = title;
    sel.appendChild(o);
  };
  const routeDevs = (m.devices || []).filter((d) => ["router", "switch"].includes(d.type) && d.routes.length);
  const rsel = $("r-device");
  rsel.innerHTML = "";
  routeDevs.slice().sort(devOrder).forEach((d) => option(rsel, d.name, devLabel(d) + "  ·  routing device", devTooltip(d)));

  const natDevs = (m.devices || []).filter((d) => d.type === "router" || d.type === "firewall");
  const dsel = $("dn-device");
  dsel.innerHTML = "";
  if (!natDevs.length) dsel.innerHTML = `<option value="">(no router/firewall)</option>`;
  natDevs.slice().sort(devOrder).forEach((d) => option(dsel, d.name, devLabel(d) + "  ·  router/firewall", devTooltip(d)));

  const targets = (m.devices || []).filter((d) => ["host", "server", "printer", "switch"].includes(d.type) && d.interfaces && d.interfaces.some((i) => i.ip));
  const psel = $("dn-private-ip");
  psel.innerHTML = "";
  if (!targets.length) psel.innerHTML = `<option value="">(no forward targets)</option>`;
  targets.slice().sort(devOrder).forEach((d) => {
    const ip = d.interfaces.find((i) => i.ip).ip.replace(/\/.*/, "");
    option(psel, ip, devLabel(d) + "  ·  forward target", devTooltip(d));
  });

  const bgpDevs = (m.devices || []).filter((d) => d.type !== "host");
  const bsel = $("bgp-device");
  if (bsel) {
    bsel.innerHTML = "";
    if (!bgpDevs.length) bsel.innerHTML = `<option value="">(no eligible device)</option>`;
    bgpDevs.slice().sort(devOrder).forEach((d) => option(bsel, d.name, devLabel(d) + "  ·  " + d.type, devTooltip(d)));
  }

  const ospfDevs = (m.devices || []).filter((d) => d.type !== "host");
  const osel = $("ospf-device");
  if (osel) {
    osel.innerHTML = "";
    if (!ospfDevs.length) osel.innerHTML = `<option value="">(no eligible device)</option>`;
    ospfDevs.slice().sort(devOrder).forEach((d) => option(osel, d.name, devLabel(d) + "  ·  " + d.type, devTooltip(d)));
  }

  const dnsDevs = (m.devices || []);
  const dnsCapable = dnsDevs.filter((d) => d.type === "server" || d.type === "router");
  const dnsOther = dnsDevs.filter((d) => d.type !== "server" && d.type !== "router");
  const dsel2 = $("dns-device");
  if (dsel2) {
    dsel2.innerHTML = "";
    if (!dnsDevs.length) dsel2.innerHTML = `<option value="">(no devices)</option>`;
    dnsCapable.slice().sort(devOrder).forEach((d) => option(dsel2, d.name, devLabel(d) + "  ·  " + d.type, devTooltip(d)));
    dnsOther.slice().sort(devOrder).forEach((d) => option(dsel2, d.name, devLabel(d) + "  ·  " + d.type, devTooltip(d)));
  }

  const vlanDevs = (m.devices || []).filter((d) => d.type !== "host");
  const vsel = $("vlan-device");
  if (vsel) {
    vsel.innerHTML = "";
    if (!vlanDevs.length) vsel.innerHTML = `<option value="">(no eligible device)</option>`;
    vlanDevs.slice().sort(devOrder).forEach((d) => option(vsel, d.name, devLabel(d) + "  ·  " + d.type, devTooltip(d)));
  }
}

/* ---------------- plain-English behavior guide ---------------- */

/* Shown the moment you focus each box: "what does this box do?" */
const FIELD_BLURBS = {
  "ch-type": "What kind of change you want to try out. The rest of the form rearranges to fit. Nothing touches the real network — the referee only simulates the change on a copy of it.",
  "f-filter": "The policy point where the referee installs your rule: the device and its network side the traffic actually crosses (e.g. router-lan-in = rules for traffic entering the LAN interface). A \u201cdefault deny\u201d list blocks everything that matches no rule; \u201cdefault permit\u201d lets it through unless a rule says deny.",
  "f-index": "Position of your rule in the list \u2014 0 = very top. Rules are read top-down and the first match wins, so a deny here can outrank a lower permit. Only the Add / Replace / Remove rule types use it.",
  "f-action": "permit = allow this traffic, deny = drop it. Deny is what outlaws a connection; permit is what re-opens one the policy would otherwise block.",
  "f-proto": "Which protocol this rule cares about: tcp / udp (they use ports), icmp (ping), or any (everything, ports ignored). The port box only appears for tcp.",
  "f-src": "Who sends the traffic this rule matches: one device's IP, a whole subnet like 192.168.31.0/24, or any = everyone. Use the suggestions that appear as you type.",
  "f-dst": "Who receives the traffic \u2014 who this rule protects. Same formats as Source.",
  "f-dport": "The destination port the rule is about. Common ones: 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 445 Windows file sharing (SMB), 3389 Remote Desktop.",
  "r-device": "Which router (or layer-3 switch) owns the routing table you want to edit. Only devices that actually have routes show up.",
  "r-index": "Which route (0 = first one) to delete from that table. Deleting the default route orphans everything that has no other path \u2014 the referee flags those flows as lost.",
  "r-network": "The subnet the new route points at: 0.0.0.0/0 means \u201ceverything\u201d (the default route), or a specific 192.168.x.0/24 to steer just that network.",
  "r-nh": "Which router IP next gets handed the packets for that subnet. It must be reachable from the chosen router's own networks.",
  "dn-device": "The router/firewall whose PUBLIC side offers the forwarded port \u2014 the front door outsiders dial.",
  "dn-index": "Which existing forward (0 = first one) to delete. Anything that depended on that forward becomes unreachable and shows as a CRITICAL finding.",
  "dn-public-port": "The port internet users type on your public IP, e.g. 8080. Traffic arriving here gets translated and sent inward.",
  "dn-private-ip": "The internal device (by its IP) that should receive the forwarded traffic. Pick from the list \u2014 it shows every host/server with its address.",
  "dn-private-port": "The port on that internal device the traffic is translated to \u2014 usually the same as the public port (8080 → 80 is the classic case).",
  "dn-proto": "Protocol for the forward \u2014 almost always tcp (the port guidance above applies).",
};

const HINT_FIELDS = ["ch-type", "f-filter", "f-index", "f-action", "f-proto", "f-src", "f-dst", "f-dport",
  "r-device", "r-index", "r-network", "r-nh", "dn-device", "dn-index",
  "dn-public-port", "dn-private-ip", "dn-private-port", "dn-proto"];
let hintFocusId = null;

function explainChange() {
  const t = fieldQ("ch-type") || "add_filter_rule";
  const where = fieldQ("f-filter");
  const pol = where && (model().filters || []).find((f) => f.name === where);
  const defPol = pol ? (pol.default === "deny" ? "blocks everything not explicitly allowed" : "lets everything through unless a rule denies it") : "";
  const tool = "The referee copies your network, applies this change on the copy, then re-checks every flow (zone paths + reachability expectations) and flags anything that breaks or becomes reachable.";

  if (t === "add_filter_rule") {
    const act = fieldQ("f-action") || "permit";
    const proto = fieldQ("f-proto") || "any";
    const src = fieldQ("f-src"); const dst = fieldQ("f-dst"); const port = fieldQ("f-dport");
    const ruleTxt = `${act} ${proto === "tcp" && port ? proto + "/" + port : proto} ${src || "any"} → ${dst || "any"}`;
    const pos = num($("f-index"));
    const def = defPol || `current default for ${where || "this policy point"}`;
    return `You're asking to insert the rule “<b>${ruleTxt}</b>” at position <b>${pos}</b> in <b>${where || "a policy point"}</b> (which currently ${def}).
      ${tool}
      <b>Expect:</b> traffic fitting this rule ${act === "deny"
        ? "gets dropped (shows red ✕ on the device that blocks it) — and any reachability expectation that depended on this path turns into a CRITICAL finding"
        : "gets allowed through (green ✓) — useful when the policy's default would otherwise block it"}.`;
  }

  if (t === "replace_filter_rule") {
    const act = fieldQ("f-action") || "permit";
    const proto = fieldQ("f-proto") || "any";
    const src = fieldQ("f-src"); const dst = fieldQ("f-dst"); const port = fieldQ("f-dport");
    const pos = num($("f-index"));
    const old = ((pol && pol.rules) || []);
    const was = old[Math.min(pos, old.length - 1)];
    const wasTxt = was ? `${was.action} ${was.proto}${was.dport ? "/" + was.dport : ""} ${was.src} → ${was.dst}` : "[no such rule]";
    const newTxt = `${act} ${proto === "tcp" && port ? proto + "/" + port : proto} ${src || "any"} → ${dst || "any"}`;
    return `You're replacing the rule at position <b>${pos}</b> in <b>${where || "a policy point"}</b> — was “<b>${wasTxt}</b>”, becomes “<b>${newTxt}</b>”.
      ${tool}
      <b>Expect:</b> traffic matching the old rule changes behavior — if the old rule was the only thing permitting a path, replacing it with a deny flags a CRITICAL loss; replacing a deny with a permit re-opens previously blocked access (the referee marks which hosts are newly reachable).`;
  }

  if (t === "remove_filter_rule") {
    const pos = num($("f-index"));
    const old = ((pol && pol.rules) || []);
    const was = old[Math.min(pos, old.length - 1)];
    const wasTxt = was ? `${was.action} ${was.proto}${was.dport ? "/" + was.dport : ""} ${was.src} → ${was.dst}` : "[no such rule]";
    return `You're deleting rule #<b>${pos}</b> (“<b>${wasTxt}</b>”) from <b>${where || "a policy point"}</b>.
      ${tool}
      <b>Expect:</b> if that rule was the one allowing reachability (or was the guard blocking a dangerous path), the referee flips it — a removed allow shows CRITICAL connectivity loss, a removed deny shows newly-exposed services that previously were blocked.`;
  }

  if (t === "add_route") {
    const dev = fieldQ("r-device"); const net = fieldQ("r-network") || "0.0.0.0/0"; const nh = fieldQ("r-nh");
    let extra = "";
    if (net === "0.0.0.0/0") extra = "This is the DEFAULT route — every packet with no more-specific path follows it. Re-pointing it re-routes the whole network.";
    else extra = "Only packets destined for that subnet are affected; everything else keeps its current path.";
    return `You're adding the route <b>${net} via ${nh}</b> to <b>${dev || "a router"}</b>. ${extra}
      ${tool}
      <b>Expect:</b> packets for that subnet now leave via the new next hop — if that hop is unreachable, flows that used this route turn up as lost (CRITICAL); if it leads to the internet, anything with no other path gets its traffic redirected there.`;
  }

  if (t === "remove_route") {
    const dev = fieldQ("r-device"); const idx = num($("r-index"));
    return `You're deleting route #<b>${idx}</b> from ${dev || "a router"}'s table.
      ${tool}
      <b>Expect:</b> packets that used that route fall back to the remaining table (next-most-specific route, or the default) — if nothing is left, that traffic becomes undeliverable and the referee flags a CRITICAL outage.`;
  }

  if (t === "add_dst_nat") {
    const dev = fieldQ("dn-device"); const pub = fieldQ("dn-public-port"); const ip = fieldQ("dn-private-ip"); const priv = fieldQ("dn-private-port");
    return `You're opening a door on the internet: <b>` +
      (dev ? `${dev} ` : "a router/firewall ") +
      `public port <b>${pub}</b> → forwards to <b>${ip || "a host"}:${priv || pub}</b>.
      ${tool}
      <b>Expect:</b> an inbound flow (internet → public port) now resolves to that internal host. If the device's policy doesn't permit that inward path, the referee still creates the forward but flags it <b>WARN — added but unreachable</b>, exactly like a real firewall config that asks you to add an allow rule too.`;
  }

  if (t === "remove_dst_nat") {
    const dev = fieldQ("dn-device"); const idx = num($("dn-index"));
    return `You're deleting forward #<b>${idx}</b> from ${dev || "a router/firewall"}.
      ${tool}
      <b>Expect:</b> any service that lived behind that forward (reachability expectation or an inbound zone path) now fails — the referee reports it as a <b>CRITICAL</b> connectivity loss, so you can see exactly which public service disappears.`;
  }

  return "Choose a change type, fill the fields, then press Run validation.";
}

function fieldQ(id) {
  const el = $(id);
  return el ? String(el.value ?? "").trim() : "";
}

function refreshHint() {
  const box = $("change-hint");
  if (!box) return;
  if (hintFocusId && FIELD_BLURBS[hintFocusId]) {
    const el = $(hintFocusId);
    const lbl = el && el.previousElementSibling && el.previousElementSibling.tagName === "LABEL"
      ? el.previousElementSibling.textContent : "";
    box.innerHTML = `<b>${esc(lbl || hintFocusId)}</b> — ${FIELD_BLURBS[hintFocusId]}`;
    return;
  }
  box.innerHTML = explainChange();
}
    function wireForm() {
  $("preset").addEventListener("change", () => {
    if ($("preset").value === "__custom") { $("preset-desc").textContent = ""; return; }
    applyPresetValue();
  });
  $("ch-type").addEventListener("change", updateVisibility);
  $("f-proto").addEventListener("change", updateVisibility);
  $("f-filter").addEventListener("change", syncFields);
  HINT_FIELDS.forEach((id) => {
    const el = $(id);
    if (!el) return;
    el.addEventListener("focusin", () => { hintFocusId = id; refreshHint(); });
    el.addEventListener("focusout", () => { hintFocusId = null; refreshHint(); });
    el.addEventListener("change", refreshHint);
    el.addEventListener("input", refreshHint);
  });
  $("run").addEventListener("click", run);
  $("intent-btn").addEventListener("click", () => parseIntentFromBox());
  $("reset-btn").addEventListener("click", resetAll);
  document.querySelectorAll("#mode-switch button").forEach((b) =>
    b.addEventListener("click", () => setMode(b.dataset.mode)));
  wireAgent();
  wireDevFilters();
  document.addEventListener("keydown", (e) => {
    if (e.target && $("intent") === e.target && e.key === "Enter") {
      e.preventDefault();
      parseIntentFromBox();
      return;
    }
    if (e.key === "Enter" && e.target && (e.target.tagName === "INPUT" || e.target.tagName === "SELECT" || e.target.tagName === "TEXTAREA")) {
      e.preventDefault();
      if ($("scan-target") === e.target || $("scan-community") === e.target) { $("scan-btn").click(); return; }
      run();
    }
  });
}

async function parseIntentFromBox() {
  const text = $("intent").value.trim();
  if (!text) { toast("Type the change you want, in words.", true); return; }
  const btn = $("intent-btn");
  const status = $("intent-status");
  btn.disabled = true;
  btn.textContent = "…";
  status.textContent = "Parsing intent against the current model…";
  try {
    const res = await fetch("/api/intent", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text,
        mode: MODE,
        account: MODE === "agent" ? ACTIVE_ORG : null,
      }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || "couldn't parse");
    const parsed = await res.json();
    loadChange(parsed.change);
    $("preset").value = "__custom";
    $("preset-desc").textContent = "";
    const c = Math.round(parsed.confidence * 100);
    status.innerHTML = `Parsed at ${c}% confidence — <span class="mono">${esc(parsed.change.type)}</span>: ${esc(parsed.description)}. Review the fields below, then run validation.`;
    if (parsed.confirmation) {
      status.innerHTML = `<strong>Confirmed:</strong> ${esc(parsed.confirmation)} <span class="dim">(confidence: ${c}%)</span> — <span class="mono">${esc(parsed.change.type)}</span>: ${esc(parsed.description)}. Review the fields below, then run validation.`;
    }
    toast(`Intent parsed (${c}% confidence)`);
  } catch (e) {
    status.textContent = "";
    toast("Intent failed: " + e.message, true);
  }
  btn.disabled = false;
  btn.textContent = "Parse";
}

function wireStatic() {
  // never let the browser's own autocomplete memory leak stale IPs from other
  // networks into our suggestion fields — it directly caused the repeated /
  // wrong ".0" and old-device entries the user saw.
  ["scan-target", "scan-community", "f-src", "f-dst", "r-network", "r-nh"].forEach(wipeBrowserMemory);
}

function wireAgent() {
  const sel = $("agent-org");
  const btn = $("agent-new"), go = $("agent-create-go");
  if (sel) sel.addEventListener("change", () => { saveActiveOrg(sel.value); selectActiveOrg().then(() => { renderAll(); refreshSuggestions(); }); });
  if (btn) btn.addEventListener("click", () => { const c = $("agent-create"); if (c) c.hidden = !c.hidden; });
  if (go) go.addEventListener("click", createOrg);
}

function updateVisibility() {
  const t = $("ch-type").value;
  document.querySelectorAll("[data-for]").forEach((el) => {
    const groups = el.getAttribute("data-for").split(" ");
    el.hidden = !groups.includes(t);
  });
  const dh = document.querySelector("[data-dport]");
  if (dh) dh.hidden = !(t.includes("_filter_rule") && $("f-proto").value === "tcp");
  refreshHint();
}

/* A live scan has no BGP/OSPF config, DNS zone or switchport VLANs to change —
   offering those change types on a discovered LAN only produces confusing
   control-plane noise. Keep them for the Demo model and hide them in scan/agent. */
const DEMO_ONLY_CHANGE_TYPES = ["add_bgp_peer", "add_ospf_network", "add_dns_record", "add_vlan_assignment"];

function applyChangeTypeFilter() {
  const sel = $("ch-type");
  if (!sel) return;
  const hide = (MODE === "scan" || MODE === "agent") ? DEMO_ONLY_CHANGE_TYPES : [];
  Array.from(sel.options).forEach((opt) => { opt.hidden = hide.includes(opt.value); });
  let cur = sel.value;
  if (hide.includes(cur)) cur = "add_filter_rule";
  sel.value = cur;
  updateVisibility();
}

function syncFields() {
  const t = $("ch-type").value;
  if (!t.includes("_filter_rule")) return;
  const rule = (model().filters || []).find((f) => f.name === $("f-filter").value);
  if (rule && t === "replace_filter_rule" && rule.rules.length) {
    const r = rule.rules[Math.min(num($("f-index")), rule.rules.length - 1)];
    if (r) {
      $("f-action").value = r.action; $("f-proto").value = r.proto;
      $("f-src").value = r.src; $("f-dst").value = r.dst;
      $("f-dport").value = r.dport ?? "";
    }
  }
}

function num(v) { const n = parseInt(v.value, 10); return Number.isFinite(n) ? n : 0; }

/* ---------------- run / validate ---------------- */
async function run() {
  const btn = $("run");
  const change = collectChange();
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span>&nbsp; Reasoning the change…`;
  try {
    const res = await fetch("/api/validate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        change,
        mode: MODE,
        account: MODE === "agent" ? ACTIVE_ORG : null,
        org: MODE === "agent" ? ACTIVE_ORG || "default" : "default",
      }),
    });
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    report = await res.json();
    report.change = change;
    fetchGuardrails(change).then((checks) => { report.guardrails = checks; renderGuardrails(checks); });
  } catch (e) {
    toast("Validation failed: " + e.message, true);
    btn.disabled = false;
    btn.innerHTML = `<span>Run validation</span>`;
    return;
  }
  btn.disabled = false;
  btn.innerHTML = `<span>Run validation</span><svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12h14M13 6l6 6-6 6"/></svg>`;
  renderResult(report);
  renderRequirements(model().requirements, report);
  recordRecent(report);
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
  // scroll map into view and start the live-flow overlay
  const topoCard = document.querySelector(".topo-card");
  if (topoCard) topoCard.scrollIntoView({ behavior: "smooth", block: "nearest" });
  startTopoFlowOverlay(report);
}

async function fetchGuardrails(change) {
  try {
    const res = await fetch("/api/guardrails", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        change,
        mode: MODE,
        account: MODE === "agent" ? ACTIVE_ORG : null,
        org: MODE === "agent" ? ACTIVE_ORG || "default" : "default",
      }),
    });
    return res.ok ? (await res.json()).checks || [] : [];
  } catch (e) {
    return [];
  }
}

function recordRecent(report) {
  recent.unshift(report);
  if (recent.length > 6) recent.pop();
  $("recent-wrap").hidden = false;
  $("recent").innerHTML = recent.map((r, i) =>
    `<span class="recent-item ${r.summary.verdict}" data-i="${i}"><span class="b"></span>${esc(describeChange(r.change))}</span>`
  ).join("");
  $("recent").querySelectorAll(".recent-item").forEach((el) => el.addEventListener("click", () => renderResult(recent[+el.dataset.i])));
}

function describeChange(c) {
  switch (c.type) {
    case "add_filter_rule": return `add ${c.rule ? c.rule.action + " " + c.rule.proto : "?"} on ${c.filter}`;
    case "remove_filter_rule": return `remove rule #${c.at_index} on ${c.filter}`;
    case "replace_filter_rule": return `replace rule #${c.at_index} on ${c.filter}`;
    case "add_route": return `add ${c.route.network} via ${c.route.next_hop} on ${c.device}`;
    case "remove_route": return `remove route #${c.index} on ${c.device}`;
    case "add_dst_nat": {
      const r = c.dst_nat || {};
      return `port-forward :${r.public_port} → ${r.private_ip}:${r.private_port} on ${c.device}`;
    }
    case "remove_dst_nat": return `remove forward #${c.index} on ${c.device}`;
    case "add_bgp_peer": return `add BGP peer ${c.peer ? c.peer.neighbor : "?"} (AS${c.peer ? c.peer.remote_as : "?"}) on ${c.device}`;
    case "add_ospf_network": return `advertise ${c.network} in OSPF area ${c.area_id} on ${c.device}`;
    case "add_dns_record": return `add DNS ${c.record ? c.record.type : "?"} ${c.record ? c.record.fqdn : "?"} on ${c.device}`;
    case "add_vlan_assignment": return `assign VLAN ${c.vlan ? c.vlan.vlan_id : "?"} ${c.vlan ? c.vlan.name : ""} on ${c.device}`;
    default: return c.type;
  }
}

/* ---------------- result ---------------- */
function renderResult(report) {
  const box = $("result");
  box.hidden = false;
  box.className = "card result " + report.summary.verdict;
  box.innerHTML = "";
  const s = report.summary;
  const verdictLabel = s.verdict === "pass" ? "Safe to apply" : s.verdict === "warn" ? "Review before apply" : "Block this change";

  const acts = document.createElement("div");
  acts.className = "result-acts";
  acts.innerHTML = `<span class="acts-meta mono">referee test · ${esc(describeChange(report.change))}</span>
    <button type="button" class="btn btn-secondary" id="export-btn" title="Download the full validation report (JSON) for the audit trail">⬇ Export report</button>`;
  box.appendChild(acts);
  acts.querySelector("#export-btn").addEventListener("click", () => exportReport(report));

  const hero = document.createElement("div");
  hero.className = "result-hero";
  hero.innerHTML = `
    <div class="ring"><svg width="104" height="104" viewBox="0 0 104 104">
      <circle class="track" cx="52" cy="52" r="45" fill="none" stroke-width="7"/>
      <circle class="fill" cx="52" cy="52" r="45" fill="none" stroke-width="7"
        stroke="var(${s.verdict === "pass" ? "--pass" : s.verdict === "warn" ? "--warn" : "--danger"})"
        stroke-dasharray="${2 * Math.PI * 45}" stroke-dashoffset="${2 * Math.PI * 45}"/>
    </svg><div class="score"><b>${s.trust_score}</b><span>trust</span></div></div>
    <div class="verdict-zone">
      <div class="verdict-tag-line"><span class="verdict-badge">${verdictLabel}</span>
        <span class="mono dim">${s.blocked} critical · ${s.warnings} warnings · ${s.info} info</span></div>
      ${report.summary.guardrail_block ? `<p class="verdict-sub" style="color:var(--danger);font-weight:600">Guardrail override — engine verdict <span class="mono">${esc(report.summary.engine_verdict || "?")}</span> (${report.summary.engine_score ?? "?"} trust) was overridden to block by policy guardrails.</p>` : ""}
      <p class="verdict-sub">${esc(describeChange(report.change))} — verified over <span class="mono">${s.flows_checked}</span> flows.</p>
      <p class="verdict-sub" style="color:${s.verdict === "pass" ? "var(--pass)" : s.verdict === "warn" ? "var(--warn)" : "var(--danger)"}">${s.verdict === "pass" ? "Behavior-preserving for every checked flow." : s.blocked ? "Connectivity or policy is broken for the flows below." : "New exposure needs human confirmation."}</p>
    </div>`;
  box.appendChild(hero);

  box.appendChild(buildSimPanel(report));

  const guards = document.createElement("div");
  guards.className = "guard-chips";
  guards.id = "guard-chips";
  guards.innerHTML = `<span class="guard-chip pass">policy pre-flight · no guardrails tripped</span>`;
  box.appendChild(guards);

  const tabs = document.createElement("div");
  tabs.className = "result-tabs";
  const tF = document.createElement("button"); tF.className = "tab active"; tF.dataset.tab = "findings";
  tF.innerHTML = `Findings<span class="cnt">${report.findings.length}</span>`;
  const tM = document.createElement("button"); tM.className = "tab"; tM.dataset.tab = "matrix";
  tM.innerHTML = `Zone reachability<span class="cnt">${Object.keys(report.matrix).length}</span>`;
  tabs.appendChild(tF); tabs.appendChild(tM);
  if (report.proposed_diff) {
    const tD = document.createElement("button"); tD.className = "tab"; tD.dataset.tab = "diff";
    tD.innerHTML = `Diff`;
    tabs.appendChild(tD);
  }
  box.appendChild(tabs);

  const body = document.createElement("div");
  body.className = "result-body";
  const rF = renderFindings(report.findings);
  const rM = renderMatrix(report);
  const rR = renderReplay(report);
  const rD = renderDiff(report);
  body.appendChild(rF); body.appendChild(rM); body.appendChild(rR);
  if (rD) body.appendChild(rD);
  box.appendChild(body);

  const prov = document.createElement("div");
  prov.className = "prov mono";
  const p = report.provenance || {};
  prov.innerHTML = `<span>${esc(p.engine || "netproof")} v${esc(p.engine_version || "?")} · ${esc(p.network || report.network || "")} · ${esc((p.model_source && p.model_source.mode) || MODE)}${p.model_source && p.model_source.subnet ? " · " + esc(p.model_source.subnet) : ""}</span>
    <span>${esc((p.validated_at || "").replace("T", " "))} · fingerprint ${esc(p.change_fingerprint || "—")}</span>
    <span>✅ dry run — baseline untouched, real network never modified</span>`;
  const aud = report.audit || {};
  if (aud.verdict_id) {
    prov.innerHTML += ` · verdict <span class="mono">${esc(aud.verdict_id)}</span>`;
  }
  box.appendChild(prov);

  if (aud.export_endpoint) {
    const expLink = document.createElement("a");
    expLink.href = aud.export_endpoint;
    expLink.textContent = "Export JSON artifact";
    expLink.className = "btn btn-secondary";
    expLink.style.cssText = "padding:4px 12px;font-size:11px;text-decoration:none;margin-left:8px";
    box.appendChild(expLink);
  }
  if (aud.replay_endpoint) {
    const repLink = document.createElement("a");
    repLink.href = "#";
    repLink.textContent = "Replay (prove determinism)";
    repLink.className = "btn btn-secondary";
    repLink.style.cssText = "padding:4px 12px;font-size:11px;text-decoration:none;margin-left:8px";
    repLink.addEventListener("click", async (e) => {
      e.preventDefault();
      try {
        const res = await fetch(aud.replay_endpoint, { method: "POST" });
        const data = await res.json();
        toast(data.deterministic ? "✔ Deterministic — replayed verdict matches exactly." : "Non-deterministic — replayed verdict differs.");
      } catch (err) { toast("Replay failed: " + err.message, true); }
    });
    box.appendChild(repLink);
  }

  if (report.guardrails && report.guardrails.length) renderGuardrails(report.guardrails);

  tabs.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
    tabs.querySelectorAll(".tab").forEach((x) => x.classList.remove("active"));
    t.classList.add("active");
    body.querySelectorAll(".tab-zone").forEach((z) => (z.hidden = z.dataset.zone !== t.dataset.tab));
  }));
  body.querySelectorAll(".tab-zone").forEach((z) => (z.hidden = z.dataset.zone !== "findings"));

  requestAnimationFrame(() => {
    const fill = document.querySelector(".ring .fill");
    if (fill) fill.style.strokeDashoffset = `${2 * Math.PI * 45 * (1 - s.trust_score / 100)}`;
  });

  const sim = $("sim-panel");
  if (sim) setTimeout(() => {
    if ((sim._massSrcs || 0) >= 2) { runMassSim(sim); return; }
    const flows = sim._flows || [];
    const rank = (f) => (f.after && f.after.reachable === false) ? 0
      : (hasPath(f.after) || hasPath(f.before)) ? 1 : 2;
    let bestIdx = -1, bestRank = 2;
    flows.forEach((f, i) => {
      const r = rank(f);
      if (r < bestRank) { bestRank = r; bestIdx = i; }
    });
    if (bestIdx >= 0) startSim(sim, bestIdx);
  }, 550);
}

function renderGuardrails(checks) {
  const chips = $("guard-chips");
  if (!chips || !report) return;
  if (!checks || !checks.length) {
    chips.innerHTML = `<span class="guard-chip pass">policy pre-flight · no guardrails tripped</span>`;
    return;
  }
  const order = { critical: 0, warning: 1, info: 2 };
  const sorted = checks.slice().sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
  chips.innerHTML = sorted.map((c) =>
    `<span class="guard-chip ${c.severity}" title="${esc(c.message)}">${esc(c.title)}</span>`
  ).join("");
}

function exportReport(report) {
  const payload = {
    exported_at: new Date().toISOString(),
    app: "NetProof",
    provenance: report.provenance || {},
    change: report.change,
    verdict: report.summary,
    findings: report.findings,
    matrix: report.matrix,
    requirements: report.requirements,
    flow_summary: { before: report.before, after: report.after },
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `netproof-report-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  toast("Report exported (JSON) — attach it to the change ticket.");
}

function renderFindings(findings) {
  const wrap = document.createElement("div");
  wrap.className = "tab-zone findings"; wrap.dataset.zone = "findings";
  if (!findings.length) {
    wrap.innerHTML = `<div class="verdict-sub" style="padding:8px 2px">No findings — every flow and requirement still holds.</div>`;
    return wrap;
  }
  findings.forEach((f) => {
    const el = document.createElement("div");
    el.className = `finding ${f.severity}`;
    el.innerHTML = `
      <div class="finding-head"><h3><span class="sev">${f.severity}</span> ${esc(f.title)}</h3></div>
      <p class="fd">${esc(f.detail)}</p>
      ${f.requirement ? `<div class="req-line">requirement → ${esc(f.requirement)}</div>` : ""}
      <div class="evidence">
        <div class="side before"><h4>Before</h4>${sideHTML(f.before)}</div>
        <div class="side after ${f.after && !f.after.reachable ? "bad" : ""}"><h4>After</h4>${sideHTML(f.after)}</div>
      </div>`;
    wrap.appendChild(el);

    if (MODEL_HAS_TOPO) bindEvidence(el, f);
  });
  return wrap;
}

function bindEvidence(el, f) {
  el.querySelectorAll(".path-chips").forEach((pc, i) => {
    pc.style.cursor = "pointer";
    pc.title = "Click to replay this path on the topology";
    pc.addEventListener("click", () => {
      const flow = i === 1 ? f.after : f.before;
      replayPath(flow && flow.path, Boolean(flow && flow.reachable), flow && flow.drop);
    });
  });
}

function sideHTML(r) {
  if (!r) return "";
  const fate = r.status === "no_route" ? "no-route" : r.status;
  const cls = r.reachable ? "reachable" : fate === "blocked" ? "blocked" : "no-route";
  const path = (r.path || []).join(" → ") || "—";
  const chips = path.split(" → ").map((p) => `<span class="path-chip">${esc(p)}</span>`).join("");
  let drop = "";
  if (r.drop && r.drop.filter) {
    drop = `<div class="drop-line">BLOCKED by ${esc(r.drop.filter)}${r.drop.by_default ? " (default " + esc(r.drop.default) + ")" : ""} on ${esc(r.drop.device)}/${esc(r.drop.iface)}</div>`;
  } else if (r.drop && r.drop.detail) {
    drop = `<div class="drop-line">STOPPED — ${esc(r.drop.detail)}</div>`;
  }
  let nat = "";
  if (r.nat) {
    if (r.nat.kind === "dst_nat") {
      nat = `<div class="mono" style="color:var(--info);font-size:10.5px;margin-top:5px">DST-NAT ${esc(r.nat.old_dst)}:${r.nat.old_dport ?? "?"} → ${esc(r.nat.new_dst)}:${r.nat.new_dport} at ${esc(r.nat.device)}</div>`;
    } else {
      nat = `<div class="mono" style="color:var(--info);font-size:10.5px;margin-top:5px">NAT ${esc(r.nat.old_src)} → ${esc(r.nat.new_src)} at ${esc(r.nat.device)}</div>`;
    }
  }
  return `<span class="verdict-tag">${r.reachable ? "reachable" : fate}</span>${nat}
    <div class="path-chips">${chips}</div>${drop}`;
}

function renderMatrix(report) {
  const wrap = document.createElement("div");
  wrap.className = "tab-zone matrix"; wrap.dataset.zone = "matrix";
  const m = model();
  const zones = m.zones || [];
  const srcs = zones.filter((z) => z.source).map((z) => displayName(z));
  const dsts = zones.filter((z) => z.dest).map((z) => displayName(z));
  const lookup = {};
  zones.forEach((z) => { lookup[displayName(z)] = z.name; });
  const matrix = report.matrix || {};
  const pair = (sName, dName) => matrix[`${lookup[sName]} ~ ${lookup[dName]}`];

  let html = `<div class="matrix-wrap"><table class="matrix"><thead><tr><th class="r">source \\ dest</th>`;
  dsts.forEach((d) => (html += `<th>${esc(dShort(d))}</th>`));
  html += `</tr></thead><tbody>`;
  srcs.forEach((s) => {
    html += `<tr><th class="r">${esc(dShort(s))}</th>`;
    dsts.forEach((d) => {
      const cell = pair(s, d);
      if (!cell) { html += `<td class="cell">—</td>`; return; }
      const after = fateClass(cell.after);
      const same = cell.before.status === cell.after.status && cell.before.reachable === cell.after.reachable;
      html += `<td class="cell"><div class="cell-pair ${same ? "same" : ""}">
        <span class="t ${after}" title="${esc(describePath(cell.after))}" data-sim='${esc(JSON.stringify({ path: cell.after.path || [], reachable: cell.after.reachable, drop: cell.after.drop }))}'>${cell.after.reachable ? "reach" : fateWord(cell.after.status)}</span>
        <span class="lbl">before: ${cell.before.reachable ? "reach" : fateWord(cell.before.status)}</span>
      </div></td>`;
    });
    html += `</tr>`;
  });
  html += `</tbody></table></div>`;
  html += `<p class="muted" style="margin-top:10px;font-size:12px">Click any after-tag to replay that flow on the topology.</p>`;
  wrap.innerHTML = html;
  wrap.querySelectorAll("[data-sim]").forEach((t) => t.addEventListener("click", () => {
    try { replayFromJSON(t.dataset.sim); } catch (e) {}
  }));
  return wrap;
}

function fateClass(r) { return r.reachable ? "reachable" : r.status === "loop" || r.status === "no_route" ? "no-route" : "blocked"; }
function fateWord(s) { return s === "no_route" ? "no-route" : s; }
function describePath(r) {
  return (r.path || []).join(" → ") + " · " + (r.reachable ? "delivered" : r.status) + (r.drop && r.drop.filter ? ` · ${r.drop.filter}` : "");
}
function displayName(z) {
  if ((MODE === "scan" || MODE === "agent") && z.prefix && deviceByZone[z.prefix.split("/")[0]]) return deviceByZone[z.prefix.split("/")[0]] + "@" + z.name;
  return z.name;
}
function dShort(s) { return s.length > 22 ? s.slice(0, 19) + "…" : s; }

/* ---------------- replay ---------------- */
const MODEL_HAS_TOPO = true;

function replayFromJSON(data) { replayPath(data.path, data.reachable, data.drop); }

function replayPath(path, reachable, drop) {
  if (!path || !path.length) { toast("No path to replay.", true); return; }
  const svg = $("topo");
  svg.scrollIntoView({ behavior: "smooth", block: "center" });
  const dots = [];
  const nodes = svg.querySelectorAll("g.node");
  nodes.forEach((n) => n.classList.remove("flash", "flash-block", "sent", "flash0"));
  const seq = [];
  path.forEach((name) => {
    let g = svg.querySelector(`g.node[data-device="${CSS.escape(name)}"]`);
    if (!g) {
      const n = nodesByIp()[name];
      if (n) g = n;
    }
    if (g) seq.push(g);
  });
  if (!seq.length) { toast("Topology doesn't have this device highlighted — scanning hidden.", true); return; }
  const blockDevice = drop && drop.device ? svg.querySelector(`g.node[data-device="${CSS.escape(drop.device)}"]`) : null;
  seq.forEach((g, i) => {
    const r = g.getBBox();
    const c = svgNS("circle", { cx: r.x + r.width / 2, cy: r.y + r.height / 2, r: 7, fill: reachable ? "#4cb782" : "#d97b6f" });
    c.style.display = "none";
    svg.appendChild(c);
    dots.push(c);
  });
  let i = 0;
  const timer = setInterval(() => {
    dots.forEach((d) => (d.style.display = "none"));
    if (i >= seq.length) {
      clearInterval(timer);
      seq.forEach((g) => g.classList.remove("flash", "sent"));
      dots.forEach((d) => d.remove());
      if (blockDevice) {
        blockDevice.classList.add("flash-block");
        setTimeout(() => blockDevice.classList.remove("flash-block"), 1200);
        toast(`● Blocked at ${drop.device}` + (drop.filter ? ` — ${drop.filter}` : ""));
      } else if (reachable) {
        const last = seq[seq.length - 1];
        last.classList.add("flash");
        setTimeout(() => last.classList.remove("flash"), 1000);
        toast("● Delivered" + (drop && drop.detail ? ` — ${drop.detail}` : ""));
      } else {
        toast("● Dropped mid-path");
      }
      return;
    }
    seq[i].classList.add("flash");
    seq.slice(0, i).forEach((g) => g.classList.remove("flash", "sent"));
    if (i > 0) seq[i - 1].classList.add("sent");
    dots[i].style.display = "block";
    i++;
  }, 550);
}

function nodesByIp() {
  const map = {};
  (model().devices || []).forEach((d) => {
    d.interfaces && d.interfaces.forEach((i) => { if (i.ip) map[i.ip.replace(/\/.*/, "")] = d.name; });
  });
  cacheIps = map;
  const svg = $("topo");
  const out = {};
  Object.keys(map).forEach((ip) => {
    const g = svg.querySelector(`g.node[data-device="${CSS.escape(map[ip])}"]`);
    if (g) out[ip] = g;
  });
  return out;
}
let cacheIps = {};

function renderReplay(report) {
  const wrap = document.createElement("div");
  wrap.className = "tab-zone replay"; wrap.dataset.zone = "replay";
  const flows = Object.keys(report.matrix || {}).map((k) => {
    const [s, d] = k.split(" ~ ");
    const cell = report.matrix[k];
    return { label: `${dShort(s)} → ${dShort(d)}`, after: cell.after };
  });
  const options = flows.map((f, i) =>
    `<option value="${i}">${esc(f.label)} — after: ${f.after.reachable ? "reachable" : fateWord(f.after.status)}</option>`
  ).join("");
  wrap.innerHTML = `
    <div class="replay-bar">
      <select id="replay-flow"><option value="">choose a flow to replay…</option>${options}</select>
      <button class="btn btn-secondary" id="replay-play" style="width:auto;padding:8px 16px">▶ Replay</button>
      <button class="btn btn-secondary" id="replay-before" style="width:auto;padding:8px 16px">baseline</button>
      <span class="replay-status" id="replay-status"></span>
    </div>
    <p class="muted" style="font-size:12px;margin:0">Pick a zone-pair, then watch the packet hop through the routers on the topology. This is the engine's derived data plane, replayed live — the same replay you'd get in Packet Tracer.</p>`;
  wrap.querySelector("#replay-play").addEventListener("click", () => {
    const sel = wrap.querySelector("#replay-flow");
    if (!sel.value) { toast("Choose a flow first.", true); return; }
    const f = flows[+sel.value];
    wrap.querySelector("#replay-status").textContent = "replaying after-state…";
    replayPath(f.after.path, f.after.reachable, f.after.drop);
  });
  wrap.querySelector("#replay-before").addEventListener("click", () => {
    const sel = wrap.querySelector("#replay-flow");
    if (!sel.value) { toast("Choose a flow first.", true); return; }
    const cell = report.matrix[Object.keys(report.matrix)[+sel.value]];
    wrap.querySelector("#replay-status").textContent = "replaying before-state…";
    replayPath(cell.before.path, cell.before.reachable, cell.before.drop);
  });
  return wrap;
}

function renderDiff(report) {
  const diff = report.proposed_diff;
  if (!diff || diff === "no configuration lines changed") return null;
  const wrap = document.createElement("div");
  wrap.className = "tab-zone diff";
  wrap.dataset.zone = "diff";
  const pre = document.createElement("pre");
  pre.className = "diff-content";
  pre.style.cssText = "font-family:var(--mono);font-size:11px;white-space:pre-wrap;overflow-x:auto;padding:12px;background:var(--bg2);border-radius:8px;margin:0";
  pre.textContent = diff;
  wrap.appendChild(pre);
  return wrap;
}

/* ---------------- live simulation (Packet-Tracer style) ---------------- */
/* Plays packets across the topology using the ENGINE-DERIVED paths, before
   and after the proposed change. Purely visual — nothing is ever sent. */
let simCancelCtl = 0;

/* Has a usable packet path to animate (control-plane findings like DNS/BGP
   carry no data-plane path and must be skipped by the live simulation). */
function hasPath(d) {
  return !!d && Array.isArray(d.path) && d.path.length > 0;
}

let simRunner = { paused: false, speed: 1, _gateResolve: null, stepping: false };

function simGate(ctl) {
  if (ctl !== simCancelCtl) return Promise.resolve(false);
  if (simRunner.stepping) {
    simRunner.stepping = false;
    simRunner.paused = true;
  }
  if (simRunner.paused && ctl === simCancelCtl) {
    return new Promise((resolve) => {
      simRunner._gateResolve = () => resolve(ctl === simCancelCtl);
    });
  }
  return Promise.resolve(ctl === simCancelCtl);
}

function onPlay(wrap) {
  if (simRunner.paused) {
    simRunner.paused = false;
    const r = simRunner._gateResolve;
    simRunner._gateResolve = null;
    if (r) r();
    setSimStatus(wrap, "resumed.");
    return;
  }
  if (!wrap._runCtl) {
    simRunner.stepping = false;
    if ((wrap._massSrcs || 0) >= 2) runMassSim(wrap);
    else startSim(wrap);
  }
}

function onPause(wrap) {
  simRunner.paused = true;
  setSimStatus(wrap, "paused — press step to advance one step at a time.");
}

function onStep(wrap) {
  if (!simRunner.paused) simRunner.paused = true;
  simRunner.stepping = true;
  const r = simRunner._gateResolve;
  simRunner._gateResolve = null;
  if (r) r();
  if (!wrap._runCtl) startSim(wrap);
}

function onReplay(wrap) {
  const r = simRunner._gateResolve;
  simRunner._gateResolve = null;
  simRunner.paused = false;
  simRunner.stepping = false;
  simCancelCtl++;
  if (r) r();
  startSim(wrap);
}

function wp$(wrap, id) { return wrap.querySelector("#" + id); }

function buildSimPanel(report) {
  const wrap = document.createElement("div");
  wrap.className = "sim-panel";
  wrap.id = "sim-panel";
  const pairLabel = (k) => {
    const parts = k.split(" ~ ");
    if (MODE === "demo") return parts.join(" → ");
    return parts.map((p) => {
      const r = scanByIp[p];
      if (r) return `${r.hostname || p} (${p})`;
      const d = deviceByZone[p];
      return d ? `${d} (${p})` : p;
    }).join(" → ");
  };
  const flows = [];
  (report.findings || []).forEach((f, i) => {
    if (!hasPath(f.before) && !hasPath(f.after)) return;
    flows.push({ key: "f" + i, label: f.title || "finding", before: f.before, after: f.after, srcMeta: null });
  });
  Object.keys(report.matrix || {}).forEach((k) => {
    const cell = report.matrix[k];
    flows.push({ key: "m" + k, label: pairLabel(k), before: cell.before, after: cell.after, srcMeta: null });
  });
  /* rank flows: new blocks first (this is the drama), path/state changes next,
     untouched baseline flows last — so Play always starts with the good stuff. */
  const affected = (f) => {
    const b = f.before || {}, a = f.after || {};
    if (a.reachable === false) return 0;
    if (hasPath(b) && hasPath(a) &&
        (a.reachable !== b.reachable ||
         (a.path || []).join(">").replace(":0", "") !== (b.path || []).join(">").replace(":0", ""))) return 1;
    return 2;
  };
  flows.sort((x, y) => affected(x) - affected(y));
  wrap._flows = flows;
  /* count of distinct devices whose traffic is blocked AFTER the change —
     used to trigger the full-map "play every block at once" replay. */
  const bsrc = new Set();
  flows.forEach((f) => {
    if (f.after && f.after.reachable === false) {
      const p = (f.after.path || [])[0];
      if (p) bsrc.add(p);
    }
  });
  wrap._massSrcs = bsrc.size;
  const opts = flows.map((f, i) =>
    `<option value="${i}">${esc(f.label)} · after: ${f.after && f.after.reachable ? "reachable" : fateWord((f.after || {}).status || "—")}</option>`
  ).join("");
  wrap.innerHTML = `
    <div class="sim-head">
      <div class="sim-title"><span class="sim-live"></span>Live simulation
        <span class="dim">— packets are replayed on the map, never sent. The real network stays untouched.</span></div>
      <div class="sim-ctl">
        <select id="sim-flow">${opts}</select>
        <div class="sim-switch" id="sim-switch">
          <button type="button" data-sim="after" class="active">After change</button>
          <button type="button" data-sim="before">Before</button>
        </div>
        <select id="sim-speed" title="playback speed">
          <option value="0.5">0.5×</option>
          <option value="1" selected>1×</option>
          <option value="2">2×</option>
          <option value="4">4×</option>
        </select>
        <button type="button" class="sim-btn accent" id="sim-play">▶ Play</button>
        <button type="button" class="sim-btn" id="sim-pause" disabled>⏸ Pause</button>
        <button type="button" class="sim-btn" id="sim-step" disabled>⏭ Step</button>
        <button type="button" class="sim-btn" id="sim-replay" disabled>↻ Replay</button>
      </div>
    </div>
    <div class="sim-log" id="sim-log"></div>
    <div class="sim-rules" id="sim-rules"></div>
    <div class="sim-status" id="sim-status">ready — choose a flow, press play.</div>`;

  wp$(wrap, "sim-play").addEventListener("click", () => onPlay(wrap));
  wp$(wrap, "sim-pause").addEventListener("click", () => onPause(wrap));
  wp$(wrap, "sim-step").addEventListener("click", () => onStep(wrap));
  wp$(wrap, "sim-replay").addEventListener("click", () => onReplay(wrap));
  wp$(wrap, "sim-speed").addEventListener("change", (e) => { simRunner.speed = +e.target.value || 1; });
  wrap.querySelectorAll("#sim-switch button").forEach((b) => b.addEventListener("click", () => {
    wrap.querySelectorAll("#sim-switch button").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
  }));
  return wrap;
}

function enableSimBtns(wrap) {
  const running = !!wrap._runCtl;
  const p = wp$(wrap, "sim-play"), pa = wp$(wrap, "sim-pause");
  const st = wp$(wrap, "sim-step"), rp = wp$(wrap, "sim-replay");
  if (p) p.disabled = !!running;
  if (pa) pa.disabled = !running;
  if (st) st.disabled = !running;
  if (rp) rp.disabled = !running;
}

function setSimStatus(wrap, text) {
  const el = wp$(wrap, "sim-status");
  if (el) el.textContent = text;
}

function simLog(wrap, text, cls) {
  const log = wp$(wrap, "sim-log");
  if (!log) return;
  const el = document.createElement("div");
  el.className = "sim-line " + (cls || "");
  el.textContent = text;
  log.appendChild(el);
  log.scrollTop = log.scrollHeight;
}

function clearSimLog(wrap) {
  const log = wp$(wrap, "sim-log");
  if (log) log.innerHTML = "";
}

function nodeIpLabel(name) {
  const m = model();
  const dev = (m.devices || []).find((d) => d.name === name);
  if (dev && dev.interfaces) {
    const i = dev.interfaces.find((x) => x.ip);
    if (i) return i.ip.replace(/\/.*/, "");
  }
  return "";
}

/* Route hops only record the routing path (router, router, …). L2 hand-offs and
   final delivery live in `steps` (e.g. router → forwarded to host, host →
   delivered). Fold those in so the dot really flies to the destination. */
function extendPathFromSteps(path, steps) {
  const seen = new Set(path || []);
  const out = (path || []).slice();
  for (const s of (steps || [])) {
    const n = s && s.device;
    if (!n) continue;
    if (seen.has(n)) continue;
    out.push(n);
    seen.add(n);
  }
  return out;
}

function animateSegment(svg, from, to, color, ctl) {
  return new Promise((resolve) => {
    const route = svgNS("line", {
      x1: from.x, y1: from.y, x2: to.x, y2: to.y,
      stroke: color, "stroke-width": 3, "stroke-dasharray": "2 8", "stroke-linecap": "round",
      "stroke-opacity": 0.9, class: "sim-route",
    });
    const glow = svgNS("circle", { cx: from.x, cy: from.y, r: 18, fill: color, "fill-opacity": 0.3, class: "sim-dot sim-glow" });
    const dot = svgNS("circle", { cx: from.x, cy: from.y, r: 10, fill: color, "stroke": "#0b0f14", "stroke-width": 2, class: "sim-dot" });
    svg.appendChild(route);
    svg.appendChild(glow);
    svg.appendChild(dot);
    const dur = 950 / simRunner.speed;
    const t0 = performance.now();
    function frame(t) {
      if (ctl !== simCancelCtl) { glow.remove(); dot.remove(); resolve(); return; }
      let p = Math.min(1, (t - t0) / dur);
      const e = 1 - Math.pow(1 - p, 2);
      const cx = from.x + (to.x - from.x) * e;
      const cy = from.y + (to.y - from.y) * e;
      glow.setAttribute("cx", cx); glow.setAttribute("cy", cy);
      dot.setAttribute("cx", cx); dot.setAttribute("cy", cy);
      if (p < 1) requestAnimationFrame(frame);
      else { glow.remove(); dot.remove(); resolve(); }
    }
    requestAnimationFrame(frame);
  });
}

let _traceEl = null;

function clearSimSvg() {
  const svg = $("topo");
  if (!svg) return;
  svg.querySelectorAll(".sim-route, .sim-dot, .sim-dropmark").forEach((el) => el.remove());
  _traceEl = null;
}

/* Grows a persistent dashed polyline along the devices the packet has visited,
   so the user sees the full path traced out on the map as the dots fly. */
function traceRoute(svg, pts, color) {
  if (!pts.length) return;
  if (!_traceEl) {
    _traceEl = svgNS("polyline", {
      fill: "none", stroke: color, "stroke-width": 3,
      "stroke-linecap": "round", "stroke-linejoin": "round",
      "stroke-opacity": 0.65, "stroke-dasharray": "7 6", class: "sim-route",
    });
    svg.appendChild(_traceEl);
  }
  _traceEl.setAttribute("points", pts.map((p) => `${p.x},${p.y}`).join(" "));
}

function drawDropMark(svg, coord, deviceName, why) {
  const grp = svgNS("g", { class: "sim-dropmark", transform: `translate(${coord.x},${coord.y})` });
  const ring = svgNS("circle", { r: 24, fill: "rgba(217,123,111,0.22)", stroke: "#d97b6f", "stroke-width": 2, "stroke-dasharray": "4 3" });
  const txt = svgNS("text", { y: -26, class: "sim-dropmark-txt" });
  txt.setAttribute("text-anchor", "middle");
  txt.style.fill = "#d97b6f";
  txt.style.fontSize = "11px";
  txt.style.fontFamily = "var(--mono)";
  txt.style.fontWeight = "700";
  txt.textContent = "✖ " + deviceName;
  grp.appendChild(ring);
  grp.appendChild(txt);
  svg.appendChild(grp);
  setTimeout(() => grp.remove(), 5500 / (simRunner.speed || 1));
}

async function startSim(wrap, idx) {
  const sel = wp$(wrap, "sim-flow");
  if (!sel || !sel.options.length) return;
  if (idx != null && sel.value !== String(idx)) sel.value = idx;
  const speedEl = wp$(wrap, "sim-speed");
  simRunner.paused = false;
  simRunner._gateResolve = null;
  simRunner.speed = (speedEl && +speedEl.value) || 1;
  const activeBtn = wrap.querySelector("#sim-switch button.active");
  const which = (activeBtn && activeBtn.dataset.sim) || "after";
  const flow = (wrap._flows || [])[+sel.value];
  if (!flow) { toast("Choose a flow to simulate first.", true); return; }
  const data = flow[which];
  simCancelCtl++;
  const ctl = simCancelCtl;
  wrap._runCtl = ctl;
  enableSimBtns(wrap);
  clearSimLog(wrap);
  clearSimRules(wrap);
  setSimStatus(wrap, "preparing…");

  if (!data || !data.path || !data.path.length) {
    simLog(wrap, `no forwarding path for this ${which}-state (${data ? data.status : "no data"})`, "block");
    setSimStatus(wrap, "nothing to simulate — the packet never leaves the source.");
    wrap._runCtl = null;
    enableSimBtns(wrap);
    return;
  }

  const svg = $("topo");
  svg.scrollIntoView({ behavior: "smooth", block: "center" });
  clearSimSvg();
  svg.querySelectorAll("g.node.flash, g.node.flash-block, g.node.sent").forEach((n) => n.classList.remove("flash", "flash-block", "sent"));

  const reachable = data.reachable;
  const drop = data.drop || {};
  const color = reachable ? "#4cb782" : "#d97b6f";
  simLog(wrap, `${which === "after" ? "AFTER the change" : "BEFORE the change"} · ${flow.label}`, "head");
  simLog(wrap, `send: ${flow.label} · ${data.reachable ? "expects delivery" : "expects " + (drop.filter ? "DENY" : data.status)}`, "");

  const trace = (data.trace || []).filter((t) => t && t.device);
  const pathNodes = (reachable ? extendPathFromSteps(data.path, data.steps) : data.path.slice());
  const traced = [];
  let prev = null;
  let blocked = false;

  for (let i = 0; i < pathNodes.length; i++) {
    if (!(await simGate(ctl))) return;
    const name = pathNodes[i];
    const coord = nodeCoords[name];
    if (!coord) { simLog(wrap, `no map node for ${name} — skipping hop`, "warn"); continue; }
    const g = svg.querySelector(`g.node[data-device="${CSS.escape(name)}"]`);
    const ip = nodeIpLabel(name);

    if (i > 0 && prev && prev.g) {
      prev.g.classList.remove("sent");
    }
    if (prev && prev.coord) {
      simLog(wrap, `→ ${name}${ip ? " (" + ip + ")" : ""}`, "hop");
      traced.push(coord);
      traceRoute(svg, traced, color);
      await animateSegment(svg, prev.coord, coord, color, ctl);
      if (ctl !== simCancelCtl) return;
    } else {
      simLog(wrap, `start: ${name}${ip ? " (" + ip + ")" : ""}`, "hop");
      traced.push(coord);
      traceRoute(svg, traced, color);
    }
    if (g) {
      g.classList.remove("flash");
      g.classList.add("sent");
    }
    setSimStatus(wrap, `packet in flight · hop ${i + 1}/${pathNodes.length}`);
    for (const entry of trace) {
      if (ctl !== simCancelCtl) return;
      if (entry.device !== name) continue;
      if (!(await simTraceStep(wrap, entry, ctl))) return;
    }
    if (!reachable && drop.device === name) {
      if (g) { g.classList.remove("sent"); g.classList.add("flash-block"); }
      const why = drop.filter ? `blocked by ${drop.filter}` + (drop.rule ? ` (rule: ${drop.rule})` : ` (default ${drop.default})`) : (drop.detail || "dropped");
      simLog(wrap, `✖ dropped at ${name} — ${why}`, "block");
      setSimStatus(wrap, "DROPPED — traffic does not cross the change.");
      drawDropMark(svg, coord, name, why);
      blocked = true;
      break;
    }
    prev = { coord, g };
  }

  if (!(await simGate(ctl))) return;

  if (!blocked && !reachable && drop.device && nodeCoords[drop.device]) {
    const lastPrev = prev;
    if (lastPrev && lastPrev.coord) {
      simLog(wrap, `→ ${drop.device} (packet strikes the filter)`, "hop");
      await animateSegment(svg, lastPrev.coord, nodeCoords[drop.device], color, ctl);
      if (ctl !== simCancelCtl) return;
    }
    const dg = svg.querySelector(`g.node[data-device="${CSS.escape(drop.device)}"]`);
    if (dg) dg.classList.add("flash-block");
    const why = drop.filter ? `blocked by ${drop.filter}` + (drop.rule ? ` (rule: ${drop.rule})` : ` (default ${drop.default})`) : (drop.detail || "dropped");
    simLog(wrap, `✖ dropped at ${drop.device} (${drop.iface || "iface"}) — ${why}`, "block");
    setSimStatus(wrap, "DROPPED — traffic does not cross the change.");
    drawDropMark(svg, nodeCoords[drop.device], drop.device, why);
    blocked = true;
  }

  if (!(await simGate(ctl))) return;

  if (reachable) {
    const last = prev && prev.g;
    if (last) { last.classList.remove("sent"); last.classList.add("flash"); }
    const natTxt = data.nat ? (data.nat.kind === "dst_nat"
      ? ` DST-NAT ${data.nat.old_dst || ""}:${data.nat.old_dport ?? ""} → ${data.nat.new_dst}:${data.nat.new_dport} at ${data.nat.device}`
      : ` NAT ${data.nat.old_src} → ${data.nat.new_src} at ${data.nat.device}`) : "";
    simLog(wrap, `✔ delivered (${pathNodes.length} hop${pathNodes.length > 1 ? "s" : ""})${natTxt}`, "ok");
    if (drop && drop.detail) simLog(wrap, `note: ${drop.detail}`, "warn");
    setSimStatus(wrap, "delivered ✔ (simulated only — zero real packets sent)");
  } else if (!blocked) {
    simLog(wrap, `✖ not delivered — ${drop.detail || drop.filter || data.status || "unreachable"}`, "block");
    setSimStatus(wrap, "traffic blocked before delivery.");
  }

  simRunner.paused = false;
  wrap._runCtl = null;
  enableSimBtns(wrap);
  setTimeout(() => {
    clearSimSvg();
    svg.querySelectorAll("g.node.flash, g.node.flash-block, g.node.sent").forEach((n) => n.classList.remove("flash", "flash-block", "sent"));
  }, 3000 / simRunner.speed);
}

/* ------- blast-radius replay: internet → router → every device ---------- */
/* When a change blocks flows (e.g. a deny-any-any at the top of the router
   policy), tell the WHOLE story on the map Packet-Tracer style:
     1) an inbound packet arrives from the INTERNET (right) to the ROUTER (center)
     2) the router checks the change, finds it matches, and refuses the traffic
     3) the refusal BLASTS out from the router to EVERY affected device —
        red dashed links + red packets flying router → device + an ✖ on each. */

async function runMassSim(wrap) {
  const sel = wp$(wrap, "sim-flow");
  if (!sel || !sel.options.length) return;
  const flows = (wrap._flows || []).filter((f) =>
    f.after && f.after.reachable === false && (hasPath(f.after) || (f.after.drop && f.after.drop.device)));
  if (flows.length < 2) { startSim(wrap); return; }

  simRunner.paused = false;
  simRunner._gateResolve = null;
  simRunner.speed = (+(wp$(wrap, "sim-speed") && wp$(wrap, "sim-speed").value)) || 1;
  simCancelCtl++;
  const ctl = simCancelCtl;
  wrap._runCtl = ctl;
  enableSimBtns(wrap);
  clearSimLog(wrap);
  clearSimRules(wrap);
  setSimStatus(wrap, "playing the full scenario: internet → router → every device…");

  const svg = $("topo");
  svg.scrollIntoView({ behavior: "smooth", block: "center" });
  clearSimSvg();
  svg.querySelectorAll("g.node.flash, g.node.flash-block, g.node.sent").forEach((n) => n.classList.remove("flash", "flash-block", "sent"));

  const jobs = [];
  const seen = new Set();
  for (const f of flows) {
    const p = f.after.path || [];
    const src = p[0] || (f.after.drop && f.after.drop.device);
    if (!src || seen.has(src)) continue;
    seen.add(src);
    jobs.push({ flow: f, src });
  }

  /* where the packets strike — the device running the blocking filter */
  const drop = flows.find((f) => f.after && f.after.drop);
  const d = (drop && drop.after.drop) || {};
  const why = d.filter ? `blocked by ${d.filter}${d.rule ? " (rule: " + d.rule + ")" : ""}` : (d.detail || "denied");
  const routerName = d.device;
  const routerCoord = routerName && nodeCoords[routerName];

  /* the internet node lies on the right side of the map */
  const m = model();
  const internetDev = (m.devices || []).find((x) => x.type === "cloud" || x.type === "internet");
  const netCoord = internetDev && nodeCoords[internetDev.name];

  simLog(wrap, `AFTER the change — replaying ${flows.length} blocked flow(s) across ${jobs.length} device(s)`, "head");
  simLog(wrap, `the full scenario: internet → ${routerName || "router"} → every device`, "hop");

  /* ---- PHASE 1 · the packet arrives from the internet (right → center) ---- */
  if (netCoord && routerCoord) {
    const ingress = svgNS("line", { class: "sim-route sim-block-link", x1: netCoord.x, y1: netCoord.y, x2: routerCoord.x, y2: routerCoord.y,
      stroke: "#5ec8b2", "stroke-width": 2.5, "stroke-dasharray": "4 7", "stroke-opacity": 0.8 });
    svg.appendChild(ingress);
    setTimeout(() => ingress.remove(), 3500 / simRunner.speed);
    simLog(wrap, `internet → ${routerName}: inbound data reaches the edge of the network`, "hop");
    await animateSegment(svg, netCoord, routerCoord, "#5ec8b2", ctl);
    if (ctl !== simCancelCtl) return;
  }

  /* ---- PHASE 2 · the router checks the change and refuses the traffic ---- */
  const rg = routerName && svg.querySelector(`g.node[data-device="${CSS.escape(routerName)}"]`);
  if (rg) rg.classList.add("flash-block");
  if (routerCoord) drawDropMark(svg, routerCoord, routerName, why);
  simLog(wrap, `${routerName || "router"} runs the policy: the packet MATCHES your change (${why}) — refused`, "block");
  setSimStatus(wrap, `router refuses the packet (${why}) · blasting red signals to every device…`);
  await delay(700 / simRunner.speed);
  if (ctl !== simCancelCtl) return;

  /* ---- PHASE 3 · red deny-signal BLASTS out to every affected device ---- */
  await Promise.all(jobs.map((job, i) => massBlockedJob(wrap, svg, job, routerCoord, ctl, i, jobs.length)));
  if (ctl !== simCancelCtl) return;

  [...seen].slice(0, 200).forEach((n) => simLog(wrap, `✖ ${n} — will not receive data (${why})`, "block"));

  simRunner.paused = false;
  wrap._runCtl = null;
  enableSimBtns(wrap);
  setSimStatus(wrap, `BLOCKED: ${flows.length} flow(s) refused at ${routerName || "the router"} (${why}). Every affected device got the deny signal. No real data was sent.`);
  setTimeout(() => {
    clearSimSvg();
    svg.querySelectorAll("g.node.flash, g.node.flash-block, g.node.sent").forEach((n) => n.classList.remove("flash", "flash-block", "sent"));
  }, 5000 / simRunner.speed);
}

async function massBlockedJob(wrap, svg, job, fromCoord, ctl, idx, total) {
  const { flow, src } = job;
  const drop = (flow.after || {}).drop || {};
  const toCoord = nodeCoords[src];
  if (!fromCoord || !toCoord || fromCoord === toCoord) return;

  await delay(60 + (idx * 200) / (simRunner.speed || 1));
  if (ctl !== simCancelCtl) return;

  /* red dashed connection: router <-> this device (the broken path) */
  const line = svgNS("line", { class: "sim-route sim-block-link", x1: fromCoord.x, y1: fromCoord.y, x2: toCoord.x, y2: toCoord.y,
    stroke: "#d97b6f", "stroke-width": 2.5, "stroke-dasharray": "4 7", "stroke-opacity": 0.85 });
  svg.appendChild(line);

  const g = svg.querySelector(`g.node[data-device="${CSS.escape(src)}"]`);
  if (g) g.classList.add("sent");

  /* the red deny-signal flies router → this device */
  if (!(await simGate(ctl))) return;
  await animateSegment(svg, fromCoord, toCoord, "#d97b6f", ctl);
  if (ctl !== simCancelCtl) return;

  /* mark the device as cut off: red flash + ✖ */
  if (g) { g.classList.remove("sent"); g.classList.add("flash-block"); }
  if (nodeCoords[src]) drawDropMark(svg, nodeCoords[src], src, "blocked");
  simLog(wrap, `✖ ${src} — traffic refused`, "block");

  if (idx === total - 1 && drop.device) {
    const dg = svg.querySelector(`g.node[data-device="${CSS.escape(drop.device)}"]`);
    if (dg) dg.classList.add("flash-block");
  }
}

async function simTraceStep(wrap, entry, ctl) {
  if (ctl !== simCancelCtl) return false;
  showFilterTrace(wrap, entry);
  const checks = entry.checks || [];
  const hitIdx = entry.hit_rule;
  for (let i = 0; i < checks.length; i++) {
    const check = checks[i];
    if (!(await simGate(ctl))) return false;
    if (ctl !== simCancelCtl) return false;
    const isHit = hitIdx === check.index && !!check.matched;
    highlightRule(wrap, check.index, check, isHit);
    await delay(350 / simRunner.speed);
    if (ctl !== simCancelCtl) return false;
  }
  if (!(await simGate(ctl))) return false;
  if (ctl !== simCancelCtl) return false;
if (entry.by_default && hitIdx == null) {
    highlightRule(wrap, checks.length, { action: entry.default_action }, true);
  } else if (hitIdx != null) {
    const chk = checks.find((c) => c.index === hitIdx);
    if (chk) highlightRule(wrap, checks.indexOf(chk), chk, true);
  }
  showDecision(wrap, entry);
  await delay(300 / simRunner.speed);
  return ctl === simCancelCtl;
}

function clearSimRules(wrap) {
  const box = wp$(wrap, "sim-rules");
  if (box) box.innerHTML = "";
}

function showFilterTrace(wrap, entry) {
  clearSimRules(wrap);
  const box = wp$(wrap, "sim-rules");
  if (!box) return;
  const checks = entry.checks || [];
  const rules = checks.map((c) =>
    `<div class="sim-rule" data-idx="${c.index}">${c.index}: ${esc(c.desc)}${c.matched ? " ✓" : ""}</div>`
  ).join("");
  box.innerHTML =
    `<div class="sim-filter-head">${esc(entry.filter || "filter")} <span class="dim">(${checks.length} rules, default: ${esc(entry.default_action || "deny")})</span></div>` +
    `<div class="sim-rules-list" id="sim-rules-list">${rules}` +
    `<div class="sim-rule" data-idx="${checks.length}">—: [default → ${esc(entry.default_action || "deny")}]</div></div>` +
    `<div class="sim-decision" id="sim-decision"></div>`;
}

function highlightRule(wrap, idx, check, isHit) {
  const list = wp$(wrap, "sim-rules-list");
  if (!list) return;
  list.querySelectorAll(".sim-rule").forEach((r) => r.classList.remove("active", "match", "deny-match"));
  const row = list.querySelector(`.sim-rule[data-idx="${idx}"]`);
  if (!row) return;
  row.classList.add("active");
  if (isHit && check) row.classList.add(check.action === "deny" ? "deny-match" : "match");
}

function showDecision(wrap, entry) {
  const d = wp$(wrap, "sim-decision");
  if (!d) return;
  const denied = !entry.allowed;
  d.textContent = denied ? "✕ DENIED — packet blocked" : "✓ ALLOWED — packet passes";
  d.className = "sim-decision " + (denied ? "block" : "ok");
}

function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }

/* ============================================================
   TOPOLOGY LIVE-FLOW OVERLAY  (Cisco Packet Tracer style)
   After validation, draws colored path lines on the map and
   animates packet dots flying hop-by-hop for every flow.
   ============================================================ */

let _topoFlowState = null;   // { flows, raf, paused, speed, which, idx }

/* Build the list of flows to animate from a validation report */
function _buildTopoFlows(report, which) {
  const flows = [];
  Object.keys(report.matrix || {}).forEach((k) => {
    const cell = report.matrix[k];
    const d = cell[which];
    if (!d || !d.path || !d.path.length) return;
    flows.push({
      key: k,
      path: d.path.slice(),
      reachable: d.reachable,
      drop: d.drop || {},
      status: d.status || "",
    });
  });
  // blocked flows first so they're immediately visible
  flows.sort((a, b) => (a.reachable ? 1 : 0) - (b.reachable ? 1 : 0));
  return flows;
}

/* Draw static colored path lines for ALL flows at once */
function _drawPathLines(svg, flows) {
  svg.querySelectorAll(".flow-path-line").forEach((e) => e.remove());
  const drawn = new Set();
  flows.forEach((f) => {
    const color = f.reachable ? "#4cb782" : "#d97b6f";
    const opacity = f.reachable ? 0.28 : 0.45;
    const w = f.reachable ? 2.5 : 3;
    for (let i = 0; i < f.path.length - 1; i++) {
      const a = nodeCoords[f.path[i]], b = nodeCoords[f.path[i + 1]];
      if (!a || !b) continue;
      const key = [f.path[i], f.path[i + 1]].sort().join("|") + color;
      if (drawn.has(key)) continue;
      drawn.add(key);
      const line = svgNS("line", {
        x1: a.x, y1: a.y, x2: b.x, y2: b.y,
        stroke: color, "stroke-width": w,
        "stroke-opacity": opacity,
        "stroke-linecap": "round",
        "stroke-dasharray": f.reachable ? "8 6" : "5 4",
        class: "flow-path-line",
      });
      // insert before nodes so dots appear on top
      const firstNode = svg.querySelector("g.node");
      if (firstNode) svg.insertBefore(line, firstNode);
      else svg.appendChild(line);
    }
  });
}

/* Animate a single packet dot along one flow's path, returns a Promise */
function _animateFlowPacket(svg, flow, speed) {
  return new Promise((resolve) => {
    const path = flow.path;
    const color = flow.reachable ? "#4cb782" : "#d97b6f";
    const coords = path.map((n) => nodeCoords[n]).filter(Boolean);
    if (coords.length < 2) { resolve(); return; }

    const dot = svgNS("circle", {
      r: 7, fill: color, stroke: "#0b0f14", "stroke-width": 2,
      class: "flow-packet-dot",
    });
    const glow = svgNS("circle", {
      r: 14, fill: color, "fill-opacity": 0.25,
      class: "flow-packet-dot",
    });
    svg.appendChild(glow);
    svg.appendChild(dot);

    // total path length for timing
    let totalLen = 0;
    for (let i = 0; i < coords.length - 1; i++) {
      const dx = coords[i + 1].x - coords[i].x, dy = coords[i + 1].y - coords[i].y;
      totalLen += Math.sqrt(dx * dx + dy * dy);
    }
    const baseDur = Math.max(900, Math.min(2800, totalLen * 2.2)) / speed;

    const t0 = performance.now();
    function frame(now) {
      if (!_topoFlowState || _topoFlowState.paused) {
        // park the dot at current position until resumed
        requestAnimationFrame(frame);
        return;
      }
      const elapsed = now - t0;
      const p = Math.min(1, elapsed / baseDur);
      // find which segment we're on
      let traveled = p * totalLen;
      let cx = coords[0].x, cy = coords[0].y;
      for (let i = 0; i < coords.length - 1; i++) {
        const dx = coords[i + 1].x - coords[i].x, dy = coords[i + 1].y - coords[i].y;
        const segLen = Math.sqrt(dx * dx + dy * dy);
        if (traveled <= segLen) {
          const t = segLen > 0 ? traveled / segLen : 0;
          cx = coords[i].x + dx * t;
          cy = coords[i].y + dy * t;
          break;
        }
        traveled -= segLen;
        cx = coords[i + 1].x; cy = coords[i + 1].y;
      }
      dot.setAttribute("cx", cx); dot.setAttribute("cy", cy);
      glow.setAttribute("cx", cx); glow.setAttribute("cy", cy);

      // flash the node the dot just reached
      const nodeIdx = Math.min(Math.floor(p * (coords.length - 1)), coords.length - 2);
      const nodeName = path[nodeIdx + 1];
      if (nodeName) {
        const g = svg.querySelector(`g.node[data-device="${CSS.escape(nodeName)}"]`);
        if (g && !g._flashActive) {
          g._flashActive = true;
          g.classList.add(flow.reachable ? "flash" : "flash-block");
          setTimeout(() => { g.classList.remove("flash", "flash-block"); g._flashActive = false; }, 380);
        }
      }

      if (p < 1) { requestAnimationFrame(frame); }
      else {
        dot.remove(); glow.remove();
        // draw a brief "delivered" or "blocked" burst at the last node
        const last = coords[coords.length - 1];
        const burst = svgNS("circle", {
          cx: last.x, cy: last.y, r: 5,
          fill: "none", stroke: color, "stroke-width": 2.5,
          class: "flow-packet-dot",
        });
        svg.appendChild(burst);
        let br = 5, bo = 1;
        function burstFrame() {
          br += 2.5; bo -= 0.12;
          burst.setAttribute("r", br);
          burst.setAttribute("stroke-opacity", Math.max(0, bo));
          if (bo > 0) requestAnimationFrame(burstFrame);
          else burst.remove();
        }
        requestAnimationFrame(burstFrame);
        resolve();
      }
    }
    requestAnimationFrame(frame);
  });
}

/* Main loop: cycle through all flows continuously */
async function _topoFlowLoop(state) {
  const svg = $("topo");
  if (!svg) return;
  while (_topoFlowState === state && !state.stopped) {
    if (state.paused) { await delay(80); continue; }
    const flow = state.flows[state.idx % state.flows.length];
    state.idx++;
    if (!flow) { await delay(100); continue; }
    // update the overlay bar label
    const lbl = $("topo-flow-label");
    if (lbl) {
      const parts = flow.key.split(" ~ ");
      lbl.textContent = (parts[0] || "").split("@").pop() + " → " + (parts[1] || "").split("@").pop()
        + (flow.reachable ? " ✓" : " ✗");
      lbl.style.color = flow.reachable ? "var(--pass)" : "var(--danger)";
    }
    await _animateFlowPacket(svg, flow, state.speed);
    // small gap between packets
    await delay(Math.max(60, 320 / state.speed));
  }
}

/* Start (or restart) the topology live-flow overlay */
function startTopoFlowOverlay(report) {
  stopTopoFlowOverlay();
  const svg = $("topo");
  if (!svg) return;

  const which = "after";
  const flows = _buildTopoFlows(report, which);
  if (!flows.length) return;

  _drawPathLines(svg, flows);

  const state = { flows, idx: 0, paused: false, speed: 1, which, stopped: false, report };
  _topoFlowState = state;

  // inject the overlay control bar if not present
  _ensureOverlayBar(report);

  _topoFlowLoop(state);
}

function stopTopoFlowOverlay() {
  if (_topoFlowState) { _topoFlowState.stopped = true; _topoFlowState = null; }
  const svg = $("topo");
  if (svg) {
    svg.querySelectorAll(".flow-path-line, .flow-packet-dot").forEach((e) => e.remove());
    svg.querySelectorAll("g.node.flash, g.node.flash-block").forEach((g) => g.classList.remove("flash", "flash-block"));
  }
  const bar = $("topo-overlay-bar");
  if (bar) bar.remove();
}

function _ensureOverlayBar(report) {
  const wrap = document.querySelector(".topo-wrap");
  if (!wrap) return;
  let bar = $("topo-overlay-bar");
  if (bar) bar.remove();

  bar = document.createElement("div");
  bar.className = "topo-overlay-bar";
  bar.id = "topo-overlay-bar";
  bar.innerHTML = `
    <span class="ob-live"></span>
    <span style="color:var(--accent);font-weight:700">LIVE SIM</span>
    <span id="topo-flow-label" style="min-width:160px">—</span>
    <button id="ob-after" class="active" title="Show after-change flows">After</button>
    <button id="ob-before" title="Show before-change flows">Before</button>
    <button id="ob-pause" title="Pause/resume">⏸</button>
    <select id="ob-speed" title="Speed">
      <option value="0.5">0.5×</option>
      <option value="1" selected>1×</option>
      <option value="2">2×</option>
      <option value="4">4×</option>
    </select>
    <button id="ob-stop" title="Stop overlay">✕</button>`;
  wrap.appendChild(bar);

  $("ob-pause").addEventListener("click", () => {
    if (!_topoFlowState) return;
    _topoFlowState.paused = !_topoFlowState.paused;
    $("ob-pause").textContent = _topoFlowState.paused ? "▶" : "⏸";
  });
  $("ob-speed").addEventListener("change", (e) => {
    if (_topoFlowState) _topoFlowState.speed = +e.target.value || 1;
  });
  $("ob-stop").addEventListener("click", stopTopoFlowOverlay);
  $("ob-after").addEventListener("click", () => {
    if (!_topoFlowState) return;
    $("ob-after").classList.add("active"); $("ob-before").classList.remove("active");
    _topoFlowState.flows = _buildTopoFlows(_topoFlowState.report, "after");
    _topoFlowState.idx = 0;
    _drawPathLines($("topo"), _topoFlowState.flows);
  });
  $("ob-before").addEventListener("click", () => {
    if (!_topoFlowState) return;
    $("ob-before").classList.add("active"); $("ob-after").classList.remove("active");
    _topoFlowState.flows = _buildTopoFlows(_topoFlowState.report, "before");
    _topoFlowState.idx = 0;
    _drawPathLines($("topo"), _topoFlowState.flows);
  });
}

/* ============================================================ */


function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function toast(msg, error) {
  const t = $("toast");
  t.hidden = false;
  t.className = "toast" + (error ? " error" : "");
  t.textContent = msg;
  clearTimeout(t._h);
  t._h = setTimeout(() => (t.hidden = true), error ? 4200 : 2600);
}