"use strict";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

// The launcher opens us with #c=<one-time code>. Trade it for the session token
// (kept for this tab only) and scrub it from the URL. The code is useless once used,
// so it doesn't matter that it shows up in the browser's command line.
let TOKEN = sessionStorage.getItem("st-token") || "";
const ready = (async () => {
  const m = location.hash.match(/c=([\w-]+)/);
  if (!m) return;
  history.replaceState(null, "", location.pathname);
  try {
    const res = await fetch("/api/session", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: m[1] }),
    });
    const data = await res.json();
    if (res.ok && data.token) { TOKEN = data.token; sessionStorage.setItem("st-token", TOKEN); }
  } catch (e) { /* poll() shows "Open SafeTorrent from its app icon" */ }
})();

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: { "X-Safetorrent-Token": TOKEN, "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ error: "The SafeTorrent server didn't answer." }));
  if (!res.ok || data.error) throw new Error(data.error || "Something went wrong.");
  return data;
}

function toast(msg, err = false) {
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.textContent = msg;
  $("toasts").appendChild(el);
  setTimeout(() => el.remove(), err ? 9000 : 4500);
}

function human(n) {
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i ? n.toFixed(1) : n) + " " + u[i];
}

let S = null;                 // latest server state
const openDetails = new Set();
const forceChecked = new Set();

/* ---------------- safety checks ---------------- */

const FIX_LABEL = {
  import_vpn: "Import new Proton file", enable_vpn: "Turn on the VPN",
  update: "Update now", settings: "Open settings",
};

function renderChecks() {
  const h = S.health;
  const gate = $("gate");
  if (S.vm !== "Running") {
    gate.className = "gate";
    $("gate-text").textContent = S.busy.vm ? "Starting the VM…" : "VM is " + S.vm.toLowerCase();
    $("checks").innerHTML = `<p class="sub">The safety VM isn't running.</p>
      <button class="btn small" data-fix="vm">Start it</button>`;
    return;
  }
  if (!h) {
    $("checks").innerHTML = `<p class="sub">${esc(S.health_error || "Running the checks…")}</p>`;
    return;
  }
  gate.className = "gate " + (h.blocked ? "blocked" : "allowed");
  const vpn = h.checks.find((c) => c.id === "vpn");
  $("gate-text").textContent = h.blocked ? "Downloads blocked"
    : "Downloads allowed" + (vpn && vpn.state === "ok" ? ", through Proton" : "");
  $("checks").innerHTML = h.checks.map((c) => `
    <div class="check ${c.state}">
      <span class="mark ${c.state}" aria-label="${c.state === "ok" ? "passed" : c.state === "warn" ? "warning" : "blocking"}"></span>
      <div>
        <div class="check-title">${esc(c.title)}</div>
        <div class="check-detail">${esc(c.detail)}</div>
        ${c.fix && FIX_LABEL[c.fix] && c.state !== "ok" ? `<div class="fix"><button class="btn small ${c.state === "block" ? "" : "quiet"}" data-fix="${c.fix}"
          ${S.busy[c.fix] ? "disabled" : ""}>${esc(S.busy[c.fix] || FIX_LABEL[c.fix])}</button></div>` : ""}
      </div>
    </div>`).join("");
}

function renderIntake() {
  const h = S.health;
  const blocked = S.vm !== "Running" || !h || h.blocked;
  $("intake").classList.toggle("locked", blocked);
  if (blocked) {
    const first = h && h.checks.find((c) => c.state === "block");
    $("lock-msg").textContent = S.vm !== "Running" ? "Waiting for the safety VM to start."
      : !h ? "Running the safety checks…"
      : `Downloads are blocked until this is fixed: ${first.title}.`;
  }
  const adding = S.busy.add;
  $("add-btn").disabled = !!adding;
  $("add-note").classList.toggle("hidden", !adding);
  if (adding) $("add-note").textContent = adding + "… Magnet links can take a minute or two while peers are found.";
}

/* ---------------- downloads ---------------- */

const VERDICT = {
  CLEAN: ["Clean", "clean"], WARNING: ["Needs a look", "warn"], SUSPICIOUS: ["Suspicious", "bad"],
  INFECTED: ["Infected", "bad"], REJECTED: ["Rejected before download", "bad"], OK: ["", ""],
};

function chambers(m) {
  const pre = m.precheck.verdict;
  const verdict = m.scan && m.scan.verdict;
  const releasing = S.busy["release:" + m.id];
  const c = [
    { label: "File list checked", cls: pre === "OK" ? "done" : pre === "WARNING" ? "held" : "fail",
      state: pre === "OK" ? "Passed" : pre === "WARNING" ? "Warnings" : "Rejected" },
    { label: "Quarantine", cls: "", state: "Waiting" },
    { label: "Scan", cls: "", state: "Waiting" },
    { label: "On your Mac", cls: "", state: "Not yet" },
  ];
  const st = m.status;
  if (["prechecked", "skipped"].includes(st) && pre !== "REJECTED") c[1].state = "Not started";
  if (st === "queued") Object.assign(c[1], { cls: "active indeterminate", state: "Starting" });
  if (st === "downloading") {
    const p = m.progress;
    Object.assign(c[1], p && p.seeding ? { cls: "done", state: "Downloaded, sharing" }
      : p ? { cls: "active", state: `${p.percent}% downloaded`, pct: p.percent }
      : { cls: "active indeterminate", state: "Finding peers" });
  }
  if (["incomplete", "vpn-failed", "blocked"].includes(st)) {
    Object.assign(c[1], { cls: st === "incomplete" ? "held" : "fail", state: st === "incomplete" ? "Paused" : "Stopped" });
  }
  if (["downloaded", "scanning", "scanned", "released"].includes(st)) Object.assign(c[1], { cls: "done", state: "Downloaded" });
  if (st === "broken") Object.assign(c[1], { cls: "fail", state: "Record unreadable" });
  if (st === "downloaded") Object.assign(c[2], { cls: "held", state: "Not scanned" });
  if (st === "scanning") Object.assign(c[2], { cls: "active indeterminate", state: m.phase || "Scanning" });
  if (st === "scanned" || st === "released") {
    Object.assign(c[2], verdict === "CLEAN" ? { cls: "done", state: "Clean" }
      : verdict === "WARNING" ? { cls: "held", state: "Warnings" } : { cls: "fail", state: VERDICT[verdict][0] });
  }
  if (st === "scanned") {
    if (releasing) Object.assign(c[3], { cls: "active indeterminate", state: "Copying" });
    else if (verdict === "CLEAN") c[3].state = m.auto_release ? "Copying soon" : "Ready";
    else if (verdict === "WARNING") Object.assign(c[3], { cls: "held", state: "Waiting for you" });
    else Object.assign(c[3], { cls: "fail", state: "Kept in the VM" });
  }
  if (st === "released") Object.assign(c[3], { cls: "done", state: "Copied" });
  return c;
}

function progressLine(m) {
  const p = m.progress;
  if (m.status === "downloading" && p && p.seeding) {
    return `Finished. Sharing with ${p.peers || 0} peers for your set time before scanning (ratio ${p.ratio}).`;
  }
  if (m.status === "downloading" && p) {
    const bits = [`${p.done} of ${p.total}`];
    if (p.speed) bits.push(`${p.speed}/s`);
    if (p.peers) bits.push(`${p.peers} peers`);
    if (p.eta) bits.push(`${p.eta} left`);
    return bits.join(", ");
  }
  if (m.status === "scanning") return m.phase ? m.phase + "…" : "Scanning…";
  if (m.status === "released") return "Copied to " + m.released_to;
  return "";
}

function actions(m) {
  const id = m.id, v = m.scan && m.scan.verdict, st = m.status, pre = m.precheck.verdict;
  const b = (act, label, cls = "quiet") => `<button class="btn small ${cls}" data-act="${act}" data-id="${id}">${label}</button>`;
  const out = [];
  if (["prechecked", "skipped"].includes(st)) out.push(b("start", pre === "WARNING" ? "Download anyway" : "Download into quarantine", ""));
  if (st === "rejected") {
    out.push(`<label class="force-row"><input type="checkbox" data-force="${id}" ${forceChecked.has(id) ? "checked" : ""}>
      I understand the risk</label>`);
    if (forceChecked.has(id)) out.push(b("force-start", "Download it anyway", "danger"));
  }
  if (["queued", "downloading", "scanning"].includes(st)) out.push(b("stop", st === "scanning" ? "Stop scan" : "Pause"));
  if (["incomplete", "vpn-failed", "blocked"].includes(st)) out.push(b("start", "Resume", ""));
  if (st === "downloaded") out.push(b("scan", "Scan now", ""));
  if (st === "scanned" && v === "WARNING") out.push(b("release", "Copy to my Mac", ""));
  if (st === "scanned" && v === "CLEAN" && !m.auto_release) out.push(b("release", "Copy to my Mac", ""));
  if (st === "scanned" && (v === "SUSPICIOUS" || v === "INFECTED")) out.push(b("force-release", "Copy anyway", "danger"));
  if (st === "released") out.push(b("reveal", "Show in Finder", ""), b("release-again", "Copy again"));
  if (["scanned", "released"].includes(st)) out.push(b("scan", "Scan again"));
  if (!["queued", "downloading", "scanning"].includes(st)) {
    out.push(b("delete", st === "released" ? "Remove from quarantine" : "Delete", "danger"));
  }
  return out.join("");
}

function findingsHtml(list) {
  if (!list.length) return `<p class="sub" style="margin:0 0 12px">No problems found.</p>`;
  return `<ul class="findings">` + [...list].sort((a, b) => b.level - a.level).map((f) => `
    <li class="l${f.level}"><span class="dot"></span><span>${f.path ? `<span class="path">${esc(f.path)}</span><br>` : ""}${esc(f.msg)}</span></li>`
  ).join("") + `</ul>`;
}

function renderItems() {
  $("free").textContent = S.free ? `${human(S.free)} free in the VM` : "";
  if (S.items_error) { $("items").innerHTML = `<div class="empty">${esc(S.items_error)}</div>`; return; }
  if (!S.items.length) {
    $("items").innerHTML = `<div class="empty">Nothing in quarantine yet. Paste a magnet link above and it'll be checked before anything downloads.</div>`;
    return;
  }
  $("items").innerHTML = S.items.map((m) => {
    const v = (m.scan && m.scan.verdict) || (m.precheck.verdict !== "OK" ? m.precheck.verdict : "OK");
    const [vText, vCls] = VERDICT[v] || ["", ""];
    const err = m.error && !["scanned", "released"].includes(m.status) ? m.error : S.errors[m.id];
    const findings = m.scan ? m.scan.findings : m.precheck.findings;
    const isOpen = openDetails.has(m.id) || ["prechecked", "rejected", "skipped"].includes(m.status) && !openDetails.has("closed:" + m.id);
    const cats = { media: "Movies, TV or music", software: "Software", docs: "Books or documents", iso: "Disk image" };
    return `<article class="item">
      <div class="item-top">
        <div>
          <div class="item-name">${esc(m.name)}</div>
          <div class="item-facts"><span>${human(m.total)}</span><span>${m.file_count} file${m.file_count === 1 ? "" : "s"}</span>
            <span>${cats[m.category] || esc(m.category)}</span></div>
        </div>
        <div class="verdict ${vCls}">${esc(vText)}</div>
      </div>
      <div class="airlock">${chambers(m).map((c) => `
        <div class="chamber ${c.cls}">
          <div class="bar"><div class="fill" style="${c.pct != null ? `width:${c.pct}%` : ""}"></div></div>
          <div class="label">${c.label}</div><div class="state">${esc(c.state)}</div>
        </div>`).join("")}</div>
      ${progressLine(m) ? `<p class="item-msg">${esc(progressLine(m))}</p>` : ""}
      ${err ? `<p class="item-msg err">${esc(err)}</p>` : ""}
      <div class="item-actions">${actions(m)}
        <button class="details-toggle" data-toggle="${m.id}" aria-expanded="${isOpen}">${isOpen ? "Hide details" : "Details"}</button>
      </div>
      ${isOpen ? `<div class="details">
        <h2 style="font-size:14px">${m.scan ? "Scan findings" : "What the file-list check found"}</h2>
        ${findingsHtml(findings)}
        <h2 style="font-size:14px">Largest files</h2>
        <div class="files">${(m.files || []).slice(0, 60).map((f) =>
          `<div><span class="size">${human(f.size)}</span><span>${esc(f.path)}</span></div>`).join("")}</div>
      </div>` : ""}
    </article>`;
  }).join("");
}

function renderBanner() {
  const b = $("banner");
  const busy = Object.entries(S.busy).filter(([k]) => !k.startsWith("release:") && k !== "add");
  if (S.vm === "Missing") {
    b.className = "banner bad";
    b.textContent = "The safety VM hasn't been created. Run: safetorrent setup";
  } else if (busy.length) {
    b.className = "banner";
    b.textContent = busy.map(([, v]) => v + "…").join("  ");
  } else {
    b.className = "banner hidden";
  }
}

function render() {
  if (!S) return;
  renderChecks(); renderIntake(); renderItems(); renderBanner();
}

async function poll() {
  try {
    S = await api("/api/state");
    render();
  } catch (e) {
    $("gate-text").textContent = TOKEN ? e.message : "Open SafeTorrent from its app icon";
  }
  const busy = S && (S.items.some((m) => ["queued", "downloading", "scanning"].includes(m.status)) || Object.keys(S.busy).length);
  setTimeout(poll, busy ? 1500 : 4000);
}

/* ---------------- events ---------------- */

let torrentB64 = null;

$("pick-torrent").onclick = () => $("torrent-file").click();
$("torrent-file").onchange = () => loadTorrent($("torrent-file").files[0]);

async function loadTorrent(file) {
  if (!file) return;
  if (!/\.torrent$/i.test(file.name)) return toast("That isn't a .torrent file.", true);
  const buf = new Uint8Array(await file.arrayBuffer());
  let bin = "";
  for (let i = 0; i < buf.length; i += 8192) bin += String.fromCharCode(...buf.subarray(i, i + 8192));
  torrentB64 = btoa(bin);
  $("picked").textContent = file.name;
  $("magnet").value = "";
}

$("add-form").onsubmit = async (e) => {
  e.preventDefault();
  const magnet = $("magnet").value.trim();
  if (!magnet && !torrentB64) return toast("Paste a magnet link or choose a .torrent file.", true);
  const body = {
    magnet: magnet || undefined, torrent_b64: magnet ? undefined : torrentB64,
    category: $("category").value, sha256: $("sha256").value.trim(),
    auto_start: $("auto-start").checked, auto_release: $("auto-release").checked,
  };
  S.busy.add = "Reading the torrent's file list"; renderIntake();
  try {
    const m = await api("/api/add", body);
    $("magnet").value = ""; $("sha256").value = ""; torrentB64 = null; $("picked").textContent = "";
    if (m.existed) toast("You already have this one; it's in the list.");
    else if (m.started) toast("The file list looks fine, so it's downloading into quarantine.");
    else if (m.precheck.verdict === "REJECTED") toast("Rejected: this torrent shows signs of malware. Nothing was downloaded.", true);
    else if (m.precheck.verdict === "WARNING") toast("Check the warnings before downloading.");
    openDetails.add(m.id);
  } catch (err) { toast(err.message, true); }
  delete S.busy.add;
  poll();
};

// Drag a .torrent anywhere onto the intake box.
const intake = $("intake");
intake.addEventListener("dragover", (e) => { e.preventDefault(); intake.classList.add("dragging"); });
intake.addEventListener("dragleave", () => intake.classList.remove("dragging"));
intake.addEventListener("drop", (e) => {
  e.preventDefault(); intake.classList.remove("dragging");
  loadTorrent(e.dataTransfer.files[0]);
});

$("items").addEventListener("change", (e) => {
  const id = e.target.dataset.force;
  if (!id) return;
  e.target.checked ? forceChecked.add(id) : forceChecked.delete(id);
  renderItems();
});

$("items").addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  if (t.dataset.toggle) {
    const id = t.dataset.toggle;
    if (t.getAttribute("aria-expanded") === "true") { openDetails.delete(id); openDetails.add("closed:" + id); }
    else { openDetails.add(id); openDetails.delete("closed:" + id); }
    return renderItems();
  }
  const { act, id } = t.dataset;
  if (!act) return;
  const m = S.items.find((x) => x.id === id);
  if (act === "delete" && !confirm(`Delete "${m.name}" from quarantine?`)) return;
  if (act === "force-release" && !confirm(`The scan flagged "${m.name}" as ${m.scan.verdict.toLowerCase()}. Copy it to your Mac anyway?`)) return;
  const map = {
    start: ["start", {}], "force-start": ["start", { force: true }], stop: ["stop", {}], scan: ["scan", {}],
    release: ["release", {}], "force-release": ["release", { force: true }], "release-again": ["release", { again: true }],
    delete: ["delete", {}], reveal: ["reveal", {}],
  };
  const [action, body] = map[act];
  t.disabled = true;
  try {
    await api(`/api/items/${id}/${action}`, body);
    if (action === "release") toast("Copied to your Mac.");
  } catch (err) { toast(err.message, true); }
  poll();
});

$("checks").addEventListener("click", async (e) => {
  const fix = e.target.dataset && e.target.dataset.fix;
  if (!fix) return;
  if (fix === "import_vpn") return openVpn();
  if (fix === "settings") return openSettings(true);
  e.target.disabled = true;
  try {
    if (fix === "vm") await api("/api/vm/start", {});
    if (fix === "update") { await api("/api/update", {}); toast("Updating virus definitions. This takes a minute or two."); }
    if (fix === "enable_vpn") {
      if (!S.settings.vpn_config_present) return openVpn();
      await api("/api/settings", { use_vpn: true });
      toast("VPN turned on.");
    }
  } catch (err) { toast(err.message, true); }
  poll();
});

$("recheck").onclick = async () => {
  $("recheck").disabled = true; $("recheck").textContent = "Checking…";
  try { S = await api("/api/refresh", {}); render(); } catch (err) { toast(err.message, true); }
  $("recheck").disabled = false; $("recheck").textContent = "Check again";
};

$("open-downloads").onclick = () => api("/api/open-downloads", {}).catch((err) => toast(err.message, true));

/* VPN import */
function openVpn() { $("vpn-status").textContent = ""; $("vpn-dlg").showModal(); }
$("vpn-pick").onclick = () => $("vpn-file").click();
$("vpn-file").onchange = () => importVpn($("vpn-file").files[0]);
const vd = $("vpn-drop");
vd.addEventListener("dragover", (e) => { e.preventDefault(); vd.classList.add("dragging"); });
vd.addEventListener("dragleave", () => vd.classList.remove("dragging"));
vd.addEventListener("drop", (e) => { e.preventDefault(); vd.classList.remove("dragging"); importVpn(e.dataTransfer.files[0]); });

async function importVpn(file) {
  if (!file) return;
  $("vpn-status").textContent = "Testing the connection through Proton…";
  try {
    await api("/api/vpn/import", { conf_text: await file.text() });
    $("vpn-status").textContent = "It works. Torrent traffic now goes through this server.";
    toast("New VPN file is working.");
    setTimeout(() => $("vpn-dlg").close(), 1500);
  } catch (err) {
    $("vpn-status").textContent = err.message;
  }
  $("vpn-file").value = "";
  poll();
}

/* Settings */
function openSettings(focusKey = false) {
  const s = S.settings;
  $("vt-key").value = "";
  $("vt-key").placeholder = s.vt_key_set ? `Saved key ending ${s.vt_key_hint}. Paste a new one to replace it` : "Paste your API key";
  $("use-vpn").checked = s.use_vpn;
  $("vpn-hint").textContent = s.vpn_config_present ? "A Proton file is imported." : "No Proton file imported yet.";
  $("dl-dir").value = s.download_dir;
  $("seed").value = s.seed_minutes;
  $("settings-dlg").showModal();
  if (focusKey) $("vt-key").focus();
}
$("open-settings").onclick = () => S && openSettings();
$("settings-cancel").onclick = () => $("settings-dlg").close();
$("open-vpn-import").onclick = () => { $("settings-dlg").close(); openVpn(); };
$("settings-form").onsubmit = async (e) => {
  e.preventDefault();
  const body = { use_vpn: $("use-vpn").checked, download_dir: $("dl-dir").value, seed_minutes: $("seed").value };
  if ($("vt-key").value.trim()) body.vt_key = $("vt-key").value.trim();
  try {
    await api("/api/settings", body);
    $("settings-dlg").close();
    toast("Settings saved.");
  } catch (err) { toast(err.message, true); }
  poll();
};
$("update-btn").onclick = async () => {
  try { await api("/api/update", {}); toast("Updating virus definitions. This takes a minute or two."); $("settings-dlg").close(); }
  catch (err) { toast(err.message, true); }
};
$("quit-btn").onclick = async () => {
  if (S.items.some((m) => ["downloading", "scanning", "queued"].includes(m.status)) &&
      !confirm("A download or scan is running. Stopping the VM pauses it. Quit anyway?")) return;
  await api("/api/quit", { stop_vm: true }).catch(() => {});
  document.body.innerHTML = `<div class="empty" style="margin:40px">SafeTorrent has stopped. Open it again from its app icon.</div>`;
};

ready.then(poll);
