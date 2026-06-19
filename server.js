const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_KEY || "admin123";

app.use(express.json());

const DB_PATH = path.join(__dirname, "keys.json");

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
  catch { return {}; }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

let activeToken = null;

// ── API ────────────────────────────────────────

app.post("/api/login", (req, res) => {
  if (req.body.password === ADMIN_PASS) {
    activeToken = crypto.randomBytes(16).toString("hex");
    res.json({ success: true, token: activeToken });
  } else {
    res.json({ success: false });
  }
});

function auth(req, res, next) {
  if (req.body.token === activeToken || req.query.token === activeToken || req.headers["x-token"] === activeToken) {
    next();
  } else {
    res.status(401).json({ error: "unauthorized" });
  }
}

app.post("/api/validate", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ valid: false, message: "missing fields" });

  const db = loadDB();
  const entry = db[key];

  if (!entry) return res.json({ valid: false, message: "key not found" });
  if (entry.revoked) return res.json({ valid: false, message: "key revoked" });
  if (entry.expires && Date.now() > new Date(entry.expires).getTime()) {
    entry.revoked = true;
    saveDB(db);
    return res.json({ valid: false, message: "key expired" });
  }

  if (!entry.hwid) {
    entry.hwid = hwid;
    entry.activated = true;
    entry.boundAt = new Date().toISOString();
    entry.lastSeen = new Date().toISOString();
    saveDB(db);
    return res.json({ valid: true, hwid, expires: entry.expires });
  }

  if (entry.hwid !== hwid) {
    return res.json({ valid: false, message: "hwid mismatch" });
  }

  entry.lastSeen = new Date().toISOString();
  entry.usageCount = (entry.usageCount || 0) + 1;
  saveDB(db);
  res.json({ valid: true, hwid: entry.hwid, expires: entry.expires });
});

app.post("/api/generate", auth, (req, res) => {
  const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
  const db = loadDB();
  db[key] = {
    key,
    revoked: false,
    hwid: null,
    activated: false,
    expires: req.body.expires || null,
    note: req.body.note || "",
    createdAt: new Date().toISOString(),
    lastSeen: null,
    usageCount: 0
  };
  saveDB(db);
  res.json({ success: true, key });
});

app.post("/api/generate-bulk", auth, (req, res) => {
  const count = Math.min(parseInt(req.body.count) || 1, 100);
  const keys = [];
  const db = loadDB();
  for (let i = 0; i < count; i++) {
    const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    db[key] = {
      key, revoked: false, hwid: null, activated: false,
      expires: req.body.expires || null, note: req.body.note || "",
      createdAt: new Date().toISOString(), lastSeen: null, usageCount: 0
    };
    keys.push(key);
  }
  saveDB(db);
  res.json({ success: true, keys, count: keys.length });
});

app.post("/api/revoke", auth, (req, res) => {
  const db = loadDB();
  if (db[req.body.key]) { db[req.body.key].revoked = true; saveDB(db); res.json({ success: true }); }
  else res.json({ success: false, message: "not found" });
});

app.post("/api/unrevoke", auth, (req, res) => {
  const db = loadDB();
  if (db[req.body.key]) { db[req.body.key].revoked = false; saveDB(db); res.json({ success: true }); }
  else res.json({ success: false, message: "not found" });
});

app.post("/api/delete", auth, (req, res) => {
  const db = loadDB();
  if (db[req.body.key]) { delete db[req.body.key]; saveDB(db); res.json({ success: true }); }
  else res.json({ success: false, message: "not found" });
});

app.post("/api/reset-hwid", auth, (req, res) => {
  const db = loadDB();
  const entry = db[req.body.key];
  if (entry) { entry.hwid = null; entry.activated = false; entry.boundAt = null; entry.usageCount = 0; saveDB(db); res.json({ success: true }); }
  else res.json({ success: false, message: "not found" });
});

app.post("/api/list", auth, (req, res) => {
  const db = loadDB();
  let keys = Object.values(db);
  keys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const filter = req.body.filter;
  if (filter === "active") keys = keys.filter(k => !k.revoked);
  else if (filter === "revoked") keys = keys.filter(k => k.revoked);
  else if (filter === "activated") keys = keys.filter(k => k.activated);
  else if (filter === "unactivated") keys = keys.filter(k => !k.activated);

  res.json({ success: true, total: keys.length, keys });
});

app.get("/api/stats", auth, (req, res) => {
  const keys = Object.values(loadDB());
  res.json({
    total: keys.length,
    activated: keys.filter(k => k.activated).length,
    revoked: keys.filter(k => k.revoked).length,
    unactivated: keys.filter(k => !k.activated).length
  });
});

// ── Dashboard HTML ─────────────────────────────

app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Key Admin</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0d1117; color: #c9d1d9; }
input, select, button { font-family: inherit; }
.card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px; }
.stats { font-size: 24px; font-weight: 700; }
.stats span { font-size: 13px; color: #8b949e; font-weight: 400; }
.row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-bottom: 16px; }
.row input, .row select { padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; }
.row input:focus, .row select:focus { border-color: #58a6ff; outline: none; }
.btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }
.btn-primary { background: #238636; color: #fff; }
.btn-primary:hover { background: #2ea043; }
.btn-danger { background: #da3633; color: #fff; }
.btn-danger:hover { background: #f85149; }
.btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
.btn-secondary:hover { background: #30363d; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 10px 12px; font-size: 12px; color: #8b949e; border-bottom: 1px solid #21262d; cursor: pointer; }
th:hover { color: #c9d1d9; }
td { padding: 10px 12px; font-size: 13px; border-bottom: 1px solid #21262d; }
tr:hover td { background: #1c2128; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
.badge-active { background: #1b3a2d; color: #3fb950; }
.badge-revoked { background: #3d1f1e; color: #f85149; }
.badge-unused { background: #3d2e00; color: #d29922; }
.key-text { font-family: monospace; font-size: 12px; color: #f0883e; }
.hwid-text { font-family: monospace; font-size: 11px; color: #58a6ff; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.small { font-size: 11px; color: #8b949e; }
.actions { display: flex; gap: 4px; }
.result { font-size: 12px; color: #3fb950; margin-top: 4px; }
.result.error { color: #f85149; }
.login-wrap { display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.login-box { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 40px; width: 360px; text-align: center; }
.login-box h1 { font-size: 22px; margin-bottom: 4px; }
.login-box p { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
.login-box input { width: 100%; padding: 10px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 14px; margin-bottom: 12px; }
.login-box input:focus { border-color: #58a6ff; outline: none; }
.login-box button { width: 100%; padding: 10px; background: #238636; border: none; border-radius: 6px; color: #fff; font-size: 14px; font-weight: 600; cursor: pointer; }
.login-box button:hover { background: #2ea043; }
.login-error { color: #f85149; font-size: 13px; margin-top: 10px; display: none; }
.hidden { display: none; }
.header { display: flex; justify-content: space-between; align-items: center; padding: 16px 24px; background: #161b22; border-bottom: 1px solid #30363d; margin-bottom: 20px; }
.header h1 { font-size: 18px; }
.container { max-width: 1400px; margin: 0 auto; padding: 0 24px 40px; }
.toolbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-wrap: wrap; gap: 8px; }
.toolbar-left { display: flex; gap: 6px; flex-wrap: wrap; }
.filter-btn { padding: 6px 14px; background: #21262d; border: 1px solid #30363d; border-radius: 6px; color: #8b949e; font-size: 12px; cursor: pointer; }
.filter-btn:hover { border-color: #58a6ff; color: #c9d1d9; }
.filter-btn.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
.search-box { padding: 6px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; font-size: 13px; width: 200px; }
.search-box:focus { border-color: #58a6ff; outline: none; }
</style>
</head>
<body>

<div id="loginScreen" class="login-wrap">
  <div class="login-box">
    <h1>Key System</h1>
    <p>Admin Dashboard</p>
    <input type="password" id="loginPass" placeholder="Admin password" autofocus>
    <button onclick="login()">Unlock</button>
    <div class="login-error" id="loginError">Wrong password</div>
  </div>
</div>

<div id="app" class="hidden">
  <div class="header">
    <h1>Key System</h1>
    <div style="display:flex;align-items:center;gap:12px">
      <span class="small" id="headerStats"></span>
      <button class="btn btn-secondary" onclick="logout()">Logout</button>
    </div>
  </div>
  <div class="container">
    <div class="grid" id="statsGrid">
      <div class="card"><div class="stats" id="statTotal">-</div><div><span>Total Keys</span></div></div>
      <div class="card"><div class="stats" id="statActive">-</div><div><span>Activated</span></div></div>
      <div class="card"><div class="stats" id="statRevoked">-</div><div><span>Revoked</span></div></div>
      <div class="card"><div class="stats" id="statUnused">-</div><div><span>Unactivated</span></div></div>
    </div>

    <div class="card" style="margin-bottom:16px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
        <div>
          <div class="small" style="margin-bottom:6px">Generate Key</div>
          <div class="row">
            <input type="datetime-local" id="genExpires" style="flex:1">
            <input type="text" id="genNote" placeholder="note" style="flex:1">
            <button class="btn btn-primary" onclick="generateKey()">Generate</button>
          </div>
          <div class="result" id="genResult"></div>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px">Bulk Generate</div>
          <div class="row">
            <input type="number" id="bulkCount" value="5" min="1" max="100" style="width:60px">
            <input type="datetime-local" id="bulkExpires" style="flex:1">
            <button class="btn btn-primary" onclick="bulkGenerate()">Generate x<span id="bulkLabel">5</span></button>
          </div>
          <div class="result" id="bulkResult"></div>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px">Revoke / Restore / Delete</div>
          <div class="row">
            <input type="text" id="manageKey" placeholder="AC-..." style="flex:1;font-family:monospace">
            <button class="btn btn-danger" onclick="revokeKey()">Revoke</button>
            <button class="btn btn-primary" onclick="unrevokeKey()">Restore</button>
            <button class="btn btn-danger" onclick="deleteKey()">Delete</button>
          </div>
          <div class="result" id="manageResult"></div>
        </div>
        <div>
          <div class="small" style="margin-bottom:6px">Reset HWID</div>
          <div class="row">
            <input type="text" id="resetKey" placeholder="AC-..." style="flex:1;font-family:monospace">
            <button class="btn btn-secondary" onclick="resetHWID()">Reset HWID</button>
          </div>
          <div class="result" id="resetResult"></div>
          <div class="small" style="margin-top:4px">Allows key to activate on a new machine</div>
        </div>
      </div>
    </div>

    <div class="toolbar">
      <div class="toolbar-left">
        <button class="filter-btn active" onclick="setFilter('all',this)">All</button>
        <button class="filter-btn" onclick="setFilter('active',this)">Active</button>
        <button class="filter-btn" onclick="setFilter('revoked',this)">Revoked</button>
        <button class="filter-btn" onclick="setFilter('activated',this)">Activated</button>
        <button class="filter-btn" onclick="setFilter('unactivated',this)">Unactivated</button>
      </div>
      <input type="text" class="search-box" id="searchBox" placeholder="Search..." oninput="render()">
    </div>

    <div class="card" style="padding:0;overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th onclick="sort('key')">Key</th>
            <th onclick="sort('status')">Status</th>
            <th onclick="sort('hwid')">HWID</th>
            <th onclick="sort('note')">Note</th>
            <th onclick="sort('createdAt')">Created</th>
            <th onclick="sort('expires')">Expires</th>
            <th onclick="sort('lastSeen')">Last Seen</th>
            <th onclick="sort('usageCount')">Uses</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="tableBody"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let keys = [];
let filter = "all";
let sortField = "createdAt";
let sortDir = -1;
let token = localStorage.getItem("token");

const api = (path, body) =>
  fetch(path, { method:"POST", headers: { "Content-Type":"application/json", "x-token":token }, body: JSON.stringify(body) })
    .then(r => r.json());

if (token) { document.getElementById("loginScreen").classList.add("hidden"); document.getElementById("app").classList.remove("hidden"); load(); }

function login() {
  const pass = document.getElementById("loginPass").value;
  api("/api/login", { password: pass }).then(r => {
    if (r.success) {
      token = r.token;
      localStorage.setItem("token", token);
      document.getElementById("loginScreen").classList.add("hidden");
      document.getElementById("app").classList.remove("hidden");
      load();
    } else {
      document.getElementById("loginError").style.display = "block";
    }
  });
}

document.getElementById("loginPass").addEventListener("keydown", e => { if (e.key === "Enter") login(); });

function logout() {
  token = null;
  localStorage.removeItem("token");
  location.reload();
}

document.getElementById("bulkCount").addEventListener("input", function() {
  document.getElementById("bulkLabel").textContent = this.value;
});

function load() {
  api("/api/stats", {}).then(s => {
    document.getElementById("statTotal").textContent = s.total || 0;
    document.getElementById("statActive").textContent = s.activated || 0;
    document.getElementById("statRevoked").textContent = s.revoked || 0;
    document.getElementById("statUnused").textContent = s.unactivated || 0;
    document.getElementById("headerStats").textContent = s.total + " keys";
  });
  api("/api/list", {}).then(r => { if (r.success) { keys = r.keys; render(); } });
}

function setFilter(f, btn) {
  filter = f;
  document.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");
  render();
}

function sort(field) {
  if (sortField === field) sortDir *= -1;
  else { sortField = field; sortDir = -1; }
  render();
}

function render() {
  const search = document.getElementById("searchBox").value.toLowerCase();
  let filtered = keys;

  if (filter === "active") filtered = filtered.filter(k => !k.revoked);
  else if (filter === "revoked") filtered = filtered.filter(k => k.revoked);
  else if (filter === "activated") filtered = filtered.filter(k => k.activated);
  else if (filter === "unactivated") filtered = filtered.filter(k => !k.activated);

  if (search) {
    filtered = filtered.filter(k =>
      k.key.toLowerCase().includes(search) ||
      (k.hwid && k.hwid.toLowerCase().includes(search)) ||
      (k.note && k.note.toLowerCase().includes(search))
    );
  }

  filtered.sort((a, b) => {
    let va = a[sortField], vb = b[sortField];
    if (sortField === "status") { va = a.revoked ? "revoked" : a.activated ? "active" : "unused"; vb = b.revoked ? "revoked" : b.activated ? "active" : "unused"; }
    if (!va) va = ""; if (!vb) vb = "";
    return va < vb ? sortDir : va > vb ? -sortDir : 0;
  });

  const tbody = document.getElementById("tableBody");
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#8b949e">No keys found</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(k => {
    const st = k.revoked ? "revoked" : k.activated ? "active" : "unused";
    const sl = k.revoked ? "Revoked" : k.activated ? "Active" : "Unused";
    return '<tr>' +
      '<td class="key-text">' + k.key + '</td>' +
      '<td><span class="badge badge-' + st + '">' + sl + '</span></td>' +
      '<td class="hwid-text" title="' + (k.hwid || "") + '">' + (k.hwid || "-") + '</td>' +
      '<td class="small">' + (k.note || "-") + '</td>' +
      '<td class="small">' + (k.createdAt ? new Date(k.createdAt).toLocaleString() : "-") + '</td>' +
      '<td class="small">' + (k.expires ? new Date(k.expires).toLocaleString() : "-") + '</td>' +
      '<td class="small">' + (k.lastSeen ? new Date(k.lastSeen).toLocaleString() : "-") + '</td>' +
      '<td style="text-align:center;color:#8b949e;font-size:12px">' + (k.usageCount || 0) + '</td>' +
      '<td class="actions">' +
        (k.revoked
          ? '<button class="btn btn-primary" style="padding:4px 8px;font-size:11px" onclick="doUnrevoke(\'' + k.key + '\')">Restore</button>'
          : '<button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="doRevoke(\'' + k.key + '\')">Revoke</button>'
        ) +
        '<button class="btn btn-secondary" style="padding:4px 8px;font-size:11px" onclick="doReset(\'' + k.key + '\')">HWID</button>' +
        '<button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="doDelete(\'' + k.key + '\')">Del</button>' +
      '</td></tr>';
  }).join("");
}

function doRevoke(key) { api("/api/revoke", { key }).then(load); }
function doUnrevoke(key) { api("/api/unrevoke", { key }).then(load); }
function doReset(key) { if (confirm("Reset HWID for " + key + "?")) api("/api/reset-hwid", { key }).then(load); }
function doDelete(key) { if (confirm("Delete " + key + "?")) api("/api/delete", { key }).then(load); }

function generateKey() {
  const expires = document.getElementById("genExpires").value;
  const note = document.getElementById("genNote").value;
  api("/api/generate", { expires: expires ? new Date(expires).toISOString() : null, note }).then(r => {
    document.getElementById("genResult").textContent = r.success ? r.key : "error";
    document.getElementById("genResult").className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

function bulkGenerate() {
  const count = parseInt(document.getElementById("bulkCount").value) || 1;
  const expires = document.getElementById("bulkExpires").value;
  api("/api/generate-bulk", { count: Math.min(count,100), expires: expires ? new Date(expires).toISOString() : null }).then(r => {
    const el = document.getElementById("bulkResult");
    el.textContent = r.success ? "Generated " + r.count + " keys" : "error";
    el.className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

function revokeKey() {
  const key = document.getElementById("manageKey").value.trim();
  if (!key) return;
  api("/api/revoke", { key }).then(r => {
    document.getElementById("manageResult").textContent = r.success ? "Revoked" : "Not found";
    document.getElementById("manageResult").className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

function unrevokeKey() {
  const key = document.getElementById("manageKey").value.trim();
  if (!key) return;
  api("/api/unrevoke", { key }).then(r => {
    document.getElementById("manageResult").textContent = r.success ? "Restored" : "Not found";
    document.getElementById("manageResult").className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

function deleteKey() {
  const key = document.getElementById("manageKey").value.trim();
  if (!key || !confirm("Delete " + key + "?")) return;
  api("/api/delete", { key }).then(r => {
    document.getElementById("manageResult").textContent = r.success ? "Deleted" : "Not found";
    document.getElementById("manageResult").className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

function resetHWID() {
  const key = document.getElementById("resetKey").value.trim();
  if (!key || !confirm("Reset HWID for " + key + "?")) return;
  api("/api/reset-hwid", { key }).then(r => {
    document.getElementById("resetResult").textContent = r.success ? "HWID reset" : "Not found";
    document.getElementById("resetResult").className = "result" + (r.success ? "" : " error");
    if (r.success) load();
  });
}

setInterval(load, 15000);
</script>
</body>
</html>`);
});

app.listen(PORT, () => console.log("Key system running on port " + PORT));
