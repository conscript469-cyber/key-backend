const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const session = require("express-session");

const app = express();
const PORT = process.env.PORT || 10000;

// ── Config ─────────────────────────────────────
const ADMIN_KEY = process.env.ADMIN_KEY || "CHANGE_ME_ADMIN_SECRET";
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const DB_PATH = path.join(__dirname, "keys.json");

// ── Middleware ─────────────────────────────────
app.set("trust proxy", 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000,
    secure: false,
    httpOnly: true,
    sameSite: "lax"
  }
}));

// ── Database ──────────────────────────────────
function loadDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return {};
  }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ── Auth middleware ────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.authenticated) return next();
  if (req.headers["x-admin-key"] === ADMIN_KEY) {
    req.session.authenticated = true;
    return next();
  }
  return res.status(401).json({ error: "Unauthorized" });
}

// ═══════════════════════════════════════════════
//  API ROUTES
// ═══════════════════════════════════════════════

// Validate a key (used by the Frida client)
app.post("/api/validate", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) {
    return res.json({ valid: false, message: "Missing key or HWID" });
  }

  const db = loadDB();
  const entry = db[key];

  if (!entry) {
    return res.json({ valid: false, message: "Key not found" });
  }

  if (entry.revoked) {
    return res.json({ valid: false, message: "Key has been revoked" });
  }

  if (entry.expires && Date.now() > new Date(entry.expires).getTime()) {
    entry.revoked = true;
    saveDB(db);
    return res.json({ valid: false, message: "Key expired" });
  }

  // First-time activation — bind HWID
  if (!entry.hwid) {
    entry.hwid = hwid;
    entry.boundAt = new Date().toISOString();
    entry.activated = true;
    entry.lastSeen = new Date().toISOString();
    saveDB(db);
    return res.json({
      valid: true,
      message: "Key activated and HWID bound",
      hwid: entry.hwid,
      expires: entry.expires || null
    });
  }

  // HWID mismatch — reject
  if (entry.hwid !== hwid) {
    entry.attempts = (entry.attempts || 0) + 1;
    saveDB(db);
    return res.json({
      valid: false,
      message: "HWID mismatch — key is bound to another machine"
    });
  }

  // All good
  entry.lastSeen = new Date().toISOString();
  entry.usageCount = (entry.usageCount || 0) + 1;
  saveDB(db);

  res.json({
    valid: true,
    message: "Authenticated",
    hwid: entry.hwid,
    expires: entry.expires || null
  });
});

// Generate a key
app.post("/api/generate", requireAuth, (req, res) => {
  const { expires, note } = req.body;
  const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();

  const db = loadDB();
  db[key] = {
    key,
    revoked: false,
    hwid: null,
    activated: false,
    expires: expires || null,
    note: note || "",
    createdAt: new Date().toISOString(),
    boundAt: null,
    lastSeen: null,
    usageCount: 0,
    attempts: 0
  };
  saveDB(db);

  res.json({
    success: true,
    key,
    expires: expires || null,
    message: "Key generated successfully"
  });
});

// Bulk generate keys
app.post("/api/generate-bulk", requireAuth, (req, res) => {
  const { count = 1, expires, note } = req.body;
  const keys = [];
  const db = loadDB();

  for (let i = 0; i < Math.min(count, 100); i++) {
    const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    db[key] = {
      key,
      revoked: false,
      hwid: null,
      activated: false,
      expires: expires || null,
      note: note || "",
      createdAt: new Date().toISOString(),
      boundAt: null,
      lastSeen: null,
      usageCount: 0,
      attempts: 0
    };
    keys.push(key);
  }
  saveDB(db);

  res.json({ success: true, keys, count: keys.length });
});

// Revoke a key
app.post("/api/revoke", requireAuth, (req, res) => {
  const db = loadDB();
  const entry = db[req.body.key];
  if (entry) {
    entry.revoked = true;
    saveDB(db);
    return res.json({ success: true, message: "Key revoked" });
  }
  res.json({ success: false, message: "Key not found" });
});

// Un-revoke a key
app.post("/api/unrevoke", requireAuth, (req, res) => {
  const db = loadDB();
  const entry = db[req.body.key];
  if (entry) {
    entry.revoked = false;
    saveDB(db);
    return res.json({ success: true, message: "Key restored" });
  }
  res.json({ success: false, message: "Key not found" });
});

// Delete a key permanently
app.post("/api/delete", requireAuth, (req, res) => {
  const db = loadDB();
  if (db[req.body.key]) {
    delete db[req.body.key];
    saveDB(db);
    return res.json({ success: true, message: "Key deleted permanently" });
  }
  res.json({ success: false, message: "Key not found" });
});

// Reset HWID on a key (so user can activate on new machine)
app.post("/api/reset-hwid", requireAuth, (req, res) => {
  const db = loadDB();
  const entry = db[req.body.key];
  if (entry) {
    entry.hwid = null;
    entry.activated = false;
    entry.boundAt = null;
    entry.usageCount = 0;
    saveDB(db);
    return res.json({
      success: true,
      message: "HWID reset — key can be reactivated"
    });
  }
  res.json({ success: false, message: "Key not found" });
});

// List all keys
app.post("/api/list", requireAuth, (req, res) => {
  const db = loadDB();
  const keys = Object.values(db);

  // Sort: newest first
  keys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  const { filter } = req.body;
  let filtered = keys;

  if (filter === "active") filtered = keys.filter(k => !k.revoked);
  else if (filter === "revoked") filtered = keys.filter(k => k.revoked);
  else if (filter === "activated") filtered = keys.filter(k => k.activated);
  else if (filter === "unactivated") filtered = keys.filter(k => !k.activated);

  res.json({
    success: true,
    total: keys.length,
    filtered: filtered.length,
    keys: filtered
  });
});

// Stats
app.get("/api/stats", requireAuth, (req, res) => {
  const db = loadDB();
  const keys = Object.values(db);
  res.json({
    total: keys.length,
    activated: keys.filter(k => k.activated).length,
    revoked: keys.filter(k => k.revoked).length,
    unactivated: keys.filter(k => !k.activated).length,
    active: keys.filter(k => !k.revoked && k.activated).length
  });
});

// Change admin password
app.post("/api/change-password", requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (currentPassword !== ADMIN_KEY) {
    return res.json({ success: false, message: "Current password is wrong" });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.json({ success: false, message: "New password must be 6+ chars" });
  }
  res.json({
    success: true,
    message: "Password updated. Set ADMIN_KEY env var to: " + newPassword,
    note: "This change is NOT persistent — update the ADMIN_KEY env var on Render dashboard"
  });
});

// ── Login ──────────────────────────────────────
app.post("/api/login", (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_KEY) {
    req.session.authenticated = true;
    return res.json({ success: true });
  }
  return res.json({ success: false, message: "Wrong password" });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get("/api/check-auth", (req, res) => {
  res.json({ authenticated: !!req.session.authenticated });
});

// ═══════════════════════════════════════════════
//  ADMIN DASHBOARD (served as static HTML)
// ═══════════════════════════════════════════════

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Key System Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'Inter', -apple-system, sans-serif;
  background: #0a0a0f;
  color: #e0e0e0;
  min-height: 100vh;
}
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #12121a; }
::-webkit-scrollbar-thumb { background: #2a2a3a; border-radius: 3px; }

/* Login */
.login-overlay {
  position: fixed; inset: 0;
  display: flex; align-items: center; justify-content: center;
  background: #0a0a0f;
  z-index: 9999;
}
.login-card {
  background: #14141e;
  border: 1px solid #2a2a3a;
  border-radius: 16px;
  padding: 48px 40px;
  width: 400px;
  text-align: center;
}
.login-card h1 {
  font-size: 24px;
  font-weight: 800;
  background: linear-gradient(135deg, #ec4899, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin-bottom: 8px;
}
.login-card p { color: #888; font-size: 14px; margin-bottom: 32px; }
.login-card input {
  width: 100%;
  padding: 14px 16px;
  background: #1a1a28;
  border: 1px solid #2a2a3a;
  border-radius: 10px;
  color: #fff;
  font-size: 15px;
  outline: none;
  transition: border-color .2s;
  margin-bottom: 16px;
}
.login-card input:focus { border-color: #ec4899; }
.login-card button {
  width: 100%;
  padding: 14px;
  background: linear-gradient(135deg, #ec4899, #8b5cf6);
  border: none;
  border-radius: 10px;
  color: #fff;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: opacity .2s;
}
.login-card button:hover { opacity: .9; }
.login-error { color: #ef4444; font-size: 13px; margin-top: 12px; display: none; }

/* Layout */
.app { display: none; }
.app.visible { display: block; }
header {
  background: #14141e;
  border-bottom: 1px solid #2a2a3a;
  padding: 16px 32px;
  display: flex;
  align-items: center;
  justify-content: space-between;
}
header h1 {
  font-size: 20px;
  font-weight: 700;
  background: linear-gradient(135deg, #ec4899, #8b5cf6);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
header .subtitle { color: #666; font-size: 12px; margin-left: 8px; font-weight: 400; }
.header-actions { display: flex; align-items: center; gap: 16px; }
.header-actions .stats-badge {
  font-size: 12px;
  color: #888;
  background: #1a1a28;
  padding: 6px 14px;
  border-radius: 20px;
  border: 1px solid #2a2a3a;
}
.logout-btn {
  background: #2a2a3a;
  border: none;
  color: #aaa;
  padding: 8px 18px;
  border-radius: 8px;
  cursor: pointer;
  font-size: 13px;
  transition: all .2s;
}
.logout-btn:hover { background: #3a3a4a; color: #fff; }

.container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

/* Stats row */
.stats-row {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 28px;
}
.stat-card {
  background: #14141e;
  border: 1px solid #2a2a3a;
  border-radius: 12px;
  padding: 20px;
}
.stat-card .stat-value {
  font-size: 28px;
  font-weight: 800;
  margin-bottom: 4px;
}
.stat-card .stat-label { font-size: 13px; color: #888; }
.stat-card.total .stat-value { color: #60a5fa; }
.stat-card.active .stat-value { color: #34d399; }
.stat-card.revoked .stat-value { color: #f87171; }
.stat-card.unused .stat-value { color: #fbbf24; }

/* Action cards row */
.actions-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 16px;
  margin-bottom: 28px;
}
.action-card {
  background: #14141e;
  border: 1px solid #2a2a3a;
  border-radius: 12px;
  padding: 20px 24px;
}
.action-card h3 {
  font-size: 14px;
  font-weight: 600;
  color: #aaa;
  margin-bottom: 14px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
.inline-form {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
  align-items: center;
}
.inline-form input, .inline-form select {
  padding: 10px 14px;
  background: #1a1a28;
  border: 1px solid #2a2a3a;
  border-radius: 8px;
  color: #fff;
  font-size: 14px;
  outline: none;
  flex: 1;
  min-width: 120px;
}
.inline-form input:focus, .inline-form select:focus { border-color: #ec4899; }
.inline-form button {
  padding: 10px 20px;
  background: linear-gradient(135deg, #ec4899, #8b5cf6);
  border: none;
  border-radius: 8px;
  color: #fff;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
  transition: opacity .2s;
}
.inline-form button:hover { opacity: .85; }
.inline-form button.sec {
  background: #2a2a3a;
  color: #ccc;
}
.inline-form button.danger {
  background: linear-gradient(135deg, #dc2626, #b91c1c);
}
.inline-form button.success {
  background: linear-gradient(135deg, #059669, #047857);
}
.inline-result {
  margin-top: 10px;
  font-size: 12px;
  color: #34d399;
  word-break: break-all;
}
.inline-result.error { color: #ef4444; }

/* Filters & search */
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  gap: 12px;
  flex-wrap: wrap;
}
.toolbar-left { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.filter-btn {
  padding: 8px 16px;
  background: #1a1a28;
  border: 1px solid #2a2a3a;
  border-radius: 8px;
  color: #888;
  font-size: 13px;
  cursor: pointer;
  transition: all .2s;
}
.filter-btn:hover { border-color: #444; color: #ccc; }
.filter-btn.active {
  background: linear-gradient(135deg, #ec4899, #8b5cf6);
  border-color: transparent;
  color: #fff;
}
.search-box {
  padding: 8px 14px;
  background: #1a1a28;
  border: 1px solid #2a2a3a;
  border-radius: 8px;
  color: #fff;
  font-size: 13px;
  outline: none;
  width: 220px;
}
.search-box:focus { border-color: #ec4899; }

/* Table */
.table-wrap {
  background: #14141e;
  border: 1px solid #2a2a3a;
  border-radius: 12px;
  overflow: hidden;
}
table { width: 100%; border-collapse: collapse; }
thead { background: #1a1a28; }
th {
  padding: 12px 16px;
  text-align: left;
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.5px;
  color: #666;
  cursor: pointer;
  user-select: none;
  white-space: nowrap;
}
th:hover { color: #aaa; }
td {
  padding: 12px 16px;
  font-size: 13px;
  border-top: 1px solid #1f1f2e;
  vertical-align: middle;
}
tr:hover td { background: #1a1a28; }
.key-cell { font-family: 'Courier New', monospace; font-size: 12px; color: #fbbf24; }
.status-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 600;
}
.status-badge.active { background: rgba(52, 211, 153, 0.15); color: #34d399; }
.status-badge.revoked { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.status-badge.unused { background: rgba(251, 191, 36, 0.15); color: #fbbf24; }
.hwid-cell { font-family: 'Courier New', monospace; font-size: 11px; color: #60a5fa; max-width: 140px; overflow: hidden; text-overflow: ellipsis; }
.note-cell { max-width: 150px; overflow: hidden; text-overflow: ellipsis; color: #888; }
.actions-cell { display: flex; gap: 6px; }
.actions-cell button {
  padding: 5px 12px;
  border: none;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 500;
  cursor: pointer;
  transition: all .2s;
}
.btn-revoke { background: rgba(239, 68, 68, 0.15); color: #f87171; }
.btn-revoke:hover { background: rgba(239, 68, 68, 0.3); }
.btn-restore { background: rgba(52, 211, 153, 0.15); color: #34d399; }
.btn-restore:hover { background: rgba(52, 211, 153, 0.3); }
.btn-delete { background: rgba(239, 68, 68, 0.1); color: #ef4444; }
.btn-delete:hover { background: rgba(239, 68, 68, 0.25); }
.btn-reset { background: rgba(96, 165, 250, 0.15); color: #60a5fa; }
.btn-reset:hover { background: rgba(96, 165, 250, 0.3); }
.empty-state { padding: 48px; text-align: center; color: #555; }
.empty-state .big { font-size: 40px; margin-bottom: 12px; }
.loading { text-align: center; padding: 40px; color: #555; font-size: 14px; }
input[type="datetime-local"] { color-scheme: dark; }

/* Toast */
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  padding: 14px 24px;
  border-radius: 10px;
  font-size: 13px;
  font-weight: 500;
  z-index: 999;
  animation: slideIn .3s ease;
  max-width: 400px;
}
.toast.success { background: #065f46; color: #6ee7b7; border: 1px solid #047857; }
.toast.error { background: #7f1d1d; color: #fca5a5; border: 1px solid #b91c1c; }
.toast.info { background: #1e3a5f; color: #93c5fd; border: 1px solid #2563eb; }
@keyframes slideIn {
  from { transform: translateX(100%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}

@media (max-width: 900px) {
  .stats-row { grid-template-columns: repeat(2, 1fr); }
  .actions-row { grid-template-columns: 1fr; }
  .container { padding: 16px; }
  .toolbar { flex-direction: column; align-items: stretch; }
  .toolbar-left { justify-content: center; }
  .search-box { width: 100%; }
  .actions-cell { flex-wrap: wrap; }
}
</style>
</head>
<body>

<!-- Login -->
<div class="login-overlay" id="loginOverlay">
  <div class="login-card">
    <h1>Key System</h1>
    <p>Admin Dashboard — Animal Company</p>
    <input type="password" id="loginPass" placeholder="Enter admin password" autofocus>
    <button onclick="login()">Unlock Dashboard</button>
    <div class="login-error" id="loginError">Wrong password</div>
  </div>
</div>

<!-- App -->
<div class="app" id="app">
  <header>
    <div>
      <h1>Key System <span class="subtitle">Admin Panel</span></h1>
    </div>
    <div class="header-actions">
      <span class="stats-badge" id="headerStats">—</span>
      <button class="logout-btn" onclick="logout()">Logout</button>
    </div>
  </header>

  <div class="container">
    <!-- Stats -->
    <div class="stats-row" id="statsRow">
      <div class="stat-card total"><div class="stat-value" id="statTotal">—</div><div class="stat-label">Total Keys</div></div>
      <div class="stat-card active"><div class="stat-value" id="statActive">—</div><div class="stat-label">Activated</div></div>
      <div class="stat-card revoked"><div class="stat-value" id="statRevoked">—</div><div class="stat-label">Revoked</div></div>
      <div class="stat-card unused"><div class="stat-value" id="statUnused">—</div><div class="stat-label">Unactivated</div></div>
    </div>

    <!-- Actions -->
    <div class="actions-row">
      <div class="action-card">
        <h3>Generate Key</h3>
        <div class="inline-form">
          <input type="datetime-local" id="genExpires">
          <input type="text" id="genNote" placeholder="Note (optional)">
          <button onclick="generateKey()">Generate</button>
        </div>
        <div class="inline-result" id="genResult"></div>
      </div>
      <div class="action-card">
        <h3>Bulk Generate</h3>
        <div class="inline-form">
          <input type="number" id="bulkCount" value="5" min="1" max="100" style="max-width:80px">
          <input type="datetime-local" id="bulkExpires">
          <input type="text" id="bulkNote" placeholder="Note (optional)">
          <button onclick="bulkGenerate()">Generate ×<span id="bulkCountLabel">5</span></button>
        </div>
        <div class="inline-result" id="bulkResult"></div>
      </div>
      <div class="action-card">
        <h3>Revoke / Restore</h3>
        <div class="inline-form">
          <input type="text" id="manageKey" placeholder="AC-... key" style="min-width:200px;font-family:monospace">
          <button class="danger" onclick="revokeKey()">Revoke</button>
          <button class="success" onclick="unrevokeKey()">Restore</button>
          <button class="danger" onclick="deleteKey()">Delete</button>
        </div>
        <div class="inline-result" id="manageResult"></div>
      </div>
      <div class="action-card">
        <h3>Reset HWID</h3>
        <div class="inline-form">
          <input type="text" id="resetKey" placeholder="AC-... key" style="min-width:200px;font-family:monospace">
          <button class="sec" onclick="resetHWID()">Reset HWID</button>
        </div>
        <div class="inline-result" id="resetResult"></div>
        <div style="margin-top:8px;font-size:11px;color:#666;">
          Allows a key to be activated on a different machine.
        </div>
      </div>
    </div>

    <!-- Toolbar -->
    <div class="toolbar">
      <div class="toolbar-left">
        <button class="filter-btn active" data-filter="all" onclick="setFilter('all',this)">All</button>
        <button class="filter-btn" data-filter="active" onclick="setFilter('active',this)">Active</button>
        <button class="filter-btn" data-filter="revoked" onclick="setFilter('revoked',this)">Revoked</button>
        <button class="filter-btn" data-filter="activated" onclick="setFilter('activated',this)">Activated</button>
        <button class="filter-btn" data-filter="unactivated" onclick="setFilter('unactivated',this)">Unactivated</button>
      </div>
      <input type="text" class="search-box" id="searchBox" placeholder="Search key, HWID, note..." oninput="renderTable()">
    </div>

    <!-- Table -->
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th onclick="sortBy('key')">Key</th>
            <th onclick="sortBy('status')">Status</th>
            <th onclick="sortBy('hwid')">HWID</th>
            <th onclick="sortBy('note')">Note</th>
            <th onclick="sortBy('createdAt')">Created</th>
            <th onclick="sortBy('expires')">Expires</th>
            <th onclick="sortBy('lastSeen')">Last Seen</th>
            <th onclick="sortBy('usageCount')">Uses</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="tableBody">
          <tr><td colspan="9" class="loading">Loading keys...</td></tr>
        </tbody>
      </table>
    </div>
  </div>
</div>

<script>
let allKeys = [];
let currentFilter = "all";
let sortField = "createdAt";
let sortDir = -1;
const toastContainer = document.createElement('div');
document.body.appendChild(toastContainer);

function toast(msg, type = "info") {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = msg;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function api(path, body = {}) {
  try {
    const res = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body)
    });
    return await res.json();
  } catch(e) {
    return { error: e.message };
  }
}

async function apiGet(path) {
  try {
    const res = await fetch(path, { credentials: 'include' });
    return await res.json();
  } catch(e) {
    return { error: e.message };
  }
}

// Login
async function login() {
  try {
    const pass = document.getElementById('loginPass').value;
    const res = await api('/api/login', { password: pass });
    if (res.success) {
      document.getElementById('loginOverlay').style.display = 'none';
      document.getElementById('app').classList.add('visible');
      loadData();
    } else {
      document.getElementById('loginError').style.display = 'block';
    }
  } catch(e) {
    document.getElementById('loginError').textContent = 'Error: ' + e.message;
    document.getElementById('loginError').style.display = 'block';
  }
}

document.getElementById('loginPass').addEventListener('keydown', e => {
  if (e.key === 'Enter') login();
});

async function logout() {
  await api('/api/logout');
  location.reload();
}

// Check session on load
(async function() {
  try {
    const auth = await apiGet('/api/check-auth');
    if (auth.authenticated) {
      document.getElementById('loginOverlay').style.display = 'none';
      document.getElementById('app').classList.add('visible');
      loadData();
    }
  } catch(e) {}
})();

// Bulk count sync
document.getElementById('bulkCount').addEventListener('input', function() {
  document.getElementById('bulkCountLabel').textContent = this.value;
});

// Data
async function loadData() {
  await Promise.all([loadStats(), loadKeys()]);
}

async function loadStats() {
  try {
    const s = await apiGet('/api/stats');
    document.getElementById('statTotal').textContent = s.total;
    document.getElementById('statActive').textContent = s.activated;
    document.getElementById('statRevoked').textContent = s.revoked;
    document.getElementById('statUnused').textContent = s.unactivated;
    document.getElementById('headerStats').textContent = s.total + ' keys · ' + s.active + ' active';
  } catch(e) { document.getElementById('headerStats').textContent = 'Offline'; }
}

async function loadKeys() {
  try {
    const res = await api('/api/list');
    if (res.success) {
      allKeys = res.keys;
      renderTable();
    }
  } catch(e) {
    document.getElementById('tableBody').innerHTML =
      '<tr><td colspan="9" class="empty-state"><div class="big">⚠</div>Cannot reach backend</td></tr>';
  }
}

function setFilter(f, btn) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderTable();
}

function sortBy(field) {
  if (sortField === field) sortDir *= -1;
  else { sortField = field; sortDir = -1; }
  renderTable();
}

function renderTable() {
  const search = document.getElementById('searchBox').value.toLowerCase();
  let filtered = allKeys;

  if (currentFilter === 'active') filtered = filtered.filter(k => !k.revoked);
  else if (currentFilter === 'revoked') filtered = filtered.filter(k => k.revoked);
  else if (currentFilter === 'activated') filtered = filtered.filter(k => k.activated);
  else if (currentFilter === 'unactivated') filtered = filtered.filter(k => !k.activated);

  if (search) {
    filtered = filtered.filter(k =>
      k.key.toLowerCase().includes(search) ||
      (k.hwid && k.hwid.toLowerCase().includes(search)) ||
      (k.note && k.note.toLowerCase().includes(search))
    );
  }

  filtered.sort((a, b) => {
    let va = a[sortField], vb = b[sortField];
    if (sortField === 'status') {
      va = a.revoked ? 'revoked' : a.activated ? 'active' : 'unused';
      vb = b.revoked ? 'revoked' : b.activated ? 'active' : 'unused';
    }
    if (!va) va = '';
    if (!vb) vb = '';
    return va < vb ? sortDir : va > vb ? -sortDir : 0;
  });

  const tbody = document.getElementById('tableBody');
  if (!filtered.length) {
    tbody.innerHTML = '<tr><td colspan="9" class="empty-state"><div class="big">🔑</div>No keys found</td></tr>';
    return;
  }

  tbody.innerHTML = filtered.map(k => {
    const status = k.revoked ? 'revoked' : k.activated ? 'active' : 'unused';
    const statusLabel = k.revoked ? 'Revoked' : k.activated ? 'Active' : 'Unused';
    const expires = k.expires ? new Date(k.expires).toLocaleString() : '-';
    const created = k.createdAt ? new Date(k.createdAt).toLocaleString() : '-';
    const lastSeen = k.lastSeen ? new Date(k.lastSeen).toLocaleString() : '-';
    const hwid = k.hwid || '-';

    return '<tr>' +
      '<td class="key-cell">' + k.key + '</td>' +
      '<td><span class="status-badge ' + status + '">' + statusLabel + '</span></td>' +
      '<td class="hwid-cell" title="' + hwid + '">' + hwid + '</td>' +
      '<td class="note-cell" title="' + (k.note || '') + '">' + (k.note || '-') + '</td>' +
      '<td style="font-size:11px;color:#888">' + created + '</td>' +
      '<td style="font-size:11px;color:' + (k.expires && new Date(k.expires) < Date.now() ? '#ef4444' : '#888') + '">' + expires + '</td>' +
      '<td style="font-size:11px;color:#888">' + lastSeen + '</td>' +
      '<td style="text-align:center;font-size:12px;color:#888">' + (k.usageCount || 0) + '</td>' +
      '<td class="actions-cell">' +
        (k.revoked
          ? '<button class="btn-restore" onclick="doUnrevoke(\'' + k.key + '\')">Restore</button>'
          : '<button class="btn-revoke" onclick="doRevoke(\'' + k.key + '\')">Revoke</button>'
        ) +
        '<button class="btn-reset" onclick="doReset(\'' + k.key + '\')">HWID</button>' +
        '<button class="btn-delete" onclick="doDelete(\'' + k.key + '\')">Del</button>' +
      '</td>' +
      '</tr>';
  }).join('');
}

// Actions
async function generateKey() {
  const expires = document.getElementById('genExpires').value;
  const note = document.getElementById('genNote').value;
  const res = await api('/api/generate', {
    expires: expires ? new Date(expires).toISOString() : null,
    note
  });
  const el = document.getElementById('genResult');
  if (res.success) {
    el.textContent = '✓ ' + res.key;
    el.className = 'inline-result';
    toast('Key generated: ' + res.key, 'success');
    loadData();
  } else {
    el.textContent = '✗ ' + (res.message || 'Error');
    el.className = 'inline-result error';
  }
}

async function bulkGenerate() {
  const count = parseInt(document.getElementById('bulkCount').value) || 1;
  const expires = document.getElementById('bulkExpires').value;
  const note = document.getElementById('bulkNote').value;
  const res = await api('/api/generate-bulk', {
    count: Math.min(count, 100),
    expires: expires ? new Date(expires).toISOString() : null,
    note
  });
  const el = document.getElementById('bulkResult');
  if (res.success) {
    el.textContent = '✓ Generated ' + res.count + ' keys';
    el.className = 'inline-result';
    toast('Generated ' + res.count + ' keys', 'success');
    loadData();
  } else {
    el.textContent = '✗ ' + (res.message || 'Error');
    el.className = 'inline-result error';
  }
}

async function revokeKey() {
  const key = document.getElementById('manageKey').value.trim();
  if (!key) return toast('Enter a key', 'error');
  const res = await api('/api/revoke', { key });
  if (res.success) {
    document.getElementById('manageResult').textContent = '✓ Revoked';
    document.getElementById('manageResult').className = 'inline-result';
    toast('Key revoked', 'info');
    loadData();
  }
}

async function doRevoke(key) {
  await api('/api/revoke', { key });
  toast('Key revoked', 'info');
  loadData();
}

async function unrevokeKey() {
  const key = document.getElementById('manageKey').value.trim();
  if (!key) return toast('Enter a key', 'error');
  const res = await api('/api/unrevoke', { key });
  if (res.success) {
    document.getElementById('manageResult').textContent = '✓ Restored';
    document.getElementById('manageResult').className = 'inline-result';
    toast('Key restored', 'success');
    loadData();
  }
}

async function doUnrevoke(key) {
  await api('/api/unrevoke', { key });
  toast('Key restored', 'success');
  loadData();
}

async function deleteKey() {
  const key = document.getElementById('manageKey').value.trim();
  if (!key) return toast('Enter a key', 'error');
  if (!confirm('Permanently delete ' + key + '?')) return;
  const res = await api('/api/delete', { key });
  if (res.success) {
    document.getElementById('manageResult').textContent = '✓ Deleted';
    document.getElementById('manageResult').className = 'inline-result';
    toast('Key deleted', 'info');
    loadData();
  }
}

async function doDelete(key) {
  if (!confirm('Delete ' + key + '?')) return;
  await api('/api/delete', { key });
  toast('Key deleted', 'info');
  loadData();
}

async function resetHWID() {
  const key = document.getElementById('resetKey').value.trim();
  if (!key) return toast('Enter a key', 'error');
  if (!confirm('Reset HWID for ' + key + '? It can be activated on a new machine.')) return;
  const res = await api('/api/reset-hwid', { key });
  if (res.success) {
    document.getElementById('resetResult').textContent = '✓ HWID reset';
    document.getElementById('resetResult').className = 'inline-result';
    toast('HWID reset', 'success');
    loadData();
  }
}

async function doReset(key) {
  if (!confirm('Reset HWID for ' + key + '?')) return;
  await api('/api/reset-hwid', { key });
  toast('HWID reset', 'success');
  loadData();
}

// Auto-refresh every 15s
setInterval(loadData, 15000);
</script>
</body>
</html>`;

// ── Serve Dashboard at root ────────────────────
app.get("/", (req, res) => {
  res.type("text/html; charset=utf-8").send(DASHBOARD_HTML);
});

// ── Start ──────────────────────────────────────
app.listen(PORT, () => {
  console.log("Key System backend running on port " + PORT);
  console.log("Admin dashboard: http://localhost:" + PORT);
});
