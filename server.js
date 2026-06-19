const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_PASS = process.env.ADMIN_KEY || "admin123";

app.use(express.json());
app.use(express.static(__dirname));

const DB_PATH = path.join(__dirname, "keys.json");
const DATABASE_URL = process.env.DATABASE_URL;

let db = null;
let usingPg = false;

async function initDB() {
  if (DATABASE_URL) {
    try {
      const { Pool } = require("pg");
      const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });
      await pool.query(`
        CREATE TABLE IF NOT EXISTS keys (
          key_id TEXT PRIMARY KEY,
          revoked BOOLEAN DEFAULT FALSE,
          hwid TEXT,
          activated BOOLEAN DEFAULT FALSE,
          expires TIMESTAMP,
          note TEXT DEFAULT '',
          max_uses INTEGER,
          created_at TIMESTAMP DEFAULT NOW(),
          bound_at TIMESTAMP,
          last_seen TIMESTAMP,
          last_ip TEXT,
          usage_count INTEGER DEFAULT 0
        )
      `);
      db = pool;
      usingPg = true;
      console.log("Using PostgreSQL");
      return;
    } catch (e) {
      console.log("PostgreSQL unavailable, falling back to JSON:", e.message);
    }
  }
  console.log("Using JSON file storage");
}

function loadJSON() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
  catch { return {}; }
}

function saveJSON(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

function makeEntry(key, expires, note, maxUses) {
  return {
    key, revoked: false, hwid: null, activated: false,
    expires: expires || null, note: note || "", maxUses: maxUses || null,
    createdAt: new Date().toISOString(), lastSeen: null, lastIp: null, usageCount: 0
  };
}

var activeToken = crypto.createHash("sha256").update(ADMIN_PASS).digest("hex").slice(0, 32);

app.post("/api/login", (req, res) => {
  if (req.body.password === ADMIN_PASS) {
    res.json({ success: true, token: activeToken });
  } else {
    res.json({ success: false });
  }
});

function auth(req, res, next) {
  const t = req.body.token || req.query.token || req.headers["x-token"];
  if (t === activeToken) { next(); }
  else { res.status(401).json({ error: "unauthorized" }); }
}

// ──
// POSTGRES helpers
// ──

async function pgFind(key) {
  const r = await db.query("SELECT * FROM keys WHERE key_id = $1", [key]);
  return r.rows[0] || null;
}

async function pgSave(key, data) {
  await db.query(`
    INSERT INTO keys (key_id, revoked, hwid, activated, expires, note, max_uses, created_at, bound_at, last_seen, last_ip, usage_count)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    ON CONFLICT (key_id) DO UPDATE SET
      revoked = EXCLUDED.revoked, hwid = EXCLUDED.hwid, activated = EXCLUDED.activated,
      expires = EXCLUDED.expires, note = EXCLUDED.note, max_uses = EXCLUDED.max_uses,
      bound_at = EXCLUDED.bound_at, last_seen = EXCLUDED.last_seen,
      last_ip = EXCLUDED.last_ip, usage_count = EXCLUDED.usage_count
  `, [
    data.key, data.revoked, data.hwid, data.activated,
    data.expires, data.note, data.maxUses,
    data.createdAt, data.boundAt, data.lastSeen,
    data.lastIp, data.usageCount || 0
  ]);
}

async function pgDelete(key) {
  await db.query("DELETE FROM keys WHERE key_id = $1", [key]);
}

async function pgAll() {
  const r = await db.query("SELECT * FROM keys ORDER BY created_at DESC");
  return r.rows.map(mapPG);
}

async function pgFiltered(filter, search) {
  let sql = "SELECT * FROM keys WHERE 1=1";
  const params = [];
  if (filter === "active") { sql += " AND revoked = FALSE"; }
  else if (filter === "revoked") { sql += " AND revoked = TRUE"; }
  else if (filter === "activated") { sql += " AND activated = TRUE"; }
  else if (filter === "unactivated") { sql += " AND activated = FALSE"; }
  if (search) {
    sql += " AND (LOWER(key_id) LIKE $1 OR LOWER(hwid) LIKE $1 OR LOWER(note) LIKE $1 OR LOWER(last_ip) LIKE $1)";
    params.push("%" + search.toLowerCase() + "%");
  }
  sql += " ORDER BY created_at DESC";
  const r = await db.query(sql, params);
  return r.rows.map(mapPG);
}

function mapPG(row) {
  return {
    key: row.key_id,
    revoked: row.revoked,
    hwid: row.hwid,
    activated: row.activated,
    expires: row.expires ? row.expires.toISOString() : null,
    note: row.note || "",
    maxUses: row.max_uses,
    createdAt: row.created_at ? row.created_at.toISOString() : null,
    boundAt: row.bound_at ? row.bound_at.toISOString() : null,
    lastSeen: row.last_seen ? row.last_seen.toISOString() : null,
    lastIp: row.last_ip,
    usageCount: row.usage_count || 0
  };
}

// ──
// Helper: pick JSON or PG
// ──

async function findEntry(key) {
  if (usingPg) return pgFind(key);
  const j = loadJSON();
  return j[key] || null;
}

async function saveEntry(data) {
  if (usingPg) { await pgSave(data.key, data); return; }
  const j = loadJSON();
  j[data.key] = data;
  saveJSON(j);
}

async function deleteEntry(key) {
  if (usingPg) { await pgDelete(key); return; }
  const j = loadJSON();
  delete j[key];
  saveJSON(j);
}

async function allEntries() {
  if (usingPg) return pgAll();
  return Object.values(loadJSON());
}

async function filteredEntries(filter, search) {
  if (usingPg) return pgFiltered(filter, search);
  let keys = Object.values(loadJSON());
  if (filter === "active") keys = keys.filter(k => !k.revoked);
  else if (filter === "revoked") keys = keys.filter(k => k.revoked);
  else if (filter === "activated") keys = keys.filter(k => k.activated);
  else if (filter === "unactivated") keys = keys.filter(k => !k.activated);
  if (search) {
    const s = search.toLowerCase();
    keys = keys.filter(k =>
      k.key.toLowerCase().includes(s) ||
      (k.hwid && k.hwid.toLowerCase().includes(s)) ||
      (k.note && k.note.toLowerCase().includes(s)) ||
      (k.lastIp && k.lastIp.includes(s))
    );
  }
  keys.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  return keys;
}

async function bulkSave(entries) {
  if (usingPg) {
    const client = await db.connect();
    try {
      await client.query("BEGIN");
      for (const data of entries) {
        await client.query(`
          INSERT INTO keys (key_id, revoked, hwid, activated, expires, note, max_uses, created_at, bound_at, last_seen, last_ip, usage_count)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
          ON CONFLICT (key_id) DO UPDATE SET
            revoked = EXCLUDED.revoked, hwid = EXCLUDED.hwid, activated = EXCLUDED.activated,
            expires = EXCLUDED.expires, note = EXCLUDED.note, max_uses = EXCLUDED.max_uses,
            bound_at = EXCLUDED.bound_at, last_seen = EXCLUDED.last_seen,
            last_ip = EXCLUDED.last_ip, usage_count = EXCLUDED.usage_count
        `, [
          data.key, data.revoked, data.hwid, data.activated,
          data.expires, data.note, data.maxUses,
          data.createdAt, data.boundAt, data.lastSeen,
          data.lastIp, data.usageCount || 0
        ]);
      }
      await client.query("COMMIT");
    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }
    return;
  }
  const j = loadJSON();
  for (const data of entries) {
    j[data.key] = data;
  }
  saveJSON(j);
}

// ──
// Migrate JSON to PG if needed
// ──

async function migrateIfNeeded() {
  if (!usingPg) return;
  const j = loadJSON();
  const keys = Object.keys(j);
  if (keys.length === 0) return;
  console.log("Migrating " + keys.length + " keys from JSON to PostgreSQL...");
  for (const k of keys) {
    await pgSave(k, j[k]);
  }
  fs.renameSync(DB_PATH, DB_PATH + ".bak");
  console.log("Migration complete (JSON backed up to keys.json.bak)");
}

// ──
// Routes
// ──

app.post("/api/validate", async (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ valid: false, message: "missing fields" });
  try {
    let entry = await findEntry(key);
    if (!entry) return res.json({ valid: false, message: "key not found" });
    if (entry.revoked) return res.json({ valid: false, message: "key revoked" });
    if (entry.expires && Date.now() > new Date(entry.expires).getTime()) {
      entry.revoked = true; entry.key = key; await saveEntry(entry);
      return res.json({ valid: false, message: "key expired" });
    }
    if (entry.maxUses && (entry.usageCount || 0) >= entry.maxUses) {
      return res.json({ valid: false, message: "max uses reached" });
    }
    if (!entry.hwid) {
      entry.hwid = hwid; entry.activated = true;
      entry.boundAt = new Date().toISOString();
      entry.lastIp = req.ip || req.connection.remoteAddress || "unknown";
      entry.lastSeen = new Date().toISOString();
      entry.key = key;
      await saveEntry(entry);
      return res.json({ valid: true, hwid, expires: entry.expires, maxUses: entry.maxUses });
    }
    if (entry.hwid !== hwid) return res.json({ valid: false, message: "hwid mismatch" });
    entry.lastIp = req.ip || req.connection.remoteAddress || "unknown";
    entry.lastSeen = new Date().toISOString();
    entry.usageCount = (entry.usageCount || 0) + 1;
    entry.key = key;
    await saveEntry(entry);
    res.json({ valid: true, hwid: entry.hwid, expires: entry.expires, usageCount: entry.usageCount, maxUses: entry.maxUses });
  } catch (e) {
    console.error("validate error:", e);
    res.json({ valid: false, message: "server error" });
  }
});

app.post("/api/generate", auth, async (req, res) => {
  try {
    const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    const entry = makeEntry(key, req.body.expires, req.body.note, req.body.maxUses);
    await saveEntry(entry);
    res.json({ success: true, key });
  } catch (e) {
    console.error("generate error:", e);
    res.json({ success: false, message: "server error" });
  }
});

app.post("/api/generate-bulk", auth, async (req, res) => {
  try {
    const count = Math.min(parseInt(req.body.count) || 1, 100);
    const keys = [];
    const entries = [];
    for (let i = 0; i < count; i++) {
      const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
      keys.push(key);
      entries.push(makeEntry(key, req.body.expires, req.body.note, req.body.maxUses));
    }
    await bulkSave(entries);
    res.json({ success: true, keys, count });
  } catch (e) {
    console.error("bulk generate error:", e);
    res.json({ success: false, message: "server error" });
  }
});

app.post("/api/revoke", auth, async (req, res) => {
  try {
    const entry = await findEntry(req.body.key);
    if (entry) { entry.revoked = true; entry.key = req.body.key; await saveEntry(entry); res.json({ success: true }); }
    else res.json({ success: false, message: "not found" });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/unrevoke", auth, async (req, res) => {
  try {
    const entry = await findEntry(req.body.key);
    if (entry) { entry.revoked = false; entry.key = req.body.key; await saveEntry(entry); res.json({ success: true }); }
    else res.json({ success: false, message: "not found" });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/delete", auth, async (req, res) => {
  try {
    const entry = await findEntry(req.body.key);
    if (entry) { await deleteEntry(req.body.key); res.json({ success: true }); }
    else res.json({ success: false, message: "not found" });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/reset-hwid", auth, async (req, res) => {
  try {
    const entry = await findEntry(req.body.key);
    if (entry) {
      entry.hwid = null; entry.activated = false; entry.boundAt = null; entry.usageCount = 0; entry.key = req.body.key;
      await saveEntry(entry);
      res.json({ success: true });
    } else res.json({ success: false, message: "not found" });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/list", auth, async (req, res) => {
  try {
    let keys = await filteredEntries(req.body.filter, req.body.search);
    const total = keys.length;
    const page = Math.max(1, parseInt(req.body.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.body.limit) || 50));
    const start = (page - 1) * limit;
    keys = keys.slice(start, start + limit);
    res.json({ success: true, total, page, limit, pages: Math.ceil(total / limit), keys });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/export", auth, async (req, res) => {
  try {
    const keys = await filteredEntries(req.body.filter, req.body.search);
    let csv = "Key,Status,HWID,Note,MaxUses,UsageCount,Created,BoundAt,Expires,LastSeen,LastIP\n";
    keys.forEach(k => {
      const status = k.revoked ? "Revoked" : k.activated ? "Active" : "Unused";
      csv += [k.key, status, k.hwid || "", k.note || "", k.maxUses || "", k.usageCount || 0, k.createdAt || "", k.boundAt || "", k.expires || "", k.lastSeen || "", k.lastIp || ""].join(",") + "\n";
    });
    res.json({ success: true, csv, count: keys.length });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/bulk-revoke", auth, async (req, res) => {
  try {
    const list = req.body.keys || [];
    let count = 0;
    for (const k of list) {
      const entry = await findEntry(k);
      if (entry) { entry.revoked = true; entry.key = k; await saveEntry(entry); count++; }
    }
    res.json({ success: true, count });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/bulk-delete", auth, async (req, res) => {
  try {
    const list = req.body.keys || [];
    let count = 0;
    for (const k of list) {
      const entry = await findEntry(k);
      if (entry) { await deleteEntry(k); count++; }
    }
    res.json({ success: true, count });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/purge-expired", auth, async (req, res) => {
  try {
    const keys = await allEntries();
    const now = Date.now();
    let removed = 0;
    for (const k of keys) {
      if (k.expires && now > new Date(k.expires).getTime()) {
        await deleteEntry(k.key); removed++;
      }
    }
    res.json({ success: true, removed });
  } catch (e) { res.json({ success: false, message: "server error" }); }
});

app.post("/api/db-status", auth, async (req, res) => {
  var available = false;
  if (usingPg) {
    try {
      await db.query("SELECT 1");
      available = true;
    } catch (e) { available = false; }
  } else {
    try {
      fs.accessSync(DB_PATH, fs.constants.R_OK | fs.constants.W_OK);
      available = true;
    } catch (e) { available = false; }
  }
  res.json({ database: usingPg ? "PostgreSQL" : "JSON file", usingPg, available });
});

app.post("/api/stats", auth, async (req, res) => {
  try {
    const keys = await allEntries();
    res.json({ total: keys.length, activated: keys.filter(k => k.activated).length, revoked: keys.filter(k => k.revoked).length, unactivated: keys.filter(k => !k.activated).length });
  } catch (e) { res.json({ total: 0, activated: 0, revoked: 0, unactivated: 0 }); }
});

// ──
// Start
// ──

async function start() {
  await initDB();
  await migrateIfNeeded();
  app.listen(PORT, () => console.log("Key system running on port " + PORT));
}

start();
