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

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, "utf8")); }
  catch { return {}; }
}

function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

let activeToken = null;

app.post("/api/login", (req, res) => {
  if (req.body.password === ADMIN_PASS) {
    activeToken = crypto.randomBytes(16).toString("hex");
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

app.post("/api/validate", (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.json({ valid: false, message: "missing fields" });
  const db = loadDB();
  const entry = db[key];
  if (!entry) return res.json({ valid: false, message: "key not found" });
  if (entry.revoked) return res.json({ valid: false, message: "key revoked" });
  if (entry.expires && Date.now() > new Date(entry.expires).getTime()) {
    entry.revoked = true; saveDB(db);
    return res.json({ valid: false, message: "key expired" });
  }
  if (!entry.hwid) {
    entry.hwid = hwid; entry.activated = true;
    entry.boundAt = new Date().toISOString();
    entry.lastSeen = new Date().toISOString();
    saveDB(db);
    return res.json({ valid: true, hwid, expires: entry.expires });
  }
  if (entry.hwid !== hwid) return res.json({ valid: false, message: "hwid mismatch" });
  entry.lastSeen = new Date().toISOString();
  entry.usageCount = (entry.usageCount || 0) + 1;
  saveDB(db);
  res.json({ valid: true, hwid: entry.hwid, expires: entry.expires });
});

app.post("/api/generate", auth, (req, res) => {
  const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
  const db = loadDB();
  db[key] = { key, revoked: false, hwid: null, activated: false, expires: req.body.expires || null, note: req.body.note || "", createdAt: new Date().toISOString(), lastSeen: null, usageCount: 0 };
  saveDB(db);
  res.json({ success: true, key });
});

app.post("/api/generate-bulk", auth, (req, res) => {
  const count = Math.min(parseInt(req.body.count) || 1, 100);
  const keys = []; const db = loadDB();
  for (let i = 0; i < count; i++) {
    const key = "AC-" + crypto.randomBytes(12).toString("hex").toUpperCase();
    db[key] = { key, revoked: false, hwid: null, activated: false, expires: req.body.expires || null, note: req.body.note || "", createdAt: new Date().toISOString(), lastSeen: null, usageCount: 0 };
    keys.push(key);
  }
  saveDB(db);
  res.json({ success: true, keys, count });
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
  const f = req.body.filter;
  if (f === "active") keys = keys.filter(k => !k.revoked);
  else if (f === "revoked") keys = keys.filter(k => k.revoked);
  else if (f === "activated") keys = keys.filter(k => k.activated);
  else if (f === "unactivated") keys = keys.filter(k => !k.activated);
  res.json({ success: true, total: keys.length, keys });
});

app.get("/api/stats", auth, (req, res) => {
  const keys = Object.values(loadDB());
  res.json({ total: keys.length, activated: keys.filter(k => k.activated).length, revoked: keys.filter(k => k.revoked).length, unactivated: keys.filter(k => !k.activated).length });
});

app.listen(PORT, () => console.log("Key system running on port " + PORT));
