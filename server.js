// server.js
const express = require("express");
const cors    = require("cors");
const helmet  = require("helmet");
const { Pool } = require("pg");
const bcrypt  = require("bcryptjs");
const jwt     = require("jsonwebtoken");
const crypto  = require("crypto");

const app  = express();
const PORT = process.env.PORT || 3000;

const JWT_SECRET             = process.env.JWT_SECRET             || "change-me-in-production-please";
const OWNER_PANEL_PASSPHRASE = process.env.OWNER_PANEL_PASSPHRASE || "";
const HIDDEN_IP_USERS = new Set(
  (process.env.HIDDEN_IP_USERS || "").split(",").map(u => u.trim().toLowerCase()).filter(Boolean)
);

// ═══════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false,
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id           TEXT PRIMARY KEY,
      username     TEXT UNIQUE NOT NULL,
      password     TEXT NOT NULL,
      is_admin     BOOLEAN DEFAULT FALSE,
      is_owner     BOOLEAN DEFAULT FALSE,
      is_og        BOOLEAN DEFAULT FALSE,
      is_mod       BOOLEAN DEFAULT FALSE,
      is_vip       BOOLEAN DEFAULT FALSE,
      is_owner2    BOOLEAN DEFAULT FALSE,
      last_ip      TEXT DEFAULT NULL,
      ip_history   TEXT[] DEFAULT '{}',
      created_at   TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS game_state (
      user_id          TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      score            NUMERIC DEFAULT 0,
      luck_level       INT DEFAULT 1,
      luck_xp          NUMERIC DEFAULT 0,
      mult_level       INT DEFAULT 0,
      cd_level         INT DEFAULT 0,
      auto_level       INT DEFAULT 0,
      vault_level      INT DEFAULT 0,
      xp_level         INT DEFAULT 0,
      crit_level       INT DEFAULT 0,
      echo_level       INT DEFAULT 0,
      soul_level       INT DEFAULT 0,
      voidupg_level    INT DEFAULT 0,
      asc_level        INT DEFAULT 0,
      time_level       INT DEFAULT 0,
      forge_level      INT DEFAULT 0,
      prestige_level   INT DEFAULT 0,
      total_rolls      INT DEFAULT 0,
      legendary_count  INT DEFAULT 0,
      mythic_count     INT DEFAULT 0,
      divine_count     INT DEFAULT 0,
      celestial_count  INT DEFAULT 0,
      ethereal_count   INT DEFAULT 0,
      void_count       INT DEFAULT 0,
      primordial_count INT DEFAULT 0,
      omega_count      INT DEFAULT 0,
      crit_count       INT DEFAULT 0,
      echo_count       INT DEFAULT 0,
      achievements     TEXT[] DEFAULT '{}',
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS leaderboard_snapshots (
      id         SERIAL PRIMARY KEY,
      user_id    TEXT REFERENCES users(id) ON DELETE CASCADE,
      username   TEXT NOT NULL,
      score      NUMERIC NOT NULL,
      luck_level INT NOT NULL,
      prestige   INT DEFAULT 0,
      snapped_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  const adminId = "uid_admin_root";
  const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
  if (!ADMIN_PASSWORD) {
    console.warn("⚠️  ADMIN_PASSWORD env var not set — root admin account will not be created until it is.");
    return;
  }
  const existing = await pool.query("SELECT id FROM users WHERE id = $1", [adminId]);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query(
      `INSERT INTO users (id, username, password, is_admin) VALUES ($1, $2, $3, TRUE) ON CONFLICT DO NOTHING`,
      [adminId, "admin", hash]
    );
    await pool.query(
      `INSERT INTO game_state (user_id, score, luck_level, mult_level, cd_level, auto_level,
        vault_level, xp_level, crit_level, echo_level, soul_level, voidupg_level, asc_level,
        time_level, forge_level, prestige_level, total_rolls, legendary_count, mythic_count,
        divine_count, celestial_count, ethereal_count, void_count, primordial_count, omega_count,
        crit_count, echo_count)
       VALUES ($1, 999999999999, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100, 100,
               100, 999999, 9999, 9999, 9999, 999, 999, 99, 9, 1, 9999, 999)
       ON CONFLICT DO NOTHING`,
      [adminId]
    );
    console.log("✅ Root admin account created");
  } else {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, adminId]);
    console.log("✅ Root admin password synced from env");
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rooms (
      id            TEXT PRIMARY KEY,
      game          TEXT NOT NULL,
      host_user_id  TEXT NOT NULL,
      phase         TEXT NOT NULL DEFAULT 'waiting',
      max_players   INT NOT NULL DEFAULT 6,
      created_at    BIGINT NOT NULL
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS room_players (
      room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id    TEXT NOT NULL,
      username   TEXT NOT NULL,
      ready      BOOLEAN DEFAULT FALSE,
      bet_total  NUMERIC DEFAULT 0,
      bet_json   JSONB DEFAULT NULL,
      joined_at  BIGINT NOT NULL,
      PRIMARY KEY (room_id, user_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS room_chat (
      id         BIGSERIAL PRIMARY KEY,
      room_id    TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      ts         BIGINT NOT NULL,
      user_id    TEXT,
      username   TEXT,
      rank       TEXT,
      text       TEXT NOT NULL,
      system     BOOLEAN DEFAULT FALSE
    );
    CREATE INDEX IF NOT EXISTS room_chat_room_ts ON room_chat(room_id, ts);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS room_roulette_last (
      room_id     TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
      ts          BIGINT NOT NULL,
      number      INT NOT NULL,
      color       TEXT NOT NULL,
      result_json JSONB
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS room_blackjack_state (
      room_id     TEXT PRIMARY KEY REFERENCES rooms(id) ON DELETE CASCADE,
      updated_at  BIGINT NOT NULL,
      state_json  JSONB NOT NULL
    );
  `);

  const migrations = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner2       BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip         TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_history      TEXT[] DEFAULT '{}'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner        BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_og           BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_mod          BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_vip          BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS owner_token     TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS owner_token_exp TIMESTAMPTZ DEFAULT NULL`,
  ];
  for (const sql of migrations) {
    try { await pool.query(sql); } catch (e) { console.warn("Migration skipped:", e.message); }
  }

  console.log("✅ Database initialized");
}

// ═══════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
const ALLOWED_ORIGINS = new Set([
  "https://game-3v1.pages.dev",
  "https://rng.capitaldupe.com",
  "https://main.game-3v1.pages.dev",
  "https://b1f15f7.game-3v1.pages.dev",
  "https://4a23193c.game-3v1.pages.dev",
  ...(process.env.EXTRA_ORIGINS || "").split(",").map(o => o.trim()).filter(Boolean),
]);

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    if (/^https:\/\/[a-z0-9-]+\.game-3v1\.pages\.dev$/.test(origin)) return callback(null, true);
    callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));
app.use(express.json());

// ═══════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════
const _adminFailures = new Map();
const ADMIN_MAX_FAILS  = 10;
const ADMIN_LOCKOUT_MS = 15 * 60 * 1000;

function trackAdminFail(ip) {
  const f = _adminFailures.get(ip);
  if (!f || Date.now() - f.ts > ADMIN_LOCKOUT_MS) {
    _adminFailures.set(ip, { count: 1, ts: Date.now() });
  } else {
    f.count++;
  }
}

function isAdminLocked(ip) {
  const f = _adminFailures.get(ip);
  return f && f.count >= ADMIN_MAX_FAILS && Date.now() - f.ts < ADMIN_LOCKOUT_MS;
}

const _auditLog = [];
function audit(req, action, detail = '') {
  const ip    = getClientIP(req);
  const user  = req.user ? `${req.user.username}(${req.user.id})` : 'anon';
  const entry = `[${new Date().toISOString()}] ${action} | ${user} | IP:${ip} ${detail}`;
  _auditLog.unshift(entry);
  if (_auditLog.length > 500) _auditLog.pop();
  console.log('📋 AUDIT:', entry);
}

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
  try {
    const result = await pool.query(
      "SELECT id, username, is_admin, is_owner, is_owner2, is_og, is_mod, is_vip FROM users WHERE id=$1",
      [payload.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    req.user = {
      id: u.id, username: u.username,
      isAdmin: u.is_admin || false, isOwner: u.is_owner || false,
      isOwner2: u.is_owner2 || false, isOG: u.is_og || false,
      isMod: u.is_mod || false, isVIP: u.is_vip || false,
    };
    next();
  } catch { return res.status(500).json({ error: "Server error" }); }
}

async function requireAdmin(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
  try {
    const result = await pool.query("SELECT is_admin, is_owner, is_owner2 FROM users WHERE id=$1", [payload.id]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    if (!u.is_admin && !u.is_owner && !u.is_owner2) {
      trackAdminFail(ip);
      audit({ headers: req.headers, socket: req.socket, user: payload }, 'ADMIN_DENIED', req.path);
      return res.status(403).json({ error: "Admin only" });
    }
    req.user = { ...payload, isAdmin: u.is_admin, isOwner: u.is_owner, isOwner2: u.is_owner2 };
    next();
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
}

async function requireOwner(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
  try {
    const result = await pool.query("SELECT is_owner, is_owner2 FROM users WHERE id=$1", [payload.id]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    if (!u.is_owner && !u.is_owner2) {
      trackAdminFail(ip);
      audit({ headers: req.headers, socket: req.socket, user: payload }, 'OWNER_DENIED', req.path);
      return res.status(403).json({ error: "Owner only" });
    }
    req.user = { ...payload, isOwner: u.is_owner, isOwner2: u.is_owner2 };
    next();
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
}

async function requireMod(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }
  try {
    const result = await pool.query(
      "SELECT is_mod, is_admin, is_owner, is_owner2 FROM users WHERE id=$1", [payload.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    if (!u.is_mod && !u.is_admin && !u.is_owner && !u.is_owner2) {
      trackAdminFail(ip);
      audit({ headers: req.headers, socket: req.socket, user: payload }, 'MOD_DENIED', req.path);
      return res.status(403).json({ error: "Mod only" });
    }
    req.user = { ...payload, isMod: u.is_mod, isAdmin: u.is_admin, isOwner: u.is_owner, isOwner2: u.is_owner2 };
    next();
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
}

// ═══════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════
function makeToken(userRow) {
  return jwt.sign({ id: userRow.id, username: userRow.username }, JWT_SECRET, { expiresIn: "7d" });
}

function rowToState(row) {
  if (!row) return null;
  return {
    score: parseFloat(row.score) || 0, luckLevel: row.luck_level || 1,
    luckXP: parseFloat(row.luck_xp) || 0, multLevel: row.mult_level || 0,
    cdLevel: row.cd_level || 0, autoLevel: row.auto_level || 0,
    vaultLevel: row.vault_level || 0, xpLevel: row.xp_level || 0,
    critLevel: row.crit_level || 0, echoLevel: row.echo_level || 0,
    soulLevel: row.soul_level || 0, voidupgLevel: row.voidupg_level || 0,
    ascLevel: row.asc_level || 0, timeLevel: row.time_level || 0,
    forgeLevel: row.forge_level || 0, prestigeLevel: row.prestige_level || 0,
    totalRolls: row.total_rolls || 0, legendaryCount: row.legendary_count || 0,
    mythicCount: row.mythic_count || 0, divineCount: row.divine_count || 0,
    celestialCount: row.celestial_count || 0, etherealCount: row.ethereal_count || 0,
    voidCount: row.void_count || 0, primordialCount: row.primordial_count || 0,
    omegaCount: row.omega_count || 0, critCount: row.crit_count || 0,
    echoCount: row.echo_count || 0, achievements: row.achievements || [],
  };
}

function getClientIP(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    "unknown"
  );
}

async function recordIP(userId, ip) {
  if (!ip || ip === "unknown") return;
  try {
    await pool.query(
      `UPDATE users SET last_ip = $2, ip_history = (
         SELECT ARRAY(SELECT DISTINCT unnest(array_append(COALESCE(ip_history,'{}'), $2::TEXT)) LIMIT 20)
       ) WHERE id = $1`,
      [userId, ip]
    );
  } catch (e) { console.warn("IP record failed:", e.message); }
}

// ═══════════════════════════════════════
//  OWNER PASSPHRASE
// ═══════════════════════════════════════
const _ppFailures = new Map();
const PP_MAX_ATTEMPTS = 5;
const PP_LOCKOUT_MS   = 15 * 60 * 1000;

app.post("/api/owner/verify-passphrase", (req, res) => {
  const ip   = getClientIP(req);
  const fail = _ppFailures.get(ip);
  if (fail && fail.count >= PP_MAX_ATTEMPTS && Date.now() - fail.ts < PP_LOCKOUT_MS) {
    const mins = Math.ceil((PP_LOCKOUT_MS - (Date.now() - fail.ts)) / 60000);
    return res.status(429).json({ error: `Too many attempts. Try again in ${mins} min.` });
  }
  const { passphrase } = req.body || {};
  if (!passphrase) return res.status(400).json({ error: "Missing passphrase" });
  if (!OWNER_PANEL_PASSPHRASE) return res.status(500).json({ error: "OWNER_PANEL_PASSPHRASE not set on server" });
  if (passphrase !== OWNER_PANEL_PASSPHRASE) {
    if (!fail || Date.now() - fail.ts > PP_LOCKOUT_MS) _ppFailures.set(ip, { count: 1, ts: Date.now() });
    else fail.count++;
    const remaining = PP_MAX_ATTEMPTS - (_ppFailures.get(ip)?.count || 0);
    return res.status(401).json({ error: `Wrong passphrase. ${remaining} attempt(s) left.` });
  }
  _ppFailures.delete(ip);
  return res.json({ ok: true });
});

app.post("/api/owner/generate-token", requireOwner, async (req, res) => {
  try {
    const token = crypto.randomBytes(32).toString("hex");
    const exp   = new Date(Date.now() + 48 * 60 * 60 * 1000);
    await pool.query(`UPDATE users SET owner_token=$1, owner_token_exp=$2 WHERE id=$3`, [token, exp, req.user.id]);
    return res.json({ token, expires: exp.toISOString() });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.post("/api/owner/token-login", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: "Missing token" });
    const result = await pool.query(`SELECT * FROM users WHERE owner_token=$1`, [token]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid token" });
    const user = result.rows[0];
    if (!user.is_owner && !user.is_owner2) return res.status(403).json({ error: "Not an owner account" });
    if (new Date(user.owner_token_exp) < new Date()) return res.status(401).json({ error: "Token expired" });
    return res.json({
      token: makeToken(user),
      user: { id: user.id, username: user.username, isAdmin: user.is_admin, isOwner: user.is_owner || false, isOwner2: user.is_owner2 || false },
      expires: user.owner_token_exp,
    });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.get("/api/owner/audit", requireOwner, (req, res) => {
  audit(req, 'AUDIT_VIEW');
  res.json({ log: _auditLog });
});

app.get("/api/owner/ips", requireOwner, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, username, is_admin, is_owner, is_owner2, is_og, is_mod, is_vip, last_ip, ip_history, created_at FROM users ORDER BY created_at DESC`);
    const users = result.rows.map(u => HIDDEN_IP_USERS.has(u.username.toLowerCase()) ? { ...u, last_ip: '🔒 hidden', ip_history: [] } : u);
    return res.json({ users });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || username.length < 2) return res.status(400).json({ error: "Username must be 2+ chars" });
    if (!password || password.length < 6)  return res.status(400).json({ error: "Password must be 6+ chars" });
    const RESERVED = ['admin','owner','mod','moderator','staff','system','bot','server','support','root','administrator','capitaldupe','capital'];
    if (RESERVED.includes(username.toLowerCase())) return res.status(400).json({ error: "Username is reserved" });
    const exists = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);
    if (exists.rows.length) return res.status(409).json({ error: "Username already taken" });
    const id   = "u_" + Date.now() + "_" + Math.random().toString(36).slice(2);
    const hash = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (id, username, password) VALUES ($1, $2, $3)", [id, username, hash]);
    await pool.query("INSERT INTO game_state (user_id) VALUES ($1)", [id]);
    await recordIP(id, getClientIP(req));
    const u = { id, username, is_admin: false, is_owner: false, is_owner2: false, is_og: false, is_mod: false, is_vip: false };
    return res.json({ token: makeToken(u), user: { id, username, isAdmin: false, isOwner: false, isOwner2: false, isOG: false, isMod: false, isVIP: false } });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const result = await pool.query("SELECT * FROM users WHERE LOWER(username) = LOWER($1)", [username]);
    if (!result.rows.length) return res.status(401).json({ error: "Invalid credentials" });
    const user  = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });
    await recordIP(user.id, getClientIP(req));
    return res.json({
      token: makeToken(user),
      user: { id: user.id, username: user.username, isAdmin: user.is_admin, isOwner: user.is_owner || false, isOwner2: user.is_owner2 || false, isOG: user.is_og || false, isMod: user.is_mod || false, isVIP: user.is_vip || false },
    });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const user = result.rows[0];
    return res.json({ user: { id: user.id, username: user.username, isAdmin: user.is_admin, isOwner: user.is_owner || false, isOwner2: user.is_owner2 || false, isOG: user.is_og || false, isMod: user.is_mod || false, isVIP: user.is_vip || false } });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.get("/api/game/load", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.user.id]);
    return res.json({ state: rowToState(result.rows[0]) });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  GAMBLING ROUTE
// ═══════════════════════════════════════
app.post("/api/game/gamble", requireAuth, async (req, res) => {
  try {
    const { bet, delta, game } = req.body || {};
    const betAmt   = parseFloat(bet);
    const deltaAmt = parseFloat(delta);
    if (isNaN(betAmt) || betAmt <= 0) return res.status(400).json({ error: "Invalid bet" });
    if (isNaN(deltaAmt))               return res.status(400).json({ error: "Invalid delta" });
    if (!['roulette', 'blackjack', 'horses'].includes(game)) return res.status(400).json({ error: "Invalid game" });
    const MAX_BET = 1_000_000_000_000;
    if (betAmt > MAX_BET) return res.status(400).json({ error: `Max bet is ${MAX_BET}` });
    const MAX_WIN_MULT = game === 'roulette' ? 35 : game === 'horses' ? 12 : 2.5;
    if (deltaAmt > betAmt * MAX_WIN_MULT) return res.status(400).json({ error: "Invalid win amount" });
    if (deltaAmt < -betAmt)               return res.status(400).json({ error: "Invalid loss amount" });
    const cur = await pool.query("SELECT score FROM game_state WHERE user_id=$1", [req.user.id]);
    if (!cur.rows.length) return res.status(404).json({ error: "No game state found" });
    const curScore = parseFloat(cur.rows[0].score) || 0;
    if (betAmt > curScore) return res.status(400).json({ error: "Insufficient score" });
    const newScore = Math.max(0, curScore + deltaAmt);
    await pool.query("UPDATE game_state SET score=$1, updated_at=NOW() WHERE user_id=$2", [newScore, req.user.id]);
    audit(req, `GAMBLE_${game.toUpperCase()}`, `bet:${betAmt} delta:${deltaAmt} new:${newScore}`);
    return res.json({ ok: true, newScore });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.post("/api/game/save", requireAuth, async (req, res) => {
  try {
    const s = req.body || {};
    const clamp  = (v, min, max) => Math.min(max, Math.max(min, parseFloat(v) || 0));
    const clampI = (v, min, max) => Math.min(max, Math.max(min, parseInt(v)   || 0));
    const cur = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.user.id]);
    const curState = cur.rows[0] || {};
    const MAX_SCORE      = 1e18;
    const curScore       = parseFloat(curState.score) || 0;
    const submittedScore = clamp(s.score, 0, MAX_SCORE);
    const MAX_SCORE_PER_SEC = 50_000_000;
    const lastSaveTime = curState.updated_at ? new Date(curState.updated_at).getTime() : 0;
    const elapsedSecs  = lastSaveTime ? Math.max(0, (Date.now() - lastSaveTime) / 1000) : 300;
    const maxEarnable  = curScore + (MAX_SCORE_PER_SEC * elapsedSecs);
    const newScore     = Math.min(submittedScore, maxEarnable);
    const curLuck      = parseInt(curState.luck_level) || 1;
    const newLuck      = clampI(s.luckLevel, curLuck, 100);
    const curPrestige  = parseInt(curState.prestige_level) || 0;
    const newPrestige  = clampI(s.prestigeLevel, curPrestige, curPrestige + 1);
    const upg  = (key, curKey, max = 200) => clampI(s[key], parseInt(curState[curKey]) || 0, max);
    const rolls = (key, curKey) => Math.max(parseInt(curState[curKey]) || 0, clampI(s[key], 0, 1e9));
    await pool.query(
      `INSERT INTO game_state (user_id, score, luck_level, luck_xp, mult_level, cd_level, auto_level,
        vault_level, xp_level, crit_level, echo_level, soul_level, voidupg_level, asc_level, time_level,
        forge_level, prestige_level, total_rolls, legendary_count, mythic_count, divine_count,
        celestial_count, ethereal_count, void_count, primordial_count, omega_count, crit_count,
        echo_count, achievements, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,NOW())
       ON CONFLICT (user_id) DO UPDATE SET
        score=$2, luck_level=$3, luck_xp=$4, mult_level=$5, cd_level=$6, auto_level=$7,
        vault_level=$8, xp_level=$9, crit_level=$10, echo_level=$11, soul_level=$12,
        voidupg_level=$13, asc_level=$14, time_level=$15, forge_level=$16, prestige_level=$17,
        total_rolls=$18, legendary_count=$19, mythic_count=$20, divine_count=$21,
        celestial_count=$22, ethereal_count=$23, void_count=$24, primordial_count=$25,
        omega_count=$26, crit_count=$27, echo_count=$28, achievements=$29, updated_at=NOW()`,
      [req.user.id, newScore, newLuck, clamp(s.luckXP, 0, 1e9),
       upg('multLevel','mult_level'), upg('cdLevel','cd_level'), upg('autoLevel','auto_level'),
       upg('vaultLevel','vault_level'), upg('xpLevel','xp_level'), upg('critLevel','crit_level'),
       upg('echoLevel','echo_level'), upg('soulLevel','soul_level'), upg('voidupgLevel','voidupg_level'),
       upg('ascLevel','asc_level'), upg('timeLevel','time_level'), upg('forgeLevel','forge_level'),
       newPrestige, rolls('totalRolls','total_rolls'), rolls('legendaryCount','legendary_count'),
       rolls('mythicCount','mythic_count'), rolls('divineCount','divine_count'),
       rolls('celestialCount','celestial_count'), rolls('etherealCount','ethereal_count'),
       rolls('voidCount','void_count'), rolls('primordialCount','primordial_count'),
       rolls('omegaCount','omega_count'), rolls('critCount','crit_count'),
       rolls('echoCount','echo_count'), Array.isArray(s.achievements) ? s.achievements : []]
    );
    return res.json({ ok: true });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  LEADERBOARD
// ═══════════════════════════════════════
app.get("/api/leaderboard", async (req, res) => {
  try {
    const limit    = Math.min(parseInt(req.query.limit) || 50, 100);
    const sortBy   = req.query.sort || "score";
    const colMap   = { score: "gs.score", prestige: "gs.prestige_level", rolls: "gs.total_rolls", luck: "gs.luck_level" };
    const orderCol = colMap[sortBy] || "gs.score";
    const result = await pool.query(
      `SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
        gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls, gs.omega_count, gs.void_count,
        gs.legendary_count, gs.mythic_count, gs.divine_count, gs.achievements, gs.updated_at
       FROM users u JOIN game_state gs ON gs.user_id = u.id
       ORDER BY ${orderCol} DESC LIMIT $1`, [limit]
    );
    return res.json({
      leaderboard: result.rows.map((r, i) => ({
        rank: i + 1, id: r.id, username: r.username,
        isAdmin: r.is_admin, isOwner: r.is_owner || false, isOwner2: r.is_owner2 || false,
        isOG: r.is_og || false, isMod: r.is_mod || false, isVIP: r.is_vip || false,
        score: parseFloat(r.score), luckLevel: r.luck_level, prestigeLevel: r.prestige_level,
        totalRolls: r.total_rolls, omegaCount: r.omega_count, voidCount: r.void_count,
        legendaryCount: r.legendary_count, mythicCount: r.mythic_count, divineCount: r.divine_count,
        achievements: (r.achievements || []).length, lastSeen: r.updated_at,
      })),
    });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  MOD ROUTES
// ═══════════════════════════════════════
app.get("/api/mod/users", requireMod, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
             u.created_at, gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls
      FROM users u LEFT JOIN game_state gs ON gs.user_id = u.id ORDER BY gs.score DESC NULLS LAST`);
    return res.json({ users: result.rows });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.post("/api/mod/reset/:id", requireMod, async (req, res) => {
  try {
    const target = await pool.query("SELECT is_admin, is_owner, is_owner2 FROM users WHERE id=$1", [req.params.id]);
    if (!target.rows.length) return res.status(404).json({ error: "User not found" });
    const t = target.rows[0];
    if (t.is_admin || t.is_owner || t.is_owner2) {
      audit(req, 'MOD_RESET_BLOCKED', `tried to reset admin/owner ${req.params.id}`);
      return res.status(403).json({ error: "Cannot reset admins or owners" });
    }
    await pool.query(`UPDATE game_state SET score=0, luck_level=1, luck_xp=0, mult_level=0, cd_level=0,
      auto_level=0, vault_level=0, xp_level=0, crit_level=0, echo_level=0, soul_level=0,
      voidupg_level=0, asc_level=0, time_level=0, forge_level=0, prestige_level=0, total_rolls=0,
      legendary_count=0, mythic_count=0, divine_count=0, celestial_count=0, ethereal_count=0,
      void_count=0, primordial_count=0, omega_count=0, crit_count=0, echo_count=0,
      achievements='{}', updated_at=NOW() WHERE user_id=$1`, [req.params.id]);
    audit(req, 'MOD_RESET', `reset user ${req.params.id}`);
    return res.json({ ok: true });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
             u.last_ip, u.ip_history, u.created_at, gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls
      FROM users u LEFT JOIN game_state gs ON gs.user_id = u.id ORDER BY gs.score DESC NULLS LAST`);
    const users = result.rows.map(u => HIDDEN_IP_USERS.has(u.username.toLowerCase()) ? { ...u, last_ip: '🔒 hidden', ip_history: [] } : u);
    return res.json({ users });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.get("/api/admin/user/:id", requireAdmin, async (req, res) => {
  try {
    const u  = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    const gs = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.params.id]);
    if (!u.rows.length) return res.status(404).json({ error: "User not found" });
    let user = u.rows[0];
    if (HIDDEN_IP_USERS.has(user.username.toLowerCase())) user = { ...user, last_ip: '🔒 hidden', ip_history: [] };
    return res.json({ user, state: rowToState(gs.rows[0]) });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.patch("/api/admin/user/:id", requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const s = req.body || {};
    const rankUpdates = [], rankVals = [];
    let ri = 1;
    if (s.isOwner  !== undefined) { rankUpdates.push(`is_owner=$${ri++}`);  rankVals.push(!!s.isOwner); }
    if (s.isOwner2 !== undefined) { rankUpdates.push(`is_owner2=$${ri++}`); rankVals.push(!!s.isOwner2); }
    if (s.isAdmin  !== undefined && id !== "uid_admin_root") { rankUpdates.push(`is_admin=$${ri++}`); rankVals.push(!!s.isAdmin); }
    if (s.isOG     !== undefined) { rankUpdates.push(`is_og=$${ri++}`);     rankVals.push(!!s.isOG); }
    if (s.isMod    !== undefined) { rankUpdates.push(`is_mod=$${ri++}`);    rankVals.push(!!s.isMod); }
    if (s.isVIP    !== undefined) { rankUpdates.push(`is_vip=$${ri++}`);    rankVals.push(!!s.isVIP); }
    if (rankUpdates.length > 0) { rankVals.push(id); await pool.query(`UPDATE users SET ${rankUpdates.join(", ")} WHERE id=$${ri}`, rankVals); }
    if (s.password) { const hash = await bcrypt.hash(s.password, 10); await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hash, id]); }
    const map = {
      score: "score", luckLevel: "luck_level", prestigeLevel: "prestige_level",
      totalRolls: "total_rolls", voidCount: "void_count", omegaCount: "omega_count",
      multLevel: "mult_level", cdLevel: "cd_level", autoLevel: "auto_level",
      vaultLevel: "vault_level", xpLevel: "xp_level", critLevel: "crit_level",
      voidupgLevel: "voidupg_level", echoLevel: "echo_level", soulLevel: "soul_level",
      ascLevel: "asc_level", timeLevel: "time_level", forgeLevel: "forge_level",
    };
    const fields = [], vals = [id]; let idx = 2;
    for (const [jsKey, dbCol] of Object.entries(map)) {
      if (s[jsKey] !== undefined) { fields.push(`${dbCol}=$${idx++}`); vals.push(s[jsKey]); }
    }
    if (fields.length > 0) {
      fields.push("updated_at=NOW()");
      await pool.query(`INSERT INTO game_state (user_id) VALUES ($1) ON CONFLICT DO NOTHING`, [id]);
      await pool.query(`UPDATE game_state SET ${fields.join(", ")} WHERE user_id=$1`, vals);
    }
    return res.json({ ok: true });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.delete("/api/admin/user/:id", requireAdmin, async (req, res) => {
  try {
    if (req.params.id === "uid_admin_root") return res.status(403).json({ error: "Cannot delete root admin" });
    await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);
    return res.json({ ok: true });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

app.post("/api/admin/reset/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query(`UPDATE game_state SET score=0, luck_level=1, luck_xp=0, mult_level=0, cd_level=0,
      auto_level=0, vault_level=0, xp_level=0, crit_level=0, echo_level=0, soul_level=0,
      voidupg_level=0, asc_level=0, time_level=0, forge_level=0, prestige_level=0, total_rolls=0,
      legendary_count=0, mythic_count=0, divine_count=0, celestial_count=0, ethereal_count=0,
      void_count=0, primordial_count=0, omega_count=0, crit_count=0, echo_count=0,
      achievements='{}', updated_at=NOW() WHERE user_id=$1`, [req.params.id]);
    return res.json({ ok: true });
  } catch (err) { console.error(err); return res.status(500).json({ error: "Server error" }); }
});

let globalSettings = { globalMult: 1, xpRate: 1, broadcastMsg: "" };
app.get("/api/settings", (req, res) => res.json(globalSettings));
app.post("/api/admin/settings", requireAdmin, (req, res) => {
  const { globalMult, xpRate, broadcastMsg } = req.body || {};
  if (globalMult   !== undefined) globalSettings.globalMult  = parseFloat(globalMult) || 1;
  if (xpRate       !== undefined) globalSettings.xpRate      = parseFloat(xpRate)    || 1;
  if (broadcastMsg !== undefined) globalSettings.broadcastMsg = broadcastMsg;
  return res.json({ ok: true, settings: globalSettings });
});

// ═══════════════════════════════════════
//  MULTIPLAYER ROOMS
// ═══════════════════════════════════════
const RED_NUMS_MP = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
function numColorMP(n) { return n === 0 ? "green" : RED_NUMS_MP.has(n) ? "red" : "black"; }

function safeRoomId() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < 6; i++) out += alphabet[crypto.randomInt(0, alphabet.length)];
  return out;
}

function getRoomRank(u) {
  if (u.isOwner || u.isOwner2) return "owner";
  if (u.isAdmin) return "admin";
  if (u.isMod)   return "mod";
  return "user";
}

function computePayout(number, betsObj) {
  const col = numColorMP(number);
  const outsideWins = {
    red: col==="red", black: col==="black",
    even: number!==0&&number%2===0, odd: number!==0&&number%2!==0,
    low: number>=1&&number<=18, high: number>=19&&number<=36,
    dozen1: number>=1&&number<=12, dozen2: number>=13&&number<=24, dozen3: number>=25&&number<=36,
    col1: number!==0&&number%3===1, col2: number!==0&&number%3===2, col3: number!==0&&number%3===0,
  };
  const pay = { red:1,black:1,even:1,odd:1,low:1,high:1,dozen1:2,dozen2:2,dozen3:2,col1:2,col2:2,col3:2 };
  let payout = 0;
  const nums = betsObj?.numbers || {};
  const outs = betsObj?.outside || {};
  if (nums[number] !== undefined) payout += Number(nums[number]) * 36;
  for (const [t, amtRaw] of Object.entries(outs)) {
    const amt = Number(amtRaw) || 0;
    if (amt > 0 && outsideWins[t]) payout += amt * (pay[t] + 1);
  }
  return payout;
}

async function buildRoomPayload(roomId) {
  const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1`, [roomId]);
  if (!roomQ.rowCount) return null;
  const room = roomQ.rows[0];
  const playersQ = await pool.query(`SELECT user_id, username, ready, bet_total FROM room_players WHERE room_id=$1 ORDER BY joined_at ASC`, [roomId]);
  const chatQ    = await pool.query(`SELECT ts, user_id, username, rank, text, system FROM room_chat WHERE room_id=$1 ORDER BY ts ASC LIMIT 120`, [roomId]);
  const lastQ    = await pool.query(`SELECT result_json FROM room_roulette_last WHERE room_id=$1`, [roomId]);
  const bjQ      = await pool.query(`SELECT state_json FROM room_blackjack_state WHERE room_id=$1`, [roomId]);
  const players  = playersQ.rows.map(p => ({ id: p.user_id, username: p.username, ready: p.ready, bet: Number(p.bet_total) || 0 }));
  return {
    id: room.id, game: room.game, host: players[0]?.username || "", hostId: room.host_user_id,
    phase: room.phase, maxPlayers: room.max_players, players,
    chat: chatQ.rows.map(m => ({ ts: Number(m.ts), id: m.user_id, username: m.username, rank: m.rank, text: m.text, system: m.system })),
    rouletteResult: lastQ.rowCount ? lastQ.rows[0].result_json : null,
    bjState: bjQ.rowCount ? bjQ.rows[0].state_json : null,
  };
}

app.get("/api/rooms/roulette", requireAuth, async (req, res) => {
  try {
    const q = await pool.query(`
      SELECT r.id, r.max_players,
        (SELECT COUNT(*)::int FROM room_players rp WHERE rp.room_id=r.id) AS players,
        (SELECT rp2.username FROM room_players rp2 WHERE rp2.room_id=r.id ORDER BY rp2.joined_at ASC LIMIT 1) AS host
      FROM rooms r WHERE r.game='roulette' AND r.phase IN ('waiting','betting') ORDER BY r.created_at DESC LIMIT 20`);
    res.json({ rooms: q.rows.map(r => ({ id: r.id, maxPlayers: r.max_players, players: r.players, host: r.host || "" })) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/rooms/blackjack", requireAuth, async (req, res) => {
  try {
    const q = await pool.query(`
      SELECT r.id, r.max_players,
        (SELECT COUNT(*)::int FROM room_players rp WHERE rp.room_id=r.id) AS players,
        (SELECT rp2.username FROM room_players rp2 WHERE rp2.room_id=r.id ORDER BY rp2.joined_at ASC LIMIT 1) AS host
      FROM rooms r WHERE r.game='blackjack' AND r.phase IN ('waiting','betting') ORDER BY r.created_at DESC LIMIT 20`);
    res.json({ rooms: q.rows.map(r => ({ id: r.id, maxPlayers: r.max_players, players: r.players, host: r.host || "" })) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/rooms/:game", requireAuth, async (req, res) => {
  try {
    const { game } = req.params;
    const q = await pool.query(`
      SELECT r.id, r.max_players,
        (SELECT COUNT(*)::int FROM room_players rp WHERE rp.room_id=r.id) AS players,
        (SELECT rp2.username FROM room_players rp2 WHERE rp2.room_id=r.id ORDER BY rp2.joined_at ASC LIMIT 1) AS host
      FROM rooms r WHERE r.game=$1 AND r.phase IN ('waiting','betting') ORDER BY r.created_at DESC LIMIT 20`, [game]);
    res.json({ rooms: q.rows.map(r => ({ id: r.id, maxPlayers: r.max_players, players: r.players, host: r.host || "" })) });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/create", requireAuth, async (req, res) => {
  const game = (req.body?.game || "").toLowerCase();
  if (!["roulette", "blackjack"].includes(game)) return res.status(400).json({ error: "Invalid game" });
  const user = req.user, id = safeRoomId(), ts = Date.now();
  try {
    await pool.query("BEGIN");
    await pool.query(`INSERT INTO rooms (id, game, host_user_id, phase, max_players, created_at) VALUES ($1,$2,$3,'waiting',$4,$5)`, [id, game, user.id, game === "roulette" ? 8 : 6, ts]);
    await pool.query(`INSERT INTO room_players (room_id, user_id, username, ready, bet_total, bet_json, joined_at) VALUES ($1,$2,$3,false,0,NULL,$4)`, [id, user.id, user.username, ts]);
    await pool.query(`INSERT INTO room_chat (room_id, ts, user_id, username, rank, text, system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [id, ts + 1, `🎰 Room created by ${user.username}`]);
    await pool.query("COMMIT");
    audit(req, 'ROOM_CREATE', `${game} room ${id}`);
    res.json({ room: await buildRoomPayload(id) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/join", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user, ts = Date.now();
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    const room = roomQ.rows[0];
    const countQ = await pool.query(`SELECT COUNT(*)::int AS c FROM room_players WHERE room_id=$1`, [roomId]);
    if (countQ.rows[0].c >= room.max_players) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Room full" }); }
    if (!["waiting","betting"].includes(room.phase)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Game in progress" }); }
    await pool.query(`INSERT INTO room_players (room_id, user_id, username, ready, bet_total, bet_json, joined_at) VALUES ($1,$2,$3,false,0,NULL,$4) ON CONFLICT (room_id, user_id) DO UPDATE SET username=EXCLUDED.username`, [roomId, user.id, user.username, ts]);
    await pool.query(`INSERT INTO room_chat (room_id, ts, user_id, username, rank, text, system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [roomId, ts, `✅ ${user.username} joined`]);
    await pool.query("COMMIT");
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/leave", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user, ts = Date.now();
  try {
    await pool.query("BEGIN");
    const rpQ = await pool.query(`SELECT bet_total FROM room_players WHERE room_id=$1 AND user_id=$2`, [roomId, user.id]);
    if (rpQ.rowCount && Number(rpQ.rows[0].bet_total) > 0) {
      await pool.query(`UPDATE game_state SET score = score + $1 WHERE user_id=$2`, [Number(rpQ.rows[0].bet_total), user.id]);
    }
    await pool.query(`DELETE FROM room_players WHERE room_id=$1 AND user_id=$2`, [roomId, user.id]);
    await pool.query(`INSERT INTO room_chat (room_id, ts, user_id, username, rank, text, system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [roomId, ts, `👋 ${user.username} left`]);
    const countQ = await pool.query(`SELECT COUNT(*)::int AS c FROM room_players WHERE room_id=$1`, [roomId]);
    if (countQ.rows[0].c === 0) await pool.query(`DELETE FROM rooms WHERE id=$1`, [roomId]);
    await pool.query("COMMIT");
    res.json({ ok: true });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.get("/api/room/:id/poll", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase();
  try {
    const payload = await buildRoomPayload(roomId);
    if (!payload) return res.status(404).json({ error: "Room not found" });
    res.json({ room: payload });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/chat", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user;
  const text = String(req.body?.text || "").trim().slice(0, 120);
  if (!text) return res.status(400).json({ error: "Empty message" });
  try {
    const inQ = await pool.query(`SELECT 1 FROM room_players WHERE room_id=$1 AND user_id=$2`, [roomId, user.id]);
    if (!inQ.rowCount) return res.status(403).json({ error: "Not in room" });
    await pool.query(`INSERT INTO room_chat (room_id, ts, user_id, username, rank, text, system) VALUES ($1,$2,$3,$4,$5,$6,false)`, [roomId, Date.now(), user.id, user.username, getRoomRank(user), text]);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/roulette/bet", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user;
  const totalBet = Number(req.body?.totalBet) || 0, bets = req.body?.bets || null;
  if (!bets || totalBet <= 0) return res.status(400).json({ error: "Invalid bet" });
  if (totalBet > 1_000_000_000_000) return res.status(400).json({ error: "Max bet 1T" });
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1 AND game='roulette'`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    if (!["waiting","betting"].includes(roomQ.rows[0].phase)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Bets closed" }); }
    const rpQ = await pool.query(`SELECT bet_total FROM room_players WHERE room_id=$1 AND user_id=$2 FOR UPDATE`, [roomId, user.id]);
    if (!rpQ.rowCount) { await pool.query("ROLLBACK"); return res.status(403).json({ error: "Not in room" }); }
    const old = Number(rpQ.rows[0].bet_total) || 0;
    if (old > 0) await pool.query(`UPDATE game_state SET score = score + $1 WHERE user_id=$2`, [old, user.id]);
    const gsQ = await pool.query(`SELECT score FROM game_state WHERE user_id=$1 FOR UPDATE`, [user.id]);
    const score = Number(gsQ.rows[0]?.score) || 0;
    if (totalBet > score) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Insufficient score" }); }
    await pool.query(`UPDATE game_state SET score = score - $1, updated_at=NOW() WHERE user_id=$2`, [totalBet, user.id]);
    await pool.query(`UPDATE room_players SET ready=true, bet_total=$3, bet_json=$4 WHERE room_id=$1 AND user_id=$2`, [roomId, user.id, totalBet, bets]);
    await pool.query(`UPDATE rooms SET phase='betting' WHERE id=$1`, [roomId]);
    await pool.query("COMMIT");
    audit(req, 'ROOM_BET', `room:${roomId} bet:${totalBet}`);
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/roulette/spin", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user, ts = Date.now();
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1 AND game='roulette' FOR UPDATE`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    const room = roomQ.rows[0];
    if (room.host_user_id !== user.id) { await pool.query("ROLLBACK"); return res.status(403).json({ error: "Host only" }); }
    if (room.phase === "playing") { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Already spinning" }); }
    const playersQ = await pool.query(`SELECT user_id, username, bet_total, bet_json FROM room_players WHERE room_id=$1 ORDER BY joined_at ASC`, [roomId]);
    if (!playersQ.rows.some(p => Number(p.bet_total) > 0)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "No bets placed" }); }
    await pool.query(`UPDATE rooms SET phase='playing' WHERE id=$1`, [roomId]);
    const number = crypto.randomInt(0, 37), color = numColorMP(number);
    const playerResults = [];
    for (const p of playersQ.rows) {
      const betTotal = Number(p.bet_total) || 0, betsObj = p.bet_json || null;
      let payout = 0;
      if (betTotal > 0 && betsObj) payout = computePayout(number, betsObj);
      if (payout > 0) await pool.query(`UPDATE game_state SET score = score + $1, updated_at=NOW() WHERE user_id=$2`, [payout, p.user_id]);
      const delta = payout - betTotal;
      playerResults.push({ id: p.user_id, username: p.username, delta });
      audit(req, 'ROOM_SPIN_RESULT', `room:${roomId} user:${p.user_id} result:${number} payout:${payout} delta:${delta}`);
    }
    const resultObj = { ts, number, color, playerResults };
    await pool.query(`INSERT INTO room_roulette_last (room_id, ts, number, color, result_json) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (room_id) DO UPDATE SET ts=EXCLUDED.ts, number=EXCLUDED.number, color=EXCLUDED.color, result_json=EXCLUDED.result_json`, [roomId, ts, number, color, resultObj]);
    await pool.query(`UPDATE room_players SET ready=false, bet_total=0, bet_json=NULL WHERE room_id=$1`, [roomId]);
    await pool.query(`UPDATE rooms SET phase='results' WHERE id=$1`, [roomId]);
    await pool.query(`INSERT INTO room_chat (room_id, ts, user_id, username, rank, text, system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [roomId, ts + 1, `🎡 Result: ${number} (${color.toUpperCase()}) — ${playerResults.filter(r=>r.delta>0).length} winner(s)`]);
    setTimeout(async () => { try { await pool.query(`UPDATE rooms SET phase='waiting' WHERE id=$1 AND phase='results'`, [roomId]); } catch {} }, 8000);
    await pool.query("COMMIT");
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

// ═══════════════════════════════════════
//  BLACKJACK
// ═══════════════════════════════════════
function bjNewDeck(numDecks = 6) {
  const suits = ["♠","♥","♦","♣"], vals = ["A","2","3","4","5","6","7","8","9","10","J","Q","K"], deck = [];
  for (let d = 0; d < numDecks; d++) for (const s of suits) for (const v of vals) deck.push({ v, s });
  for (let i = deck.length - 1; i > 0; i--) { const j = crypto.randomInt(0, i + 1); [deck[i], deck[j]] = [deck[j], deck[i]]; }
  return deck;
}
function bjCardVal(c) { if (c.v==="A") return 11; if (["K","Q","J"].includes(c.v)) return 10; return parseInt(c.v, 10); }
function bjHandTotal(hand) { let t=0, aces=0; for (const c of hand) { t+=bjCardVal(c); if(c.v==="A") aces++; } while(t>21&&aces>0){t-=10;aces--;} return t; }
function bjIsBlackjack(hand) { return hand && hand.length===2 && bjHandTotal(hand)===21; }
function bjDealerShouldHit(hand) { return bjHandTotal(hand) < 17; }
function bjNextTurn(state) {
  const idx = state.turnOrder.indexOf(state.currentTurn);
  for (let i = idx+1; i < state.turnOrder.length; i++) {
    const pid = state.turnOrder[i], hand = state.playerHands[pid];
    if (!hand) continue;
    if (bjHandTotal(hand) > 21) continue;
    if (bjIsBlackjack(hand)) continue;
    return pid;
  }
  return null;
}
async function bjLoadState(roomId) {
  const q = await pool.query(`SELECT state_json FROM room_blackjack_state WHERE room_id=$1`, [roomId]);
  return q.rowCount ? q.rows[0].state_json : null;
}
async function bjSaveState(roomId, state) {
  await pool.query(`INSERT INTO room_blackjack_state (room_id, updated_at, state_json) VALUES ($1,$2,$3) ON CONFLICT (room_id) DO UPDATE SET updated_at=EXCLUDED.updated_at, state_json=EXCLUDED.state_json`, [roomId, Date.now(), state]);
}

app.post("/api/room/:id/blackjack/bet", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user, bet = Number(req.body?.bet) || 0;
  if (bet <= 0 || bet > 1_000_000_000_000) return res.status(400).json({ error: "Invalid bet" });
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1 AND game='blackjack' FOR UPDATE`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    if (!["waiting","betting"].includes(roomQ.rows[0].phase)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Bets closed" }); }
    const dealerQ = await pool.query(`SELECT user_id FROM room_players WHERE room_id=$1 ORDER BY joined_at ASC LIMIT 1`, [roomId]);
    if (user.id === dealerQ.rows[0]?.user_id) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Dealer does not bet" }); }
    const rpQ = await pool.query(`SELECT bet_total FROM room_players WHERE room_id=$1 AND user_id=$2 FOR UPDATE`, [roomId, user.id]);
    if (!rpQ.rowCount) { await pool.query("ROLLBACK"); return res.status(403).json({ error: "Not in room" }); }
    const old = Number(rpQ.rows[0].bet_total) || 0;
    if (old > 0) await pool.query(`UPDATE game_state SET score = score + $1 WHERE user_id=$2`, [old, user.id]);
    const gsQ = await pool.query(`SELECT score FROM game_state WHERE user_id=$1 FOR UPDATE`, [user.id]);
    if (bet > (Number(gsQ.rows[0]?.score) || 0)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Insufficient score" }); }
    await pool.query(`UPDATE game_state SET score = score - $1, updated_at=NOW() WHERE user_id=$2`, [bet, user.id]);
    await pool.query(`UPDATE room_players SET ready=true, bet_total=$3, bet_json=$4 WHERE room_id=$1 AND user_id=$2`, [roomId, user.id, bet, { bet }]);
    await pool.query(`UPDATE rooms SET phase='betting' WHERE id=$1 AND phase='waiting'`, [roomId]);
    await pool.query("COMMIT");
    audit(req, 'BJ_BET', `room:${roomId} bet:${bet}`);
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/blackjack/deal", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user;
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1 AND game='blackjack' FOR UPDATE`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    const playersQ = await pool.query(`SELECT user_id, username, bet_total FROM room_players WHERE room_id=$1 ORDER BY joined_at ASC`, [roomId]);
    if (!playersQ.rowCount) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "No players" }); }
    const dealerId = playersQ.rows[0].user_id;
    if (user.id !== dealerId) { await pool.query("ROLLBACK"); return res.status(403).json({ error: "Dealer only" }); }
    const nonDealers = playersQ.rows.slice(1);
    if (!nonDealers.length) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Need at least 1 player" }); }
    if (!nonDealers.every(p => Number(p.bet_total) > 0)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "All players must bet first" }); }
    const deck = bjNewDeck(6), dealerHand = [deck.pop(), deck.pop()];
    const playerHands = {}, bets = {}, doubled = {};
    for (const p of nonDealers) { playerHands[p.user_id]=[deck.pop(),deck.pop()]; bets[p.user_id]=Number(p.bet_total)||0; doubled[p.user_id]=false; }
    const turnOrder = nonDealers.map(p => p.user_id);
    const firstTurn = (() => { for (const pid of turnOrder) { if (!bjIsBlackjack(playerHands[pid])) return pid; } return null; })();
    const state = { phase:"player_turns", deck, dealerHand, playerHands, bets, doubled, turnOrder, currentTurn:firstTurn, results:null, startedAt:Date.now() };
    if (!firstTurn) {
      state.phase = "dealer_turn";
      while (bjDealerShouldHit(state.dealerHand)) state.dealerHand.push(state.deck.pop());
      state.phase = "finished"; state.results = await bjSettle(state, roomId, dealerId);
      await pool.query(`UPDATE rooms SET phase='results' WHERE id=$1`, [roomId]);
      await pool.query(`UPDATE room_players SET ready=false, bet_total=0, bet_json=NULL WHERE room_id=$1 AND user_id<>$2`, [roomId, dealerId]);
      setTimeout(async () => { try { await pool.query(`DELETE FROM room_blackjack_state WHERE room_id=$1`, [roomId]); await pool.query(`UPDATE rooms SET phase='waiting' WHERE id=$1 AND phase='results'`, [roomId]); } catch {} }, 8000);
    } else {
      await pool.query(`UPDATE rooms SET phase='playing' WHERE id=$1`, [roomId]);
    }
    await bjSaveState(roomId, state);
    await pool.query(`INSERT INTO room_chat (room_id,ts,user_id,username,rank,text,system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [roomId, Date.now(), "🃏 Cards dealt! Players take turns."]);
    await pool.query("COMMIT");
    audit(req, 'BJ_DEAL', `room:${roomId}`);
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

app.post("/api/room/:id/blackjack/action", requireAuth, async (req, res) => {
  const roomId = String(req.params.id || "").toUpperCase(), user = req.user;
  const action = String(req.body?.action || "").toLowerCase();
  if (!["hit","stand","double"].includes(action)) return res.status(400).json({ error: "Invalid action" });
  try {
    await pool.query("BEGIN");
    const roomQ = await pool.query(`SELECT * FROM rooms WHERE id=$1 AND game='blackjack' FOR UPDATE`, [roomId]);
    if (!roomQ.rowCount) { await pool.query("ROLLBACK"); return res.status(404).json({ error: "Room not found" }); }
    if (roomQ.rows[0].phase !== "playing") { await pool.query("ROLLBACK"); return res.status(400).json({ error: "No active round" }); }
    const dealerQ = await pool.query(`SELECT user_id FROM room_players WHERE room_id=$1 ORDER BY joined_at ASC LIMIT 1`, [roomId]);
    const dealerId = dealerQ.rows[0]?.user_id;
    if (user.id === dealerId) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Dealer acts automatically" }); }
    const state = await bjLoadState(roomId);
    if (!state) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "No BJ state" }); }
    if (state.phase !== "player_turns") { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Not player turns" }); }
    if (state.currentTurn !== user.id) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Not your turn" }); }
    const hand = state.playerHands[user.id];
    if (!hand) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "No hand found" }); }
    const bet = Number(state.bets[user.id]) || 0;
    if (action === "double") {
      if (hand.length !== 2) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Can only double on 2 cards" }); }
      const gsQ = await pool.query(`SELECT score FROM game_state WHERE user_id=$1 FOR UPDATE`, [user.id]);
      if (bet > (Number(gsQ.rows[0]?.score) || 0)) { await pool.query("ROLLBACK"); return res.status(400).json({ error: "Insufficient score to double" }); }
      await pool.query(`UPDATE game_state SET score = score - $1, updated_at=NOW() WHERE user_id=$2`, [bet, user.id]);
      state.bets[user.id] = bet * 2; state.doubled[user.id] = true;
      hand.push(state.deck.pop()); state.currentTurn = bjNextTurn(state);
    } else if (action === "hit") {
      hand.push(state.deck.pop());
      if (bjHandTotal(hand) >= 21) state.currentTurn = bjNextTurn(state);
    } else if (action === "stand") {
      state.currentTurn = bjNextTurn(state);
    }
    if (!state.currentTurn) {
      state.phase = "dealer_turn";
      while (bjDealerShouldHit(state.dealerHand)) state.dealerHand.push(state.deck.pop());
      state.phase = "finished"; state.results = await bjSettle(state, roomId, dealerId);
      await pool.query(`UPDATE rooms SET phase='results' WHERE id=$1`, [roomId]);
      await pool.query(`UPDATE room_players SET ready=false, bet_total=0, bet_json=NULL WHERE room_id=$1 AND user_id<>$2`, [roomId, dealerId]);
      const dTotal = bjHandTotal(state.dealerHand), dBust = dTotal > 21;
      const wins = Object.values(state.results).filter(r => ["win","blackjack"].includes(r.outcome)).length;
      await pool.query(`INSERT INTO room_chat (room_id,ts,user_id,username,rank,text,system) VALUES ($1,$2,NULL,NULL,NULL,$3,true)`, [roomId, Date.now(), `Dealer: ${dTotal}${dBust?" (BUST)":""} — ${wins} player(s) won`]);
      setTimeout(async () => { try { await pool.query(`DELETE FROM room_blackjack_state WHERE room_id=$1`, [roomId]); await pool.query(`UPDATE rooms SET phase='waiting' WHERE id=$1 AND phase='results'`, [roomId]); } catch {} }, 8000);
    }
    await bjSaveState(roomId, state);
    await pool.query("COMMIT");
    audit(req, `BJ_${action.toUpperCase()}`, `room:${roomId} user:${user.id}`);
    res.json({ room: await buildRoomPayload(roomId) });
  } catch (e) { await pool.query("ROLLBACK"); console.error(e); res.status(500).json({ error: "Server error" }); }
});

async function bjSettle(state, roomId, dealerId) {
  const dealerTotal = bjHandTotal(state.dealerHand), dealerBust = dealerTotal > 21, dealerBJ = bjIsBlackjack(state.dealerHand);
  const results = {};
  for (const pid of state.turnOrder) {
    const ph = state.playerHands[pid], total = bjHandTotal(ph), bust = total > 21, bj = bjIsBlackjack(ph), stake = Number(state.bets[pid]) || 0;
    let outcome = "lose", payout = 0;
    if (bust)                     { outcome="lose";      payout=0; }
    else if (bj && !dealerBJ)     { outcome="blackjack"; payout=Math.floor(stake*2.5); }
    else if (bj && dealerBJ)      { outcome="push";      payout=stake; }
    else if (dealerBJ)            { outcome="lose";      payout=0; }
    else if (dealerBust)          { outcome="win";       payout=stake*2; }
    else if (total > dealerTotal) { outcome="win";       payout=stake*2; }
    else if (total === dealerTotal){ outcome="push";     payout=stake; }
    else                          { outcome="lose";      payout=0; }
    if (payout > 0) await pool.query(`UPDATE game_state SET score=score+$1, updated_at=NOW() WHERE user_id=$2`, [payout, pid]);
    const delta = payout - stake;
    results[pid] = { outcome, delta, pTotal: total, dTotal: dealerTotal };
    audit({ headers:{authorization:'room'}, socket:{remoteAddress:'room'}, user:{id:pid,username:pid} }, `BJ_SETTLE`, `room:${roomId} pid:${pid} outcome:${outcome} payout:${payout} delta:${delta}`);
  }
  return results;
}

// ═══════════════════════════════════════
//  HEALTH / ROOT
// ═══════════════════════════════════════
app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));
app.get("/",       (req, res) => res.json({ name: "Capital RNG API", version: "2.1.0" }));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 Capital RNG API running on port ${PORT}`)))
  .catch((err) => { console.error("❌ DB init failed:", err); process.exit(1); });
