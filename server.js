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

const JWT_SECRET           = process.env.JWT_SECRET           || "change-me-in-production-please";
const OWNER_PANEL_PASSPHRASE = process.env.OWNER_PANEL_PASSPHRASE || "";

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

  // Root admin
  const adminId = "uid_admin_root";
  const existing = await pool.query("SELECT id FROM users WHERE id = $1", [adminId]);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash("admin123", 10);
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
    console.log("✅ Root admin account created (admin / admin123)");
  }

  // Migrations
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
app.use(cors({ origin: process.env.FRONTEND_ORIGIN || "*", credentials: true }));
app.use(express.json());

// Pure API — no static files served here.
// All frontend files live in the frontend repo.

// ═══════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════
// ─── Rate limiting for admin/auth probing ───
const _adminFailures = new Map(); // ip → { count, ts }
const ADMIN_MAX_FAILS  = 10;
const ADMIN_LOCKOUT_MS = 15 * 60 * 1000; // 15 min

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

// ─── Audit log (last 500 entries in memory, logged to console) ───
const _auditLog = [];
function audit(req, action, detail = '') {
  const ip      = getClientIP(req);
  const user    = req.user ? `${req.user.username}(${req.user.id})` : 'anon';
  const entry   = `[${new Date().toISOString()}] ${action} | ${user} | IP:${ip} ${detail}`;
  _auditLog.unshift(entry);
  if (_auditLog.length > 500) _auditLog.pop();
  console.log('📋 AUDIT:', entry);
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Admins AND owners can use admin routes
function requireAdmin(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) {
    return res.status(429).json({ error: "Too many failed attempts. Try again later." });
  }
  requireAuth(req, res, () => {
    if (!req.user.isAdmin && !req.user.isOwner && !req.user.isOwner2) {
      trackAdminFail(ip);
      audit(req, 'ADMIN_DENIED', req.path);
      return res.status(403).json({ error: "Admin only" });
    }
    next();
  });
}

// Owners only
function requireOwner(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) {
    return res.status(429).json({ error: "Too many failed attempts. Try again later." });
  }
  requireAuth(req, res, () => {
    if (!req.user.isOwner && !req.user.isOwner2) {
      trackAdminFail(ip);
      audit(req, 'OWNER_DENIED', req.path);
      return res.status(403).json({ error: "Owner only" });
    }
    next();
  });
}

// Owner-only audit log endpoint
app.get("/api/owner/audit", requireOwner, (req, res) => {
  audit(req, 'AUDIT_VIEW');
  res.json({ log: _auditLog });
});

// ═══════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════
function makeToken(userRow) {
  return jwt.sign(
    {
      id:       userRow.id,
      username: userRow.username,
      isAdmin:  userRow.is_admin,
      isOwner:  userRow.is_owner  || false,
      isOwner2: userRow.is_owner2 || false,
      isOG:     userRow.is_og     || false,
      isMod:    userRow.is_mod    || false,
      isVIP:    userRow.is_vip    || false,
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function rowToState(row) {
  if (!row) return null;
  return {
    score:          parseFloat(row.score) || 0,
    luckLevel:      row.luck_level || 1,
    luckXP:         parseFloat(row.luck_xp) || 0,
    multLevel:      row.mult_level || 0,
    cdLevel:        row.cd_level || 0,
    autoLevel:      row.auto_level || 0,
    vaultLevel:     row.vault_level || 0,
    xpLevel:        row.xp_level || 0,
    critLevel:      row.crit_level || 0,
    echoLevel:      row.echo_level || 0,
    soulLevel:      row.soul_level || 0,
    voidupgLevel:   row.voidupg_level || 0,
    ascLevel:       row.asc_level || 0,
    timeLevel:      row.time_level || 0,
    forgeLevel:     row.forge_level || 0,
    prestigeLevel:  row.prestige_level || 0,
    totalRolls:     row.total_rolls || 0,
    legendaryCount: row.legendary_count || 0,
    mythicCount:    row.mythic_count || 0,
    divineCount:    row.divine_count || 0,
    celestialCount: row.celestial_count || 0,
    etherealCount:  row.ethereal_count || 0,
    voidCount:      row.void_count || 0,
    primordialCount:row.primordial_count || 0,
    omegaCount:     row.omega_count || 0,
    critCount:      row.crit_count || 0,
    echoCount:      row.echo_count || 0,
    achievements:   row.achievements || [],
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
      `UPDATE users SET
        last_ip = $2,
        ip_history = (
          SELECT ARRAY(
            SELECT DISTINCT unnest(array_append(COALESCE(ip_history,'{}'), $2::TEXT))
            LIMIT 20
          )
        )
       WHERE id = $1`,
      [userId, ip]
    );
  } catch (e) { console.warn("IP record failed:", e.message); }
}

// ═══════════════════════════════════════
//  OWNER PASSPHRASE VERIFY
//  No auth required — checked before login
// ═══════════════════════════════════════
const _ppFailures = new Map();
const PP_MAX_ATTEMPTS = 5;
const PP_LOCKOUT_MS   = 15 * 60 * 1000;

app.post("/api/owner/verify-passphrase", (req, res) => {
  const ip = getClientIP(req);
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

// ═══════════════════════════════════════
//  OWNER SESSION TOKEN (48h per-account)
// ═══════════════════════════════════════

// Generate/refresh 48h token — called right after successful login
app.post("/api/owner/generate-token", requireOwner, async (req, res) => {
  try {
    const token = crypto.randomBytes(32).toString("hex");
    const exp   = new Date(Date.now() + 48 * 60 * 60 * 1000);
    await pool.query(
      `UPDATE users SET owner_token=$1, owner_token_exp=$2 WHERE id=$3`,
      [token, exp, req.user.id]
    );
    return res.json({ token, expires: exp.toISOString() });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Exchange stored owner token → fresh JWT (auto-login, no password needed)
app.post("/api/owner/token-login", async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: "Missing token" });

    const result = await pool.query(
      `SELECT * FROM users WHERE owner_token=$1`, [token]
    );
    if (!result.rows.length) return res.status(401).json({ error: "Invalid token" });

    const user = result.rows[0];
    if (!user.is_owner && !user.is_owner2) return res.status(403).json({ error: "Not an owner account" });
    if (new Date(user.owner_token_exp) < new Date()) return res.status(401).json({ error: "Token expired" });

    return res.json({
      token:   makeToken(user),
      user: {
        id:       user.id,
        username: user.username,
        isAdmin:  user.is_admin,
        isOwner:  user.is_owner  || false,
        isOwner2: user.is_owner2 || false,
      },
      expires: user.owner_token_exp,
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ═══════════════════════════════════════
//  AUTH ROUTES
// ═══════════════════════════════════════
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || username.length < 2) return res.status(400).json({ error: "Username must be 2+ chars" });
    if (!password || password.length < 6)  return res.status(400).json({ error: "Password must be 6+ chars" });
    if (username.toLowerCase() === "admin") return res.status(400).json({ error: "Username reserved" });

    const exists = await pool.query("SELECT id FROM users WHERE LOWER(username) = LOWER($1)", [username]);
    if (exists.rows.length) return res.status(409).json({ error: "Username already taken" });

    const id   = "u_" + Date.now() + "_" + Math.random().toString(36).slice(2);
    const hash = await bcrypt.hash(password, 10);

    await pool.query("INSERT INTO users (id, username, password) VALUES ($1, $2, $3)", [id, username, hash]);
    await pool.query("INSERT INTO game_state (user_id) VALUES ($1)", [id]);
    await recordIP(id, getClientIP(req));

    const u = { id, username, is_admin: false, is_owner: false, is_owner2: false, is_og: false, is_mod: false, is_vip: false };
    return res.json({
      token: makeToken(u),
      user:  { id, username, isAdmin: false, isOwner: false, isOwner2: false, isOG: false, isMod: false, isVIP: false },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
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
      user: {
        id:       user.id,
        username: user.username,
        isAdmin:  user.is_admin,
        isOwner:  user.is_owner  || false,
        isOwner2: user.is_owner2 || false,
        isOG:     user.is_og     || false,
        isMod:    user.is_mod    || false,
        isVIP:    user.is_vip    || false,
      },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Verify current token and return fresh user data from DB
app.get("/api/auth/me", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const user = result.rows[0];
    return res.json({
      user: {
        id:       user.id,
        username: user.username,
        isAdmin:  user.is_admin,
        isOwner:  user.is_owner  || false,
        isOwner2: user.is_owner2 || false,
        isOG:     user.is_og     || false,
        isMod:    user.is_mod    || false,
        isVIP:    user.is_vip    || false,
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});
app.get("/api/game/load", requireAuth, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.user.id]);
    return res.json({ state: rowToState(result.rows[0]) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/game/save", requireAuth, async (req, res) => {
  try {
    const s = req.body || {};

    // ── Server-side validation: clamp all values to legitimate ranges ──
    // A normal player cannot exceed these without cheating
    const clamp  = (v, min, max) => Math.min(max, Math.max(min, parseFloat(v) || 0));
    const clampI = (v, min, max) => Math.min(max, Math.max(min, parseInt(v)   || 0));

    // First load their current state so we can validate progression
    const cur = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.user.id]);
    const curState = cur.rows[0] || {};

    // Scores can grow very large legitimately, but cap at a sane ceiling
    // and never allow a single save to jump by more than a reasonable amount
    const MAX_SCORE = 1e18; // 1 quintillion — effectively unlimited for real play
    const curScore  = parseFloat(curState.score) || 0;
    const newScore  = clamp(s.score, 0, MAX_SCORE);

    // Luck level: 1–100, can only go up (never allow reducing except via admin)
    const curLuck  = parseInt(curState.luck_level) || 1;
    const newLuck  = clampI(s.luckLevel, curLuck, 100); // can't decrease own luck

    // Prestige: 0–999, can only increase
    const curPrestige = parseInt(curState.prestige_level) || 0;
    const newPrestige = clampI(s.prestigeLevel, curPrestige, 999);

    // Upgrade levels: 0–200 each, can only increase
    const upg = (key, curKey, max = 200) => clampI(s[key], parseInt(curState[curKey]) || 0, max);

    // Roll counts: can only increase
    const rolls = (key, curKey) => Math.max(parseInt(curState[curKey]) || 0, clampI(s[key], 0, 1e9));

    await pool.query(
      `INSERT INTO game_state (
        user_id, score, luck_level, luck_xp, mult_level, cd_level, auto_level,
        vault_level, xp_level, crit_level, echo_level, soul_level, voidupg_level,
        asc_level, time_level, forge_level, prestige_level, total_rolls,
        legendary_count, mythic_count, divine_count, celestial_count, ethereal_count,
        void_count, primordial_count, omega_count, crit_count, echo_count,
        achievements, updated_at
      ) VALUES (
        $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
        $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,NOW()
      )
      ON CONFLICT (user_id) DO UPDATE SET
        score=$2, luck_level=$3, luck_xp=$4, mult_level=$5, cd_level=$6,
        auto_level=$7, vault_level=$8, xp_level=$9, crit_level=$10, echo_level=$11,
        soul_level=$12, voidupg_level=$13, asc_level=$14, time_level=$15,
        forge_level=$16, prestige_level=$17, total_rolls=$18, legendary_count=$19,
        mythic_count=$20, divine_count=$21, celestial_count=$22, ethereal_count=$23,
        void_count=$24, primordial_count=$25, omega_count=$26, crit_count=$27,
        echo_count=$28, achievements=$29, updated_at=NOW()`,
      [
        req.user.id,
        newScore,
        newLuck,
        clamp(s.luckXP,          0, 1e9),
        upg('multLevel',      'mult_level'),
        upg('cdLevel',        'cd_level'),
        upg('autoLevel',      'auto_level'),
        upg('vaultLevel',     'vault_level'),
        upg('xpLevel',        'xp_level'),
        upg('critLevel',      'crit_level'),
        upg('echoLevel',      'echo_level'),
        upg('soulLevel',      'soul_level'),
        upg('voidupgLevel',   'voidupg_level'),
        upg('ascLevel',       'asc_level'),
        upg('timeLevel',      'time_level'),
        upg('forgeLevel',     'forge_level'),
        newPrestige,
        rolls('totalRolls',       'total_rolls'),
        rolls('legendaryCount',   'legendary_count'),
        rolls('mythicCount',      'mythic_count'),
        rolls('divineCount',      'divine_count'),
        rolls('celestialCount',   'celestial_count'),
        rolls('etherealCount',    'ethereal_count'),
        rolls('voidCount',        'void_count'),
        rolls('primordialCount',  'primordial_count'),
        rolls('omegaCount',       'omega_count'),
        rolls('critCount',        'crit_count'),
        rolls('echoCount',        'echo_count'),
        Array.isArray(s.achievements) ? s.achievements : [],
      ]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ═══════════════════════════════════════
//  LEADERBOARD
// ═══════════════════════════════════════
app.get("/api/leaderboard", async (req, res) => {
  try {
    const limit   = Math.min(parseInt(req.query.limit) || 50, 100);
    const sortBy  = req.query.sort || "score";
    const colMap  = { score: "gs.score", prestige: "gs.prestige_level", rolls: "gs.total_rolls", luck: "gs.luck_level" };
    const orderCol = colMap[sortBy] || "gs.score";

    const result = await pool.query(
      `SELECT
        u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
        gs.score, gs.luck_level, gs.prestige_level,
        gs.total_rolls, gs.omega_count, gs.void_count,
        gs.legendary_count, gs.mythic_count, gs.divine_count,
        gs.achievements, gs.updated_at
       FROM users u
       JOIN game_state gs ON gs.user_id = u.id
       ORDER BY ${orderCol} DESC
       LIMIT $1`,
      [limit]
    );

    return res.json({
      leaderboard: result.rows.map((r, i) => ({
        rank:          i + 1,
        id:            r.id,
        username:      r.username,
        isAdmin:       r.is_admin,
        isOwner:       r.is_owner  || false,
        isOwner2:      r.is_owner2 || false,
        isOG:          r.is_og     || false,
        isMod:         r.is_mod    || false,
        isVIP:         r.is_vip    || false,
        score:         parseFloat(r.score),
        luckLevel:     r.luck_level,
        prestigeLevel: r.prestige_level,
        totalRolls:    r.total_rolls,
        omegaCount:    r.omega_count,
        voidCount:     r.void_count,
        legendaryCount:r.legendary_count,
        mythicCount:   r.mythic_count,
        divineCount:   r.divine_count,
        achievements:  (r.achievements || []).length,
        lastSeen:      r.updated_at,
      })),
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ═══════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════
app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
             u.last_ip, u.ip_history, u.created_at,
             gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls
      FROM users u
      LEFT JOIN game_state gs ON gs.user_id = u.id
      ORDER BY gs.score DESC NULLS LAST
    `);
    return res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/admin/user/:id", requireAdmin, async (req, res) => {
  try {
    const u  = await pool.query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    const gs = await pool.query("SELECT * FROM game_state WHERE user_id = $1", [req.params.id]);
    if (!u.rows.length) return res.status(404).json({ error: "User not found" });
    return res.json({ user: u.rows[0], state: rowToState(gs.rows[0]) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
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
    if (rankUpdates.length > 0) {
      rankVals.push(id);
      await pool.query(`UPDATE users SET ${rankUpdates.join(", ")} WHERE id=$${ri}`, rankVals);
    }

    if (s.password) {
      const hash = await bcrypt.hash(s.password, 10);
      await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hash, id]);
    }

    const map = {
      score: "score", luckLevel: "luck_level", prestigeLevel: "prestige_level",
      totalRolls: "total_rolls", voidCount: "void_count", omegaCount: "omega_count",
      multLevel: "mult_level", cdLevel: "cd_level", autoLevel: "auto_level",
      vaultLevel: "vault_level", xpLevel: "xp_level", critLevel: "crit_level",
      voidupgLevel: "voidupg_level", echoLevel: "echo_level", soulLevel: "soul_level",
      ascLevel: "asc_level", timeLevel: "time_level", forgeLevel: "forge_level",
    };
    const fields = [], vals = [id];
    let idx = 2;
    for (const [jsKey, dbCol] of Object.entries(map)) {
      if (s[jsKey] !== undefined) { fields.push(`${dbCol}=$${idx++}`); vals.push(s[jsKey]); }
    }
    if (fields.length > 0) {
      fields.push("updated_at=NOW()");
      await pool.query(`INSERT INTO game_state (user_id) VALUES ($1) ON CONFLICT DO NOTHING`, [id]);
      await pool.query(`UPDATE game_state SET ${fields.join(", ")} WHERE user_id=$1`, vals);
    }

    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.delete("/api/admin/user/:id", requireAdmin, async (req, res) => {
  try {
    if (req.params.id === "uid_admin_root") return res.status(403).json({ error: "Cannot delete root admin" });
    await pool.query("DELETE FROM users WHERE id = $1", [req.params.id]);
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/admin/reset/:id", requireAdmin, async (req, res) => {
  try {
    await pool.query(
      `UPDATE game_state SET
        score=0, luck_level=1, luck_xp=0, mult_level=0, cd_level=0,
        auto_level=0, vault_level=0, xp_level=0, crit_level=0, echo_level=0,
        soul_level=0, voidupg_level=0, asc_level=0, time_level=0, forge_level=0,
        prestige_level=0, total_rolls=0, legendary_count=0, mythic_count=0,
        divine_count=0, celestial_count=0, ethereal_count=0, void_count=0,
        primordial_count=0, omega_count=0, crit_count=0, echo_count=0,
        achievements='{}', updated_at=NOW()
       WHERE user_id=$1`,
      [req.params.id]
    );
    return res.json({ ok: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Global settings (in-memory)
let globalSettings = { globalMult: 1, xpRate: 1, broadcastMsg: "" };
app.get("/api/settings", (req, res) => res.json(globalSettings));
app.post("/api/admin/settings", requireAdmin, (req, res) => {
  const { globalMult, xpRate, broadcastMsg } = req.body || {};
  if (globalMult   !== undefined) globalSettings.globalMult  = parseFloat(globalMult) || 1;
  if (xpRate       !== undefined) globalSettings.xpRate       = parseFloat(xpRate)    || 1;
  if (broadcastMsg !== undefined) globalSettings.broadcastMsg = broadcastMsg;
  return res.json({ ok: true, settings: globalSettings });
});

// Owner IP lookup
app.get("/api/owner/ips", requireOwner, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, is_admin, is_owner, is_owner2, is_og, is_mod, is_vip,
             last_ip, ip_history, created_at
      FROM users ORDER BY created_at DESC
    `);
    return res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

// ═══════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════
app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));
app.get("/",       (req, res) => res.json({ name: "Capital RNG API", version: "2.0.0" }));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 Capital RNG API running on port ${PORT}`)))
  .catch((err) => { console.error("❌ DB init failed:", err); process.exit(1); });
