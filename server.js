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
// Comma-separated usernames whose IPs are hidden in the owner panel
// e.g. HIDDEN_IP_USERS=alice,bob,charlie
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

  // Root admin
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
    // Account already exists — update the password in case env var changed
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
    await pool.query("UPDATE users SET password=$1 WHERE id=$2", [hash, adminId]);
    console.log("✅ Root admin password synced from env");
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
    // Allow requests with no origin (mobile apps, curl, etc.)
    if (!origin) return callback(null, true);
    // Allow exact matches
    if (ALLOWED_ORIGINS.has(origin)) return callback(null, true);
    // Allow Cloudflare Pages preview URLs (*.game-3v1.pages.dev)
    if (/^https:\/\/[a-z0-9-]+\.game-3v1\.pages\.dev$/.test(origin)) return callback(null, true);
    callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));
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

async function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }

  // Always verify user actually exists in DB — JWT only proves identity claim
  try {
    const result = await pool.query(
      "SELECT id, username, is_admin, is_owner, is_owner2, is_og, is_mod, is_vip FROM users WHERE id=$1",
      [payload.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    req.user = {
      id:       u.id,
      username: u.username,
      isAdmin:  u.is_admin  || false,
      isOwner:  u.is_owner  || false,
      isOwner2: u.is_owner2 || false,
      isOG:     u.is_og     || false,
      isMod:    u.is_mod    || false,
      isVIP:    u.is_vip    || false,
    };
    next();
  } catch {
    return res.status(500).json({ error: "Server error" });
  }
}

// Re-checks DB on every request — JWT only proves identity, DB decides rank
async function requireAdmin(req, res, next) {
  const ip = getClientIP(req);
  if (isAdminLocked(ip)) return res.status(429).json({ error: "Too many failed attempts. Try again later." });

  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });

  let payload;
  try { payload = jwt.verify(auth.slice(7), JWT_SECRET); }
  catch { return res.status(401).json({ error: "Invalid token" }); }

  try {
    const result = await pool.query(
      "SELECT is_admin, is_owner, is_owner2 FROM users WHERE id=$1", [payload.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    if (!u.is_admin && !u.is_owner && !u.is_owner2) {
      trackAdminFail(ip);
      audit({ headers: req.headers, socket: req.socket, user: payload }, 'ADMIN_DENIED', req.path);
      return res.status(403).json({ error: "Admin only" });
    }
    req.user = { ...payload, isAdmin: u.is_admin, isOwner: u.is_owner, isOwner2: u.is_owner2 };
    next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
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
    const result = await pool.query(
      "SELECT is_owner, is_owner2 FROM users WHERE id=$1", [payload.id]
    );
    if (!result.rows.length) return res.status(401).json({ error: "User not found" });
    const u = result.rows[0];
    if (!u.is_owner && !u.is_owner2) {
      trackAdminFail(ip);
      audit({ headers: req.headers, socket: req.socket, user: payload }, 'OWNER_DENIED', req.path);
      return res.status(403).json({ error: "Owner only" });
    }
    req.user = { ...payload, isOwner: u.is_owner, isOwner2: u.is_owner2 };
    next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
}

// Mods, admins, and owners — DB-verified
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
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
}
app.get("/api/owner/audit", requireOwner, (req, res) => {
  audit(req, 'AUDIT_VIEW');
  res.json({ log: _auditLog });
});

// ═══════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════
function makeToken(userRow) {
  // SECURITY: Only embed ID and username — NEVER embed rank flags in JWT.
  // Ranks are always re-read from the DB on every privileged request.
  // This prevents any token manipulation from granting elevated access.
  return jwt.sign(
    {
      id:       userRow.id,
      username: userRow.username,
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
    // Block reserved and spoofable usernames
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

// ═══════════════════════════════════════
//  GAMBLING ROUTE
//  Atomic score delta — bypasses rate-cap since gambling wins/losses are instant
//  Server validates the bet was fair and the delta matches the outcome
// ═══════════════════════════════════════
app.post("/api/game/gamble", requireAuth, async (req, res) => {
  try {
    const { bet, delta, game } = req.body || {};

    // Validate inputs
    const betAmt   = parseFloat(bet);
    const deltaAmt = parseFloat(delta);
    if (isNaN(betAmt) || betAmt <= 0)   return res.status(400).json({ error: "Invalid bet" });
    if (isNaN(deltaAmt))                 return res.status(400).json({ error: "Invalid delta" });
    if (!['roulette','blackjack'].includes(game)) return res.status(400).json({ error: "Invalid game" });

    // Max bet cap — prevents someone betting 1Q and doubling it
    const MAX_BET = 1_000_000_000_000; // 1 trillion max bet
    if (betAmt > MAX_BET) return res.status(400).json({ error: `Max bet is ${MAX_BET}` });

    // Delta must be a valid gambling outcome for the bet size:
    // Roulette max win: 35x bet (single number). Blackjack max win: 2.5x bet (blackjack pays 3:2)
    const MAX_WIN_MULT = game === 'roulette' ? 35 : 2.5;
    if (deltaAmt > betAmt * MAX_WIN_MULT) return res.status(400).json({ error: "Invalid win amount" });
    // Max loss is the bet itself
    if (deltaAmt < -betAmt) return res.status(400).json({ error: "Invalid loss amount" });

    // Load current score
    const cur = await pool.query("SELECT score FROM game_state WHERE user_id=$1", [req.user.id]);
    if (!cur.rows.length) return res.status(404).json({ error: "No game state found" });

    const curScore = parseFloat(cur.rows[0].score) || 0;

    // Can't bet more than you have
    if (betAmt > curScore) return res.status(400).json({ error: "Insufficient score" });

    // Apply delta atomically
    const newScore = Math.max(0, curScore + deltaAmt);
    await pool.query(
      "UPDATE game_state SET score=$1, updated_at=NOW() WHERE user_id=$2",
      [newScore, req.user.id]
    );

    audit(req, `GAMBLE_${game.toUpperCase()}`, `bet:${betAmt} delta:${deltaAmt} new:${newScore}`);
    return res.json({ ok: true, newScore });
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

    // Score: validate based on time elapsed and max possible earn rate
    // This prevents jumping from any score to an impossible value regardless of current score
    const MAX_SCORE      = 1e18;
    const curScore       = parseFloat(curState.score) || 0;
    const submittedScore = clamp(s.score, 0, MAX_SCORE);

    // Calculate max score earnable since last save using actual game mechanics:
    // - Fastest cooldown: ~0.2s (fully upgraded)
    // - Max multiplier: ~200x (high prestige + all upgrades maxed)
    // - Max roll value at omega: ~10,000 base
    // - Vault passive income: generous upper bound ~1,000,000/sec at endgame
    // = ~200 * 10000 * 5 rolls/sec + 1,000,000/sec vault ≈ ~11,000,000/sec absolute max
    // We use 50,000,000/sec to be very generous for legitimate endgame players
    const MAX_SCORE_PER_SEC = 50_000_000;
    const lastSaveTime = curState.updated_at ? new Date(curState.updated_at).getTime() : 0;
    const elapsedSecs  = lastSaveTime ? Math.max(0, (Date.now() - lastSaveTime) / 1000) : 300; // default 5 min for first save
    const maxEarnable  = curScore + (MAX_SCORE_PER_SEC * elapsedSecs);
    const newScore     = Math.min(submittedScore, maxEarnable);

    // Luck level: 1–100, can only go up
    const curLuck  = parseInt(curState.luck_level) || 1;
    const newLuck  = clampI(s.luckLevel, curLuck, 100);

    // Prestige: can only go up by 1 per save — matches actual game mechanic
    // (prestige requires Lv50 + 10k score, so jumping 0→50 in one save is impossible legit)
    const curPrestige = parseInt(curState.prestige_level) || 0;
    const newPrestige = clampI(s.prestigeLevel, curPrestige, curPrestige + 1);

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
//  MOD ROUTES  (no IP data returned)
// ═══════════════════════════════════════
app.get("/api/mod/users", requireMod, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
             u.created_at,
             gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls
      FROM users u
      LEFT JOIN game_state gs ON gs.user_id = u.id
      ORDER BY gs.score DESC NULLS LAST
    `);
    // Never return IP data to mods
    return res.json({ users: result.rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/mod/reset/:id", requireMod, async (req, res) => {
  try {
    const target = await pool.query("SELECT is_admin, is_owner, is_owner2 FROM users WHERE id=$1", [req.params.id]);
    if (!target.rows.length) return res.status(404).json({ error: "User not found" });
    const t = target.rows[0];
    // Mods cannot reset admins or owners
    if (t.is_admin || t.is_owner || t.is_owner2) {
      audit(req, 'MOD_RESET_BLOCKED', `tried to reset admin/owner ${req.params.id}`);
      return res.status(403).json({ error: "Cannot reset admins or owners" });
    }
    await pool.query(`UPDATE game_state SET score=0, luck_level=1, luck_xp=0,
      mult_level=0, cd_level=0, auto_level=0, vault_level=0, xp_level=0,
      crit_level=0, echo_level=0, soul_level=0, voidupg_level=0, asc_level=0,
      time_level=0, forge_level=0, prestige_level=0, total_rolls=0,
      legendary_count=0, mythic_count=0, divine_count=0, celestial_count=0,
      ethereal_count=0, void_count=0, primordial_count=0, omega_count=0,
      crit_count=0, echo_count=0, achievements='{}', updated_at=NOW()
      WHERE user_id=$1`, [req.params.id]);
    audit(req, 'MOD_RESET', `reset user ${req.params.id}`);
    return res.json({ ok: true });
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
    const users = result.rows.map(u => {
      if (HIDDEN_IP_USERS.has(u.username.toLowerCase())) {
        return { ...u, last_ip: '🔒 hidden', ip_history: [] };
      }
      return u;
    });
    return res.json({ users });
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
    let user = u.rows[0];
    if (HIDDEN_IP_USERS.has(user.username.toLowerCase())) {
      user = { ...user, last_ip: '🔒 hidden', ip_history: [] };
    }
    return res.json({ user, state: rowToState(gs.rows[0]) });
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
    const users = result.rows.map(u => {
      if (HIDDEN_IP_USERS.has(u.username.toLowerCase())) {
        return { ...u, last_ip: '🔒 hidden', ip_history: [] };
      }
      return u;
    });
    return res.json({ users });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});


// ═══════════════════════════════════════
//  MULTIPLAYER — IN-MEMORY ROOMS
//  Polling-based (no WebSocket needed)
//  Rooms expire after 10 min of inactivity
// ═══════════════════════════════════════
const rooms = new Map(); // roomId → room object
const ROOM_TTL = 10 * 60 * 1000; // 10 min

function makeRoomId() {
  return Math.random().toString(36).slice(2, 8).toUpperCase();
}

function cleanRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
    if (now - room.lastActivity > ROOM_TTL) rooms.delete(id);
  }
}
setInterval(cleanRooms, 60_000);

function getRoom(id) { return rooms.get(id) || null; }

function roomView(room, myId) {
  return {
    id:          room.id,
    game:        room.game,
    phase:       room.phase,
    players:     room.players.map(p => ({
      id:       p.id,
      username: p.username,
      bet:      p.bet,
      ready:    p.ready,
      isYou:    p.id === myId,
      rank:     p.rank,
    })),
    chat:        room.chat.slice(-50),
    rouletteResult: room.rouletteResult || null,
    bjState:        room.bjState        || null,
    lastActivity:   room.lastActivity,
    maxPlayers:     room.maxPlayers,
  };
}

// Create room
app.post("/api/room/create", requireAuth, (req, res) => {
  cleanRooms();
  const { game } = req.body || {};
  if (!['roulette','blackjack'].includes(game)) return res.status(400).json({ error: "Invalid game" });

  const id   = makeRoomId();
  const rank = req.user.isOwner || req.user.isOwner2 ? 'owner' : req.user.isAdmin ? 'admin' : req.user.isMod ? 'mod' : req.user.isVIP ? 'vip' : req.user.isOG ? 'og' : 'player';
  const room = {
    id, game,
    phase:   'waiting', // waiting | betting | playing | results
    players: [{ id: req.user.id, username: req.user.username, bet: 0, ready: false, rank }],
    chat:    [{ system: true, text: `Room ${id} created. Share the code!`, ts: Date.now() }],
    rouletteResult: null,
    bjState:        null,
    lastActivity:   Date.now(),
    maxPlayers:     game === 'roulette' ? 8 : 6,
    hostId:         req.user.id,
  };
  rooms.set(id, room);
  audit(req, 'ROOM_CREATE', `${game} room ${id}`);
  res.json({ room: roomView(room, req.user.id) });
});

// Join room
app.post("/api/room/:id/join", requireAuth, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: "Room not found" });
  if (room.players.length >= room.maxPlayers) return res.status(400).json({ error: "Room is full" });
  if (room.phase !== 'waiting' && room.phase !== 'betting') return res.status(400).json({ error: "Game already in progress" });

  const already = room.players.find(p => p.id === req.user.id);
  if (!already) {
    const rank = req.user.isOwner || req.user.isOwner2 ? 'owner' : req.user.isAdmin ? 'admin' : req.user.isMod ? 'mod' : req.user.isVIP ? 'vip' : req.user.isOG ? 'og' : 'player';
    room.players.push({ id: req.user.id, username: req.user.username, bet: 0, ready: false, rank });
    room.chat.push({ system: true, text: `${req.user.username} joined`, ts: Date.now() });
  }
  room.lastActivity = Date.now();
  res.json({ room: roomView(room, req.user.id) });
});

// Poll room state
app.get("/api/room/:id/poll", requireAuth, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: "Room not found or expired" });

  // Mark player as still active
  const p = room.players.find(p => p.id === req.user.id);
  if (p) p.lastSeen = Date.now();
  room.lastActivity = Date.now();

  // Auto-remove players gone > 30 sec
  const cutoff = Date.now() - 30_000;
  const before = room.players.length;
  room.players = room.players.filter(p => !p.lastSeen || p.lastSeen > cutoff || p.id === room.hostId);
  if (room.players.length < before) {
    room.chat.push({ system: true, text: 'A player disconnected', ts: Date.now() });
  }

  res.json({ room: roomView(room, req.user.id) });
});

// Chat
app.post("/api/room/:id/chat", requireAuth, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: "Room not found" });
  const p = room.players.find(p => p.id === req.user.id);
  if (!p) return res.status(403).json({ error: "Not in room" });
  const text = (req.body.text || '').trim().slice(0, 120);
  if (!text) return res.status(400).json({ error: "Empty message" });
  room.chat.push({ id: req.user.id, username: req.user.username, rank: p.rank, text, ts: Date.now() });
  if (room.chat.length > 200) room.chat = room.chat.slice(-200);
  room.lastActivity = Date.now();
  res.json({ ok: true });
});

// ── ROULETTE MULTIPLAYER ──
// Set bet
app.post("/api/room/:id/roulette/bet", requireAuth, async (req, res) => {
  const room = getRoom(req.params.id);
  if (!room || room.game !== 'roulette') return res.status(404).json({ error: "Room not found" });
  const p = room.players.find(p => p.id === req.user.id);
  if (!p) return res.status(403).json({ error: "Not in room" });
  if (room.phase !== 'waiting' && room.phase !== 'betting') return res.status(400).json({ error: "Betting closed" });

  const { totalBet, bets } = req.body || {};
  const betAmt = parseFloat(totalBet);
  if (isNaN(betAmt) || betAmt <= 0) return res.status(400).json({ error: "Invalid bet" });
  if (betAmt > 1_000_000_000_000) return res.status(400).json({ error: "Max bet 1T" });

  // Verify they have enough score
  const gs = await pool.query("SELECT score FROM game_state WHERE user_id=$1", [req.user.id]);
  if (!gs.rows.length || parseFloat(gs.rows[0].score) < betAmt) return res.status(400).json({ error: "Insufficient score" });

  p.bet   = betAmt;
  p.bets  = bets; // store their specific number/outside bets
  p.ready = true;
  room.phase = 'betting';
  room.lastActivity = Date.now();

  res.json({ ok: true, room: roomView(room, req.user.id) });
});

// Spin (any player can trigger once all ready, or host after 30s)
app.post("/api/room/:id/roulette/spin", requireAuth, async (req, res) => {
  const room = getRoom(req.params.id);
  if (!room || room.game !== 'roulette') return res.status(404).json({ error: "Room not found" });
  if (room.phase === 'playing' || room.phase === 'results') return res.status(400).json({ error: "Already spinning or done" });
  if (room.players.filter(p => p.bet > 0).length === 0) return res.status(400).json({ error: "No bets placed" });

  room.phase = 'playing';
  const result = Math.floor(Math.random() * 37);
  const RED_NUMS = new Set([1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36]);
  const col = result === 0 ? 'green' : RED_NUMS.has(result) ? 'red' : 'black';

  // Calculate each player's delta
  const outside = { red: col==='red', black: col==='black', even: result!==0&&result%2===0, odd: result!==0&&result%2!==0, low: result>=1&&result<=18, high: result>=19&&result<=36, dozen1: result>=1&&result<=12, dozen2: result>=13&&result<=24, dozen3: result>=25&&result<=36, col1: result!==0&&result%3===1, col2: result!==0&&result%3===2, col3: result!==0&&result%3===0 };
  const outsidePayout = { red:1, black:1, even:1, odd:1, low:1, high:1, dozen1:2, dozen2:2, dozen3:2, col1:2, col2:2, col3:2 };

  const playerResults = [];
  for (const p of room.players) {
    if (!p.bet || !p.bets) continue;
    let delta = -p.bet;
    const b = p.bets;
    if (b.numbers && b.numbers[result] !== undefined) delta += b.numbers[result] * 36;
    if (b.outside) {
      for (const [type, amt] of Object.entries(b.outside)) {
        if (outside[type]) delta += amt * (outsidePayout[type] + 1);
      }
    }
    playerResults.push({ id: p.id, username: p.username, delta, bet: p.bet });

    // Apply to DB
    try {
      const cur = await pool.query("SELECT score FROM game_state WHERE user_id=$1", [p.id]);
      const cur_score = parseFloat(cur.rows[0]?.score) || 0;
      const newScore = Math.max(0, cur_score + delta);
      await pool.query("UPDATE game_state SET score=$1, updated_at=NOW() WHERE user_id=$2", [newScore, p.id]);
      audit({ headers: { authorization: 'room' }, socket: { remoteAddress: 'room' }, user: p }, `ROOM_ROULETTE`, `room:${room.id} result:${result} delta:${delta}`);
    } catch(e) { console.error('Score update error:', e); }
  }

  room.rouletteResult = { number: result, color: col, playerResults, ts: Date.now() };
  room.phase = 'results';
  room.chat.push({ system: true, text: `Spin result: ${result} (${col}) — ${playerResults.filter(r=>r.delta>0).length} winner(s)`, ts: Date.now() });

  // Reset for next round after 8s
  setTimeout(() => {
    if (!rooms.has(room.id)) return;
    room.phase   = 'waiting';
    room.players.forEach(p => { p.bet = 0; p.bets = null; p.ready = false; });
    room.rouletteResult = null;
    room.lastActivity   = Date.now();
  }, 8000);

  res.json({ room: roomView(room, req.user.id) });
});

// ── BLACKJACK MULTIPLAYER ──
// Player vs Player: one player is Dealer, others are Players
// Dealer is always the host (room.hostId)

app.post("/api/room/:id/blackjack/deal", requireAuth, async (req, res) => {
  const room = getRoom(req.params.id);
  if (!room || room.game !== 'blackjack') return res.status(404).json({ error: "Room not found" });
  if (req.user.id !== room.hostId) return res.status(403).json({ error: "Only the dealer (host) can deal" });
  if (room.players.length < 2) return res.status(400).json({ error: "Need at least 2 players" });
  if (room.phase === 'playing') return res.status(400).json({ error: "Round already in progress" });

  // Validate all non-dealer players have placed bets
  const nonDealers = room.players.filter(p => p.id !== room.hostId);
  const allBet = nonDealers.every(p => p.bet > 0);
  if (!allBet) return res.status(400).json({ error: "All players must place bets first" });

  // Build shoe and deal
  const VALS = ['A','2','3','4','5','6','7','8','9','10','J','Q','K'];
  const SUITS = ['♠','♥','♦','♣'];
  let shoe = [];
  for (let d = 0; d < 4; d++) for (const s of SUITS) for (const v of VALS) shoe.push({ v, s });
  for (let i = shoe.length-1; i > 0; i--) { const j = Math.floor(Math.random()*(i+1)); [shoe[i],shoe[j]]=[shoe[j],shoe[i]]; }

  const draw = () => shoe.pop();

  const bjState = {
    shoe,
    dealerHand:  [draw(), draw()],
    playerHands: {},
    currentTurn: null, // player id whose turn it is
    turnOrder:   nonDealers.map(p => p.id),
    turnIndex:   0,
    phase:       'player_turns', // player_turns | dealer_turn | results
    results:     {},
  };

  // Deal to each player
  for (const p of nonDealers) {
    bjState.playerHands[p.id] = [draw(), draw()];
  }

  bjState.currentTurn = bjState.turnOrder[0];
  room.bjState = bjState;
  room.phase   = 'playing';
  room.lastActivity = Date.now();
  room.chat.push({ system: true, text: 'Cards dealt! Players take turns.', ts: Date.now() });

  res.json({ room: roomView(room, req.user.id) });
});

// Player action (hit/stand)
app.post("/api/room/:id/blackjack/action", requireAuth, async (req, res) => {
  const room = getRoom(req.params.id);
  if (!room || room.game !== 'blackjack' || !room.bjState) return res.status(404).json({ error: "No active hand" });
  const bj = room.bjState;
  if (bj.currentTurn !== req.user.id) return res.status(400).json({ error: "Not your turn" });

  const { action } = req.body;
  const hand = bj.playerHands[req.user.id];
  const cardVal = c => c.v==='A' ? 11 : ['J','Q','K'].includes(c.v) ? 10 : parseInt(c.v);
  const total = h => { let t=0,a=0; h.forEach(c=>{t+=cardVal(c);if(c.v==='A')a++;}); while(t>21&&a>0){t-=10;a--;} return t; };

  if (action === 'hit') {
    hand.push(bj.shoe.pop());
    if (total(hand) >= 21) {
      bj.turnIndex++;
    }
  } else if (action === 'stand') {
    bj.turnIndex++;
  }

  // Advance turn
  if (bj.turnIndex >= bj.turnOrder.length) {
    // Dealer's turn
    bj.phase = 'dealer_turn';
    bj.currentTurn = room.hostId;

    // Dealer draws to 17
    while (total(bj.dealerHand) < 17) bj.dealerHand.push(bj.shoe.pop());

    const dTotal = total(bj.dealerHand);
    const dBust  = dTotal > 21;

    // Resolve each player
    for (const p of room.players.filter(r => r.id !== room.hostId)) {
      const pHand  = bj.playerHands[p.id];
      const pTotal = total(pHand);
      const pBJ    = pHand.length===2 && pTotal===21;
      const dBJ    = bj.dealerHand.length===2 && dTotal===21;
      let delta    = -p.bet;
      let outcome  = 'lose';

      if (pTotal > 21) { delta = -p.bet; outcome = 'bust'; }
      else if (pBJ && dBJ) { delta = 0; outcome = 'push'; }
      else if (pBJ)  { delta = Math.floor(p.bet * 1.5); outcome = 'blackjack'; }
      else if (dBJ)  { delta = -p.bet; outcome = 'lose'; }
      else if (dBust){ delta = p.bet; outcome = 'win'; }
      else if (pTotal > dTotal) { delta = p.bet; outcome = 'win'; }
      else if (pTotal < dTotal) { delta = -p.bet; outcome = 'lose'; }
      else { delta = 0; outcome = 'push'; }

      // Dealer (host) gets opposite
      const dealerDelta = -delta;
      bj.results[p.id] = { delta, outcome, pTotal, dTotal };

      // Apply to DB
      try {
        const pCur  = await pool.query("SELECT score FROM game_state WHERE user_id=$1",[p.id]);
        const pScore = Math.max(0, (parseFloat(pCur.rows[0]?.score)||0) + delta);
        await pool.query("UPDATE game_state SET score=$1, updated_at=NOW() WHERE user_id=$2",[pScore,p.id]);

        const dCur   = await pool.query("SELECT score FROM game_state WHERE user_id=$1",[room.hostId]);
        const dScore = Math.max(0, (parseFloat(dCur.rows[0]?.score)||0) + dealerDelta);
        await pool.query("UPDATE game_state SET score=$1, updated_at=NOW() WHERE user_id=$2",[dScore,room.hostId]);
      } catch(e) { console.error('BJ score error:', e); }
    }

    bj.phase = 'results';
    room.phase = 'results';
    const wins = Object.values(bj.results).filter(r=>r.outcome==='win'||r.outcome==='blackjack').length;
    room.chat.push({ system: true, text: `Dealer: ${dTotal}${dBust?' (BUST)':''} — ${wins} player(s) won`, ts: Date.now() });

    // Reset after 8s
    setTimeout(() => {
      if (!rooms.has(room.id)) return;
      room.phase   = 'waiting';
      room.bjState = null;
      room.players.forEach(p => { p.bet = 0; p.ready = false; });
      room.lastActivity = Date.now();
    }, 8000);
  } else {
    bj.currentTurn = bj.turnOrder[bj.turnIndex];
  }

  room.lastActivity = Date.now();
  res.json({ room: roomView(room, req.user.id) });
});

// Place bet for blackjack
app.post("/api/room/:id/blackjack/bet", requireAuth, async (req, res) => {
  const room = getRoom(req.params.id);
  if (!room || room.game !== 'blackjack') return res.status(404).json({ error: "Room not found" });
  if (req.user.id === room.hostId) return res.status(400).json({ error: "Dealer doesn't place bets" });
  if (room.phase === 'playing') return res.status(400).json({ error: "Round in progress" });

  const betAmt = parseFloat(req.body.bet);
  if (isNaN(betAmt) || betAmt <= 0) return res.status(400).json({ error: "Invalid bet" });
  if (betAmt > 1_000_000_000_000) return res.status(400).json({ error: "Max bet 1T" });

  const gs = await pool.query("SELECT score FROM game_state WHERE user_id=$1", [req.user.id]);
  if (!gs.rows.length || parseFloat(gs.rows[0].score) < betAmt) return res.status(400).json({ error: "Insufficient score" });

  const p = room.players.find(p => p.id === req.user.id);
  if (!p) return res.status(403).json({ error: "Not in room" });
  p.bet   = betAmt;
  p.ready = true;
  room.lastActivity = Date.now();
  res.json({ ok: true, room: roomView(room, req.user.id) });
});

// Leave room
app.post("/api/room/:id/leave", requireAuth, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.json({ ok: true });
  room.players = room.players.filter(p => p.id !== req.user.id);
  room.chat.push({ system: true, text: `${req.user.username} left`, ts: Date.now() });
  if (room.players.length === 0) rooms.delete(room.id);
  res.json({ ok: true });
});

// List open rooms
app.get("/api/rooms/:game", requireAuth, (req, res) => {
  cleanRooms();
  const { game } = req.params;
  const list = [...rooms.values()]
    .filter(r => r.game === game && r.players.length < r.maxPlayers && r.phase === 'waiting')
    .map(r => ({ id: r.id, players: r.players.length, maxPlayers: r.maxPlayers, host: r.players[0]?.username }));
  res.json({ rooms: list });
});

// ── ADMIN: list ALL active rooms (any game) ──
app.get("/api/admin/rooms", requireAdmin, (req, res) => {
  cleanRooms();
  const list = [...rooms.values()].map(r => ({
    id:        r.id,
    game:      r.game,
    phase:     r.phase,
    players:   r.players.map(p => ({ id: p.id, username: p.username, bet: p.bet, ready: p.ready })),
    hostId:    r.hostId,
    hostName:  r.players[0]?.username || '?',
    maxPlayers:r.maxPlayers,
    lastActivity: r.lastActivity,
    chatCount: r.chat.length,
  }));
  res.json({ rooms: list, total: list.length });
});

// ── ADMIN: force-close a room ──
app.delete("/api/admin/rooms/:id", requireAdmin, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: "Room not found" });
  rooms.delete(req.params.id);
  audit(req, 'ADMIN_CLOSE_ROOM', `room ${req.params.id} (${room.game})`);
  res.json({ ok: true });
});

// ── ADMIN: kick player from room ──
app.post("/api/admin/rooms/:id/kick/:userId", requireAdmin, (req, res) => {
  const room = getRoom(req.params.id);
  if (!room) return res.status(404).json({ error: "Room not found" });
  const before = room.players.length;
  room.players = room.players.filter(p => p.id !== req.params.userId);
  if (room.players.length === before) return res.status(404).json({ error: "Player not in room" });
  room.chat.push({ system: true, text: 'A player was removed by admin', ts: Date.now() });
  audit(req, 'ADMIN_KICK_FROM_ROOM', `kicked ${req.params.userId} from room ${req.params.id}`);
  res.json({ ok: true });
});

// ── BLACKJACK LEADERBOARD — tracks wins/losses in game_state extra cols ──
// We piggyback on existing leaderboard but add a ?game=blackjack filter for future use
app.get("/api/leaderboard/blackjack", async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    // Sort by score descending — blackjack winnings go into main score
    const result = await pool.query(
      `SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip,
              gs.score, gs.prestige_level, gs.total_rolls, gs.updated_at
       FROM users u JOIN game_state gs ON gs.user_id = u.id
       ORDER BY gs.score DESC LIMIT $1`,
      [limit]
    );
    return res.json({
      leaderboard: result.rows.map((r, i) => ({
        rank: i + 1, id: r.id, username: r.username,
        isAdmin: r.is_admin, isOwner: r.is_owner || false,
        isOwner2: r.is_owner2 || false, isOG: r.is_og || false,
        isMod: r.is_mod || false, isVIP: r.is_vip || false,
        score: parseFloat(r.score), prestigeLevel: r.prestige_level,
        totalRolls: r.total_rolls, lastSeen: r.updated_at,
      })),
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});


app.get("/health", (req, res) => res.json({ status: "ok", time: new Date().toISOString() }));
app.get("/",       (req, res) => res.json({ name: "Capital RNG API", version: "2.0.0" }));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB()
  .then(() => app.listen(PORT, () => console.log(`🚀 Capital RNG API running on port ${PORT}`)))
  .catch((err) => { console.error("❌ DB init failed:", err); process.exit(1); });
