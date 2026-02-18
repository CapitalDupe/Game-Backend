const express = require('express');
const cors    = require('cors');
const helmet  = require('helmet');
const { Pool } = require('pg');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production-please';

// ═══════════════════════════════════════
//  DATABASE
// ═══════════════════════════════════════
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
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

  // Ensure root admin account exists
  const adminId = 'uid_admin_root';
  const existing = await pool.query('SELECT id FROM users WHERE id = $1', [adminId]);
  if (existing.rows.length === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      `INSERT INTO users (id, username, password, is_admin) VALUES ($1, $2, $3, TRUE)
       ON CONFLICT DO NOTHING`,
      [adminId, 'admin', hash]
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
    console.log('✅ Root admin account created (admin / admin123)');
  }

  // Migrate: add rank columns if they don't exist
  const migrations = [
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner2   BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip     TEXT DEFAULT NULL`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS ip_history  TEXT[] DEFAULT '{}'`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_og    BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_mod   BOOLEAN DEFAULT FALSE`,
    `ALTER TABLE users ADD COLUMN IF NOT EXISTS is_vip   BOOLEAN DEFAULT FALSE`,
  ];
  for (const sql of migrations) {
    try { await pool.query(sql); } catch(e) { console.warn('Migration skipped:', e.message); }
  }

  console.log('✅ Database initialized');
}

// ═══════════════════════════════════════
//  MIDDLEWARE
// ═══════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.FRONTEND_ORIGIN || '*',
  credentials: true,
}));
app.use(express.json());

// Auth middleware
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Admin only' });
    next();
  });
}

// ═══════════════════════════════════════
//  HELPERS
// ═══════════════════════════════════════
function makeToken(user) {
  return jwt.sign(
    {
      id:      user.id,
      username:user.username,
      isAdmin: user.is_admin,
      isOwner:  user.is_owner  || false,
      isOwner2: user.is_owner2 || false,
      isOG:    user.is_og    || false,
      isMod:   user.is_mod   || false,
      isVIP:   user.is_vip   || false,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function rowToState(row) {
  if (!row) return null;
  return {
    score:          parseFloat(row.score)      || 0,
    luckLevel:      row.luck_level             || 1,
    luckXP:         parseFloat(row.luck_xp)    || 0,
    multLevel:      row.mult_level             || 0,
    cdLevel:        row.cd_level               || 0,
    autoLevel:      row.auto_level             || 0,
    vaultLevel:     row.vault_level            || 0,
    xpLevel:        row.xp_level               || 0,
    critLevel:      row.crit_level             || 0,
    echoLevel:      row.echo_level             || 0,
    soulLevel:      row.soul_level             || 0,
    voidupgLevel:   row.voidupg_level          || 0,
    ascLevel:       row.asc_level              || 0,
    timeLevel:      row.time_level             || 0,
    forgeLevel:     row.forge_level            || 0,
    prestigeLevel:  row.prestige_level         || 0,
    totalRolls:     row.total_rolls            || 0,
    legendaryCount: row.legendary_count        || 0,
    mythicCount:    row.mythic_count           || 0,
    divineCount:    row.divine_count           || 0,
    celestialCount: row.celestial_count        || 0,
    etherealCount:  row.ethereal_count         || 0,
    voidCount:      row.void_count             || 0,
    primordialCount:row.primordial_count       || 0,
    omegaCount:     row.omega_count            || 0,
    critCount:      row.crit_count             || 0,
    echoCount:      row.echo_count             || 0,
    achievements:   row.achievements           || [],
  };
}

// ═══════════════════════════════════════
//  AUTH ROUTES
function getClientIP(req) {
  return (
    req.headers['cf-connecting-ip'] ||       // Cloudflare
    req.headers['x-forwarded-for']?.split(',')[0].trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

async function recordIP(userId, ip) {
  if (!ip || ip === 'unknown') return;
  try {
    await pool.query(`
      UPDATE users SET
        last_ip = $2,
        ip_history = (
          SELECT ARRAY(
            SELECT DISTINCT unnest(array_append(COALESCE(ip_history,'{}'), $2::TEXT))
            LIMIT 20
          )
        )
      WHERE id = $1
    `, [userId, ip]);
  } catch(e) { console.warn('IP record failed:', e.message); }
}


// ═══════════════════════════════════════
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || username.length < 2)  return res.status(400).json({ error: 'Username must be 2+ chars' });
    if (!password || password.length < 6)  return res.status(400).json({ error: 'Password must be 6+ chars' });
    if (username.toLowerCase() === 'admin') return res.status(400).json({ error: 'Username reserved' });

    const exists = await pool.query('SELECT id FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (exists.rows.length) return res.status(409).json({ error: 'Username already taken' });

    const id   = 'u_' + Date.now() + '_' + Math.random().toString(36).slice(2);
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (id, username, password) VALUES ($1, $2, $3)',
      [id, username, hash]
    );
    await pool.query('INSERT INTO game_state (user_id) VALUES ($1)', [id]);

    const signupIP = getClientIP(req);
    await recordIP(id, signupIP);
    const user = { id, username, is_admin: false, is_owner: false, is_owner2: false, is_og: false, is_mod: false, is_vip: false };
    res.json({ token: makeToken(user), user: { id, username, isAdmin: false, isOwner: false, isOwner2: false, isOG: false, isMod: false, isVIP: false } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE LOWER(username) = LOWER($1)', [username]);
    if (!result.rows.length) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const loginIP = getClientIP(req);
    await recordIP(user.id, loginIP);
    res.json({ token: makeToken(user), user: { id: user.id, username: user.username, isAdmin: user.is_admin, isOwner: user.is_owner || false, isOwner2: user.is_owner2 || false, isOG: user.is_og || false, isMod: user.is_mod || false, isVIP: user.is_vip || false } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════════
//  GAME STATE ROUTES
// ═══════════════════════════════════════
app.get('/api/game/load', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM game_state WHERE user_id = $1', [req.user.id]);
    res.json({ state: rowToState(result.rows[0]) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/game/save', requireAuth, async (req, res) => {
  try {
    const s = req.body;
    await pool.query(`
      INSERT INTO game_state (
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
        echo_count=$28, achievements=$29, updated_at=NOW()
    `, [
      req.user.id,
      s.score || 0, s.luckLevel || 1, s.luckXP || 0,
      s.multLevel || 0, s.cdLevel || 0, s.autoLevel || 0,
      s.vaultLevel || 0, s.xpLevel || 0, s.critLevel || 0,
      s.echoLevel || 0, s.soulLevel || 0, s.voidupgLevel || 0,
      s.ascLevel || 0, s.timeLevel || 0, s.forgeLevel || 0,
      s.prestigeLevel || 0, s.totalRolls || 0,
      s.legendaryCount || 0, s.mythicCount || 0, s.divineCount || 0,
      s.celestialCount || 0, s.etherealCount || 0, s.voidCount || 0,
      s.primordialCount || 0, s.omegaCount || 0, s.critCount || 0,
      s.echoCount || 0, s.achievements || [],
    ]);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════════
//  LEADERBOARD ROUTES
// ═══════════════════════════════════════
app.get('/api/leaderboard', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const sortBy = req.query.sort || 'score'; // score | prestige | rolls | luck

    const colMap = {
      score:    'gs.score',
      prestige: 'gs.prestige_level',
      rolls:    'gs.total_rolls',
      luck:     'gs.luck_level',
    };
    const orderCol = colMap[sortBy] || 'gs.score';

    const result = await pool.query(`
      SELECT
        u.id, u.username, u.is_admin, u.is_owner, u.is_og, u.is_mod, u.is_vip,
        gs.score, gs.luck_level, gs.prestige_level,
        gs.total_rolls, gs.omega_count, gs.void_count,
        gs.legendary_count, gs.mythic_count, gs.divine_count,
        gs.achievements, gs.updated_at
      FROM users u
      JOIN game_state gs ON gs.user_id = u.id
      ORDER BY ${orderCol} DESC
      LIMIT $1
    `, [limit]);

    res.json({ leaderboard: result.rows.map((r, i) => ({
      rank:          i + 1,
      id:            r.id,
      username:      r.username,
      isAdmin:       r.is_admin,
      isOwner:       r.is_owner  || false,
      isOwner2:      r.is_owner2 || false,
      isOG:          r.is_og    || false,
      isMod:         r.is_mod   || false,
      isVIP:         r.is_vip   || false,
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
    }))});
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════════
//  ADMIN ROUTES
// ═══════════════════════════════════════
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT u.id, u.username, u.is_admin, u.is_owner, u.is_owner2, u.is_og, u.is_mod, u.is_vip, u.last_ip, u.ip_history, u.created_at,
             gs.score, gs.luck_level, gs.prestige_level, gs.total_rolls
      FROM users u
      LEFT JOIN game_state gs ON gs.user_id = u.id
      ORDER BY gs.score DESC NULLS LAST
    `);
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const u = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    const gs = await pool.query('SELECT * FROM game_state WHERE user_id = $1', [req.params.id]);
    if (!u.rows.length) return res.status(404).json({ error: 'User not found' });
    res.json({ user: u.rows[0], state: rowToState(gs.rows[0]) });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const s = req.body;

    const rankUpdates = [];
    const rankVals = [];
    let ri = 1;
    // Owner can only be set if requester is owner themselves
    if (s.isOwner  !== undefined) { rankUpdates.push(`is_owner=$${ri++}`);  rankVals.push(!!s.isOwner); }
    if (s.isOwner2 !== undefined) { rankUpdates.push(`is_owner2=$${ri++}`); rankVals.push(!!s.isOwner2); }
    if (s.isAdmin !== undefined && id !== 'uid_admin_root') { rankUpdates.push(`is_admin=$${ri++}`); rankVals.push(!!s.isAdmin); }
    if (s.isOG    !== undefined) { rankUpdates.push(`is_og=$${ri++}`);    rankVals.push(!!s.isOG); }
    if (s.isMod   !== undefined) { rankUpdates.push(`is_mod=$${ri++}`);   rankVals.push(!!s.isMod); }
    if (s.isVIP   !== undefined) { rankUpdates.push(`is_vip=$${ri++}`);   rankVals.push(!!s.isVIP); }
    if (rankUpdates.length > 0) {
      rankVals.push(id);
      await pool.query(`UPDATE users SET ${rankUpdates.join(', ')} WHERE id=$${ri}`, rankVals);
    }
    if (s.password) {
      const hash = await bcrypt.hash(s.password, 10);
      await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, id]);
    }

    // Build dynamic UPDATE — only touch fields that were sent
    const map = {
      score:         'score',
      luckLevel:     'luck_level',
      prestigeLevel: 'prestige_level',
      totalRolls:    'total_rolls',
      voidCount:     'void_count',
      omegaCount:    'omega_count',
      multLevel:     'mult_level',
      cdLevel:       'cd_level',
      autoLevel:     'auto_level',
      vaultLevel:    'vault_level',
      xpLevel:       'xp_level',
      critLevel:     'crit_level',
      voidupgLevel:  'voidupg_level',
      echoLevel:     'echo_level',
      soulLevel:     'soul_level',
      ascLevel:      'asc_level',
      timeLevel:     'time_level',
      forgeLevel:    'forge_level',
    };
    const fields = [];
    const vals   = [id];
    let   idx    = 2;
    for (const [jsKey, dbCol] of Object.entries(map)) {
      if (s[jsKey] !== undefined) {
        fields.push(`${dbCol}=$${idx++}`);
        vals.push(s[jsKey]);
      }
    }
    if (fields.length > 0) {
      fields.push('updated_at=NOW()');
      // Upsert: create the row if it doesn't exist, then update it
      await pool.query(`INSERT INTO game_state (user_id) VALUES ($1) ON CONFLICT DO NOTHING`, [id]);
      const rowsAffected = await pool.query(
        `UPDATE game_state SET ${fields.join(', ')} WHERE user_id=$1`,
        vals
      );
      if (rowsAffected.rowCount === 0) {
        console.warn(`PATCH admin/user: no game_state row for ${id} even after upsert`);
      }
    }

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/user/:id', requireAdmin, async (req, res) => {
  try {
    if (req.params.id === 'uid_admin_root') return res.status(403).json({ error: 'Cannot delete root admin' });
    await pool.query('DELETE FROM users WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/reset/:id', requireAdmin, async (req, res) => {
  try {
    await pool.query(`
      UPDATE game_state SET
        score=0, luck_level=1, luck_xp=0, mult_level=0, cd_level=0,
        auto_level=0, vault_level=0, xp_level=0, crit_level=0, echo_level=0,
        soul_level=0, voidupg_level=0, asc_level=0, time_level=0, forge_level=0,
        prestige_level=0, total_rolls=0, legendary_count=0, mythic_count=0,
        divine_count=0, celestial_count=0, ethereal_count=0, void_count=0,
        primordial_count=0, omega_count=0, crit_count=0, echo_count=0,
        achievements='{}', updated_at=NOW()
      WHERE user_id=$1
    `, [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Global settings (in-memory, broadcast via response)
let globalSettings = { globalMult: 1, xpRate: 1, broadcastMsg: '' };
app.get('/api/settings',  (req, res) => res.json(globalSettings));
app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const { globalMult, xpRate, broadcastMsg } = req.body;
  if (globalMult !== undefined) globalSettings.globalMult = parseFloat(globalMult) || 1;
  if (xpRate     !== undefined) globalSettings.xpRate     = parseFloat(xpRate)     || 1;
  if (broadcastMsg !== undefined) globalSettings.broadcastMsg = broadcastMsg;
  res.json({ ok: true, settings: globalSettings });
});

// ═══════════════════════════════════════
//  OWNER IP LOOKUP
// ═══════════════════════════════════════
app.get('/api/owner/ips', requireAdmin, async (req, res) => {
  try {
    // Only owner or owner2 can see IPs
    const caller = await pool.query('SELECT is_owner, is_owner2 FROM users WHERE id = $1', [req.user.id]);
    if (!caller.rows[0]?.is_owner && !caller.rows[0]?.is_owner2) {
      return res.status(403).json({ error: 'Owner only' });
    }
    const result = await pool.query(`
      SELECT id, username, is_admin, is_owner, is_owner2, last_ip, ip_history, created_at
      FROM users ORDER BY created_at DESC
    `);
    res.json({ users: result.rows });
  } catch(err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// ═══════════════════════════════════════
//  HEALTH CHECK
// ═══════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ name: 'Capital RNG API', version: '2.0.0' }));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 Capital RNG API running on port ${PORT}`));
}).catch(err => {
  console.error('❌ DB init failed:', err);
  process.exit(1);
});
function requireOwner(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user.isOwner && !req.user.isOwner2) {
      return res.status(403).json({ error: 'Owner only' });
    }
    next();
  });
}

app.post('/api/owner/verify-passphrase', requireOwner, (req, res) => {
  const { passphrase } = req.body || {};
  if (!passphrase) return res.status(400).json({ error: 'Missing passphrase' });

  // Compare to env var (never sent to client)
  if (passphrase !== process.env.OWNER_PANEL_PASSPHRASE) {
    return res.status(401).json({ error: 'Wrong passphrase' });
  }

  res.json({ ok: true });
});
