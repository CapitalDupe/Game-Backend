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
    { id: user.id, username: user.username, isAdmin: user.is_admin },
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

    const user = { id, username, is_admin: false };
    res.json({ token: makeToken(user), user: { id, username, isAdmin: false } });
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

    res.json({ token: makeToken(user), user: { id: user.id, username: user.username, isAdmin: user.is_admin } });
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
        u.id, u.username, u.is_admin,
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
      SELECT u.id, u.username, u.is_admin, u.created_at,
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

    if (s.isAdmin !== undefined && id !== 'uid_admin_root') {
      await pool.query('UPDATE users SET is_admin = $1 WHERE id = $2', [!!s.isAdmin, id]);
    }
    if (s.password) {
      const hash = await bcrypt.hash(s.password, 10);
      await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hash, id]);
    }

    await pool.query(`
      UPDATE game_state SET
        score=$2, luck_level=$3, prestige_level=$4, total_rolls=$5,
        mult_level=$6, cd_level=$7, auto_level=$8, vault_level=$9,
        xp_level=$10, crit_level=$11, voidupg_level=$12, echo_level=$13,
        updated_at=NOW()
      WHERE user_id=$1
    `, [
      id,
      s.score ?? 0, s.luckLevel ?? 1, s.prestigeLevel ?? 0, s.totalRolls ?? 0,
      s.multLevel ?? 0, s.cdLevel ?? 0, s.autoLevel ?? 0, s.vaultLevel ?? 0,
      s.xpLevel ?? 0, s.critLevel ?? 0, s.voidupgLevel ?? 0, s.echoLevel ?? 0,
    ]);

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
//  HEALTH CHECK
// ═══════════════════════════════════════
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ name: 'RNG Incremental API', version: '2.0.0' }));

// ═══════════════════════════════════════
//  START
// ═══════════════════════════════════════
initDB().then(() => {
  app.listen(PORT, () => console.log(`🚀 RNG API running on port ${PORT}`));
}).catch(err => {
  console.error('❌ DB init failed:', err);
  process.exit(1);
});
