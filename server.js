// server.js — SmartBiz backend (Neon Postgres)
require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const { Pool } = require('pg');
const path     = require('path');
const crypto   = require('crypto');

const PORT        = parseInt(process.env.PORT, 10) || 3000;
const HOST        = process.env.HOST || '0.0.0.0';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || crypto.randomBytes(24).toString('hex');

// Prefer the pooled connection string (Neon recommends it for app traffic)
const DATABASE_URL = process.env.DATABASE_URL_POOLED || process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('DATABASE_URL or DATABASE_URL_POOLED env var is required.');
  process.exit(1);
}

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000
});

pool.on('error', err => console.error('Unexpected pool error:', err));

// Create schema on startup
(async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        id            SERIAL PRIMARY KEY,
        business_name TEXT NOT NULL,
        answers_json  JSONB NOT NULL,
        user_agent    TEXT,
        ip            TEXT,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_created_at ON submissions (created_at);
    `);
    console.log('Schema ready');
  } catch (err) {
    console.error('Schema creation failed:', err.message);
  }
})();

const app = express();
app.set('trust proxy', true);

app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)) {
      return cb(null, true);
    }
    return cb(new Error('Origin not allowed'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x-admin-token']
}));
app.use(express.json({ limit: '256kb' }));

// --- rate limiter (in-memory) ---
const rateMap = new Map();
const RATE_WINDOW_MS = 10 * 60 * 1000;
const RATE_MAX = 10;

function rateLimit(req, res, next) {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  const e   = rateMap.get(ip) || { count: 0, reset: now + RATE_WINDOW_MS };
  if (now > e.reset) { e.count = 0; e.reset = now + RATE_WINDOW_MS; }
  e.count++;
  rateMap.set(ip, e);
  if (e.count > RATE_MAX) {
    return res.status(429).json({ ok: false, error: 'Too many submissions. Please try again later.' });
  }
  next();
}

// --- POST: save submission ---
app.post('/api/submissions', rateLimit, async (req, res) => {
  try {
    const { businessName, answers } = req.body || {};

    if (typeof businessName !== 'string' || !businessName.trim()) {
      return res.status(400).json({ ok: false, error: 'businessName is required.' });
    }
    if (!answers || typeof answers !== 'object' || Array.isArray(answers)) {
      return res.status(400).json({ ok: false, error: 'answers must be an object.' });
    }

    const cleanName  = businessName.trim().slice(0, 200);
    const answersStr = JSON.stringify(answers);
    if (answersStr.length > 100_000) {
      return res.status(413).json({ ok: false, error: 'Answers are too large.' });
    }

    const result = await pool.query(
      `INSERT INTO submissions (business_name, answers_json, user_agent, ip)
       VALUES ($1, $2::jsonb, $3, $4) RETURNING id`,
      [
        cleanName,
        answersStr,
        String(req.get('user-agent') || '').slice(0, 400),
        String(req.ip || '').slice(0, 64)
      ]
    );

    const newId = result.rows[0].id;
    console.log(`[${new Date().toISOString()}] saved #${newId} "${cleanName}"`);
    res.status(201).json({ ok: true, id: newId });
  } catch (err) {
    console.error('POST /api/submissions error:', err);
    res.status(500).json({ ok: false, error: 'Could not save submission.' });
  }
});

// --- admin auth ---
function requireAdmin(req, res, next) {
  const token = req.get('x-admin-token') || req.query.token;
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, error: 'Unauthorized.' });
  }
  next();
}

// --- GET: list ---
app.get('/api/submissions', requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
    const result = await pool.query(
      `SELECT id, business_name, created_at, ip, user_agent
       FROM submissions ORDER BY id DESC LIMIT $1`,
      [limit]
    );
    res.json({ ok: true, count: result.rowCount, submissions: result.rows });
  } catch (err) {
    console.error('GET /api/submissions error:', err);
    res.status(500).json({ ok: false, error: 'Could not load submissions.' });
  }
});

// --- GET: one ---
app.get('/api/submissions/:id', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM submissions WHERE id = $1', [req.params.id]);
    const row = result.rows[0];
    if (!row) return res.status(404).json({ ok: false, error: 'Not found.' });
    res.json({
      ok: true,
      submission: {
        id:           row.id,
        businessName: row.business_name,
        createdAt:    row.created_at,
        ip:           row.ip,
        userAgent:    row.user_agent,
        answers:      row.answers_json  // already a JSON object
      }
    });
  } catch (err) {
    console.error('GET /api/submissions/:id error:', err);
    res.status(500).json({ ok: false, error: 'Could not load submission.' });
  }
});

// --- GET: CSV export (new) ---
app.get('/api/submissions.csv', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, business_name, answers_json, created_at, ip
       FROM submissions ORDER BY id ASC`
    );

    // Build a flat schema: always emit every question seen across all rows,
    // in a stable order (q1, q2, ..., q8a, ...). Question text is the header.
    const questionKeys = new Map();       // qid → question text
    const parsedRows = result.rows.map(r => {
      const answers = r.answers_json || {};
      Object.entries(answers).forEach(([qid, item]) => {
        if (item && item.question && !questionKeys.has(qid)) {
          questionKeys.set(qid, item.question);
        }
      });
      return { row: r, answers };
    });

    // Sort question keys the way they appear in the form:
    // "q1", "q2", ..., "q8", "q8a", "q9", ...
    const sortedQids = [...questionKeys.keys()].sort((a, b) => {
      const numA = parseInt(a.match(/\d+/)?.[0] || '0', 10);
      const numB = parseInt(b.match(/\d+/)?.[0] || '0', 10);
      if (numA !== numB) return numA - numB;
      return a.localeCompare(b);
    });

    // CSV helpers
    const escapeCsv = (v) => {
      if (v == null) return '';
      const s = String(v);
      if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    };

    const headers = [
      'id',
      'business_name',
      'created_at',
      'ip',
      ...sortedQids.map(qid => questionKeys.get(qid))
    ];

    const lines = [headers.map(escapeCsv).join(',')];

    for (const { row, answers } of parsedRows) {
      const cells = [
        row.id,
        row.business_name,
        row.created_at instanceof Date ? row.created_at.toISOString() : row.created_at,
        row.ip || ''
      ];
      for (const qid of sortedQids) {
        const item = answers[qid];
        cells.push(item && item.answer != null ? item.answer : '');
      }
      lines.push(cells.map(escapeCsv).join(','));
    }

    const csv = '\uFEFF' + lines.join('\r\n');   // BOM helps Excel open UTF-8 correctly

    const stamp = new Date().toISOString().slice(0, 10);
    const filename = `smartbiz_submissions_${stamp}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (err) {
    console.error('GET /api/submissions.csv error:', err);
    res.status(500).json({ ok: false, error: 'Could not export CSV.' });
  }
});

// --- health ---
app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'up', time: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ ok: false, db: 'down', error: err.message });
  }
});

// --- static frontend ---
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, HOST, () => {
  console.log(`SmartBiz backend listening on http://${HOST}:${PORT}`);
  console.log(`Using ${process.env.DATABASE_URL_POOLED ? 'pooled' : 'direct'} Neon connection`);
  console.log(`Admin token: ${ADMIN_TOKEN}`);
});
