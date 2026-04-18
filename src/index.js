require("dotenv").config();
const dns = require("dns"); dns.setDefaultResultOrder("ipv4first");
const express = require("express");
const cors = require("cors");
const { getDb } = require("./db");

const app = express();
const PORT = Number(process.env.PORT) || 5050; // default dev port

// quick startup debug (does not print secrets)
console.log('Starting backend', { PORT, MONGODB_URI_set: !!process.env.MONGODB_URI });

// Allow the frontend origin to be configured via env (use Vite default 5173 in dev)
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:5173';
// Dev-friendly CORS: allow the configured origin or any localhost origin (different Vite ports)
app.use(cors({
  origin: (origin, cb) => {
    // Allow non-browser requests (curl, server-side) which have no origin
    if (!origin) return cb(null, true);
    if (origin === FRONTEND_ORIGIN) return cb(null, true);
    // Accept any localhost origin for dev convenience (different Vite ports)
    try {
      const u = new URL(origin);
      if (u.hostname === 'localhost') return cb(null, true);
    } catch (e) {
      // fall through
    }
    return cb(new Error('CORS not allowed'));
  },
  credentials: true
}));
app.use(express.json());
// Proxy to Python geometry engine (FastAPI)
const PY_ENGINE_URL = process.env.PY_ENGINE_URL || 'http://127.0.0.1:8000';
app.post('/api/parking/generate', async (req, res) => {
  try {
    const resp = await fetch(`${PY_ENGINE_URL}/parking/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body || {})
    });
    const data = await resp.json();
    return res.status(resp.status).json(data);
  } catch (e) {
    return res.status(502).json({ ok: false, error: e.message });
  }
});
// Circulation generation (stub)
// Accepts constraints and returns simple echoed path segments for now.
app.post('/api/circulation', async (req, res) => {
  try {
    const { scopeId, constraints, geometry } = req.body || {};
    if (!scopeId) return res.status(400).json({ error: 'scopeId required' });
    // Placeholder algorithm: return provided geometry or a trivial L-shaped path
    const segments = Array.isArray(geometry?.segments) ? geometry.segments : [
      { from: { x: 0, y: 0 }, to: { x: 10, y: 0 } },
      { from: { x: 10, y: 0 }, to: { x: 10, y: 5 } },
    ];
    res.json({ ok: true, scopeId, constraints: constraints || {}, segments });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Rectangle generator backed endpoint using architect-like heuristics
const { generateCirculationRect } = require('./circulation/generator');
app.post('/api/circulation/generate', async (req, res) => {
  try {
    const { siteRect, constraints } = req.body || {};
    const result = generateCirculationRect(siteRect, constraints);
    if (!result || !result.ok) return res.status(400).json(result || { ok: false });
    res.json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// NOTE: /api/parking/generate is handled by the Python proxy defined above

// BSI (Building Scheme Intelligence) routes
const bsiRoutes = require('./bsi/bsiRoutes');
app.use('/api/bsi', bsiRoutes);

// health
app.get("/healthz", async (_req, res) => {
  try {
    const db = await getDb();
    const r = await db.command({ ping: 1 });
    res.json({ ok: r.ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// simple landing so hitting the root in a browser shows available endpoints
app.get('/', (_req, res) => {
  res.json({
    ok: true,
    message: 'OccuCalc backend running',
    endpoints: {
      health: '/healthz',
      circulationStub: 'POST /api/circulation',
      circulationGenerate: 'POST /api/circulation/generate',
      parkingGenerate: 'POST /api/parking/generate'
    }
  });
});

// LIST rooms
app.get("/rooms", async (_req, res) => {
  try {
    const db = await getDb();
    const items = await db.collection("rooms").find().limit(200).toArray();
    res.json(items);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// CREATE room
app.post("/rooms", async (req, res) => {
  try {
    const { number, name, area, occupancyType } = req.body || {};
    if (!number || area == null || !occupancyType) {
      return res.status(400).json({ error: "number, area, occupancyType required" });
    }
    const db = await getDb();
    const doc = { number, name: name || "", area: Number(area), occupancyType, createdAt: new Date() };
    const r = await db.collection("rooms").insertOne(doc);
    res.json({ insertedId: r.insertedId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Simple dev-friendly /me endpoint so lightweight dev server on port 5050
// can satisfy frontend checks without the full auth stack.
app.get('/me', (req, res) => {
  try {
    const hdr = req.headers.authorization || null;
    const token = (typeof hdr === 'string' && hdr.startsWith('Bearer ')) ? hdr.slice(7) : null;
    // Support a known dev bypass token for local testing
    if (token === 'dev-fake-token') {
      return res.json({ id: 'dev-local', email: 'dev-local@example.com', displayName: 'Dev Local', paid: false });
    }
    // Otherwise return 401 so client knows auth is required
    return res.status(401).json({ error: 'Unauthorized' });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// helpful 404 (so you see method/path if you hit wrong route/port)
app.use((req, res) => res.status(404).json({ error: "No route", method: req.method, path: req.path }));

// Temporary error logging middleware — prints stack traces for uncaught errors
// (Useful during local debugging; remove before committing to production.)
app.use((err, req, res, next) => {
  console.error('UNHANDLED ERROR:', err && err.stack ? err.stack : err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: err && err.message ? err.message : 'Internal Server Error' });
});

// Catch unhandled promise rejections and uncaught exceptions to surface server-side errors
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err && err.stack ? err.stack : err);
});

app.listen(PORT, () => console.log(`🚀 Server listening on http://127.0.0.1:${PORT}`));
