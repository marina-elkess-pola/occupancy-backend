require('dns').setDefaultResultOrder('ipv4first');
require('dotenv').config();

/* ---------- Crash guards ---------- */
process.on('uncaughtException', (err) => {
    console.error(`[${new Date().toISOString()}] UNCAUGHT EXCEPTION:`, err);
});
process.on('unhandledRejection', (err) => {
    console.error(`[${new Date().toISOString()}] UNHANDLED REJECTION:`, err);
});

const mongoose = require('mongoose');
// mongoose connection is established after loading environment variables further down

const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const NodeCache = require('node-cache');
const calcCache = new NodeCache({ stdTTL: 60 });
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

const User = require('./User'); // make sure this file exists
const Purchase = require('./models/Purchase');
const WebhookEvent = require('./models/WebhookEvent');
const { generateLicenseKey, verifyLicenseKey } = require('./lib/licenseKey');
// Stripe (optional) — provide keys via env: STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET
let Stripe;
try { Stripe = require('stripe'); } catch (e) { Stripe = null; }

const app = express();

// File uploads for conversion/scaffolding
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const upload = multer({ dest: uploadsDir });

/* ---------- Middleware ---------- */
// Skip JSON body-parsing for the webhook route so express.raw() can provide the raw Buffer
app.use((req, res, next) => {
    if (req.path === '/lemonsqueezy/webhook') return next();
    express.json()(req, res, next);
});
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('tiny'));

// Allow common local dev origins plus any FRONTEND_URL set in env
const allowedOrigins = [
    process.env.FRONTEND_URL || 'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'https://genfabtools.com'
].filter(Boolean);

/* ---------- Request logging ---------- */
app.use((req, res, next) => {
    const start = Date.now();
    console.log(`[BSI] ${req.method} ${req.url} - started`);
    res.on('finish', () => {
        console.log(`[BSI] ${req.method} ${req.url} - ${res.statusCode} (${Date.now() - start}ms)`);
    });
    next();
});

app.use(cors({
    origin: (origin, cb) => {
        // allow requests with no origin (curl, server-to-server)
        if (!origin) return cb(null, true);
        if (allowedOrigins.includes(origin)) return cb(null, true);
        console.warn('CORS blocked for origin:', origin);
        return cb(new Error('CORS blocked'));
    },
    credentials: true
}));

/* ---------- Config ---------- */
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const MONGODB_URI = process.env.MONGODB_URI;
const EMAIL_USER = process.env.EMAIL_USER;
const EMAIL_PASS = process.env.EMAIL_PASS;

if (!MONGODB_URI) {
    console.error('ERROR: MONGODB_URI environment variable is not set.');
    process.exit(1);
}

mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 })
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Mongo error:', err.message);
        console.log('Continuing without MongoDB - parking API will still work');
        // process.exit(1); // Don't exit - parking API doesn't need MongoDB
    });

/* ---------- Auth middleware ---------- */
async function authMiddleware(req, res, next) {
    const hdr = req.headers.authorization || req.cookies?.token;
    const token = typeof hdr === 'string' && hdr.startsWith('Bearer ')
        ? hdr.slice(7)
        : (typeof hdr === 'string' ? hdr : null);

    if (!token) return res.status(401).json({ error: 'No token' });

    // Dev-only bypass: accept a known dev token to speed up local testing.
    // Historically this required NODE_ENV=development or DEV_BYPASS=true.
    // Allow the special dev token when presented but log a warning if not in development.
    if (token === 'dev-fake-token') {
        if (process.env.NODE_ENV !== 'development' && process.env.DEV_BYPASS !== 'true') {
            console.warn('Dev token used while NODE_ENV is not development. This is intended for local testing only.');
        }
        try {
            // Find or create a persistent dev user so purchases and profile persist locally.
            let devUser = await User.findOne({ email: 'dev-local@example.com' });
            if (!devUser) {
                const hashed = await bcrypt.hash('dev-password', 10);
                devUser = await User.create({ email: 'dev-local@example.com', password: hashed, displayName: 'Dev Local', confirmed: true, paid: false });
            }
            req.userId = devUser._id;
            return next();
        } catch (err) {
            // MongoDB may be down — still allow dev token through with a placeholder userId
            console.error('Dev bypass DB error (continuing without user):', err.message);
            req.userId = 'dev-local-no-db';
            return next();
        }
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

/* ---------- BSI (Building Scheme Intelligence) routes ---------- */
const bsiRoutes = require('./src/bsi/bsiRoutes');
app.use('/api/bsi', authMiddleware, bsiRoutes);

/* ---------- Health & misc ---------- */
app.get('/health', (_req, res) => res.status(200).send('ok'));
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Backend is running!' });
});
app.get('/version', (_req, res) => {
    const pkg = require('./package.json');
    res.json({ name: pkg.name, version: pkg.version });
});

/* ---------- Profile endpoint ---------- */
app.get('/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json({
            id: user._id,
            email: user.email,
            displayName: user.displayName,
            avatar: user.avatar || '',
            paid: !!user.paid,
            createdAt: user.createdAt,
        });
    } catch (err) {
        res.status(400).json({ error: 'Failed to fetch profile' });
    }
});

/* ---------- User purchases ---------- */
app.get('/api/purchases', authMiddleware, async (req, res) => {
    try {
        const purchases = await Purchase.find({ userId: req.userId })
            .sort({ createdAt: -1 })
            .lean();
        res.json(purchases.map(p => ({
            id: p._id,
            product: p.productId || 'RSI',
            date: p.createdAt,
            amount: p.amount ? `$${(p.amount / 100).toFixed(2)}` : '—',
            status: p.status,
            licenseKey: p.status === 'complete' ? (p.licenseKey || null) : null,
            machineId: p.machineId || null,
            activatedAt: p.activatedAt || null,
            receiptUrl: null,
        })));
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch purchases' });
    }
});

/* ---------- License activation (Revit plugin calls this once) ---------- */
app.post('/api/license/activate', async (req, res) => {
    const { licenseKey, machineId } = req.body || {};
    if (!licenseKey || !machineId) {
        return res.status(400).json({ error: 'licenseKey and machineId are required' });
    }

    // Verify the JWT signature first
    const claims = verifyLicenseKey(licenseKey);
    if (!claims) {
        return res.status(403).json({ error: 'Invalid license key' });
    }

    try {
        const purchase = await Purchase.findOne({ licenseKey, status: 'complete' });
        if (!purchase) {
            return res.status(404).json({ error: 'No matching purchase found' });
        }

        // Already activated on the SAME machine → success
        if (purchase.machineId && purchase.machineId === machineId) {
            return res.json({ activated: true, message: 'License already activated on this machine' });
        }

        // Already activated on a DIFFERENT machine → deny
        if (purchase.machineId && purchase.machineId !== machineId) {
            return res.status(403).json({
                error: 'License already activated on another machine',
                hint: 'Each license key can only be used on one computer. Contact support to transfer your license.',
            });
        }

        // Not yet activated → bind to this machine
        purchase.machineId = machineId;
        purchase.activatedAt = new Date();
        await purchase.save();

        return res.json({ activated: true, message: 'License activated successfully' });
    } catch (err) {
        console.error('license activate error', err);
        return res.status(500).json({ error: 'Activation failed' });
    }
});

/* ---------- License verification (Revit plugin calls this on launch) ---------- */
app.post('/api/license/verify', async (req, res) => {
    const { licenseKey, machineId } = req.body || {};
    if (!licenseKey || !machineId) {
        return res.status(400).json({ valid: false, error: 'licenseKey and machineId are required' });
    }

    const claims = verifyLicenseKey(licenseKey);
    if (!claims) {
        return res.status(403).json({ valid: false, error: 'Invalid license key' });
    }

    try {
        const purchase = await Purchase.findOne({ licenseKey, status: 'complete' }).lean();
        if (!purchase) {
            return res.json({ valid: false, error: 'No matching purchase' });
        }

        if (!purchase.machineId) {
            return res.json({ valid: false, error: 'License not yet activated' });
        }

        if (purchase.machineId !== machineId) {
            return res.json({ valid: false, error: 'License is bound to a different machine' });
        }

        return res.json({
            valid: true,
            product: claims.product,
            email: claims.email,
            activatedAt: purchase.activatedAt,
        });
    } catch (err) {
        console.error('license verify error', err);
        return res.status(500).json({ valid: false, error: 'Verification failed' });
    }
});

/* ---------- License deactivation (Revit plugin calls this on deactivate) ---------- */
app.post('/api/license/deactivate', async (req, res) => {
    const { licenseKey, machineId } = req.body || {};
    if (!licenseKey || !machineId) {
        return res.status(400).json({ success: false, error: 'licenseKey and machineId are required' });
    }

    const claims = verifyLicenseKey(licenseKey);
    if (!claims) {
        return res.status(403).json({ success: false, error: 'Invalid license key' });
    }

    try {
        const purchase = await Purchase.findOne({ licenseKey, status: 'complete' });
        if (!purchase) {
            return res.status(404).json({ success: false, error: 'License not found' });
        }

        if (purchase.machineId !== machineId) {
            return res.status(403).json({ success: false, error: 'Machine ID does not match' });
        }

        purchase.machineId = null;
        purchase.activatedAt = null;
        await purchase.save();

        return res.json({ success: true, message: 'License deactivated' });
    } catch (err) {
        console.error('license deactivate error', err);
        return res.status(500).json({ success: false, error: 'Deactivation failed' });
    }
});

app.get('/api/access', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);

        if (!user) {
            return res.json({ access: false });
        }

        return res.json({
            access: user.paid === true
        });

    } catch (err) {
        return res.status(500).json({ access: false });
    }
});

// Authenticated download — returns a short-lived signed URL instead of exposing the .exe path
app.get('/api/download/rsi', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user || user.paid !== true) {
            return res.status(403).json({ error: 'No active subscription' });
        }

        // Build a signed URL: HMAC of (product + userId + expiry)
        const secret = process.env.DOWNLOAD_SECRET || process.env.JWT_SECRET;
        const expires = Date.now() + 5 * 60 * 1000; // 5 minutes
        const payload = `rsi:${req.userId}:${expires}`;
        const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');

        const baseUrl = process.env.DOWNLOAD_BASE_URL || 'https://genfabtools.com';
        const url = `${baseUrl}/api/download/file?product=rsi&uid=${req.userId}&exp=${expires}&sig=${signature}`;

        return res.json({ url });
    } catch (err) {
        console.error('download url error', err);
        return res.status(500).json({ error: 'Failed to generate download link' });
    }
});

// Public endpoint that validates the signed URL and serves the file
app.get('/api/download/file', async (req, res) => {
    try {
        const { product, uid, exp, sig } = req.query;
        if (!product || !uid || !exp || !sig) {
            return res.status(400).json({ error: 'Invalid download link' });
        }

        // Check expiry
        if (Date.now() > Number(exp)) {
            return res.status(410).json({ error: 'Download link expired' });
        }

        // Verify signature
        const secret = process.env.DOWNLOAD_SECRET || process.env.JWT_SECRET;
        const expected = crypto.createHmac('sha256', secret).update(`${product}:${uid}:${exp}`).digest('hex');
        if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
            return res.status(403).json({ error: 'Invalid signature' });
        }

        // Map product ID to file — add more products here as needed
        const files = {
            rsi: path.join(__dirname, 'downloads', 'RSI_Setup.exe'),
        };

        const filePath = files[product];
        if (!filePath || !fs.existsSync(filePath)) {
            return res.status(404).json({ error: 'File not found' });
        }

        res.download(filePath);
    } catch (err) {
        console.error('download file error', err);
        return res.status(500).json({ error: 'Download failed' });
    }
});



/* ---------- Profile routes ---------- */
app.put('/profile', authMiddleware, async (req, res) => {
    const { displayName, email } = req.body;
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        if (displayName !== undefined) user.displayName = displayName;
        if (email !== undefined) user.email = email;
        await user.save();
        res.json({ message: 'Profile updated', user });
    } catch {
        res.status(400).json({ error: 'Profile update failed' });
    }
});

app.put('/change-password', authMiddleware, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Old password incorrect' });

    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password changed' });
});

app.put('/avatar', authMiddleware, async (req, res) => {
    const { avatar } = req.body; // base64 or URL
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.avatar = avatar;
        await user.save();
        res.json({ message: 'Avatar updated', avatar });
    } catch {
        res.status(400).json({ error: 'Avatar update failed' });
    }
});

/* ---------- Calculation routes ---------- */
app.post('/calculation', authMiddleware, async (req, res) => {
    const { data } = req.body;
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.calculations.push({ data, createdAt: new Date() });
        await user.save();
        res.json({ message: 'Calculation saved' });
    } catch {
        res.status(400).json({ error: 'Save failed' });
    }
});

// Calculation history with pagination
// Calculation history with pagination and caching
app.get('/calculations', authMiddleware, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        const cacheKey = `${req.userId}-page${page}-limit${limit}`;
        const cached = calcCache.get(cacheKey);
        if (cached) return res.json(cached);

        const user = await User.findById(req.userId).lean();
        if (!user) return res.status(404).json({ error: 'User not found' });
        const calculations = user.calculations || [];
        calculations.sort((a, b) => new Date(b.date) - new Date(a.date));
        const start = (page - 1) * limit;
        const paginated = calculations.slice(start, start + Number(limit));
        const response = {
            calculations: paginated,
            total: calculations.length,
            page: Number(page),
            pages: Math.ceil(calculations.length / limit)
        };
        calcCache.set(cacheKey, response);
        res.json(response);
    } catch {
        res.status(400).json({ error: 'Fetch failed' });
    }
});

app.delete('/account', authMiddleware, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.userId);
        res.json({ message: 'Account deleted' });
    } catch {
        res.status(400).json({ error: 'Delete failed' });
    }
});

/* ---------- Auth routes ---------- */
app.post('/register', async (req, res) => {
    const { email, password, displayName = '' } = req.body;
    try {
        const exists = await User.findOne({ email });
        if (exists) return res.status(400).json({ error: 'Email already exists' });

        const hashedPassword = await bcrypt.hash(password, 10);
        const confirmToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });
        // If email sending is not configured in env, auto-confirm accounts for local/dev convenience
        const emailConfigured = !!(EMAIL_USER && EMAIL_PASS);
        const user = new User({
            email,
            password: hashedPassword,
            displayName,
            confirmToken: emailConfigured ? confirmToken : '',
            confirmed: emailConfigured ? false : true
        });
        await user.save();

        // Send confirmation email
        if (emailConfigured) {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: { user: EMAIL_USER, pass: EMAIL_PASS }
            });
            const confirmUrl = `http://localhost:5000/confirm/${confirmToken}`;
            await transporter.sendMail({
                from: EMAIL_USER,
                to: email,
                subject: 'Confirm your account',
                html: `<h2>Welcome!</h2><p>Please confirm your account by clicking <a href="${confirmUrl}">here</a>.</p>`
            });
        }
        // If email was sent, ask user to confirm; otherwise, allow immediate login in dev
        if (emailConfigured) {
            res.status(201).json({ message: 'User registered. Please check your email to confirm your account.' });
        } else {
            res.status(201).json({ message: 'User registered and auto-confirmed (dev mode).' });
        }
    } catch (err) {
        console.error('register error', err && err.stack ? err.stack : err);
        res.status(400).json({ error: 'Registration failed' });
    }
});

app.get('/confirm/:token', async (req, res) => {
    const { token } = req.params;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = await User.findOne({ email: decoded.email, confirmToken: token });
        if (!user) return res.status(400).send('Invalid or expired token');
        user.confirmed = true;
        user.confirmToken = '';
        await user.save();
        res.send('Account confirmed! You can now log in.');
    } catch {
        res.status(400).send('Invalid or expired token');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });
    if (!user.confirmed) return res.status(400).json({ error: 'Please confirm your email before logging in.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

/* ---------- Stripe Checkout endpoint (requires STRIPE_SECRET_KEY and STRIPE_PRICE_ID) ---------- */
app.post('/create-checkout-session', authMiddleware, async (req, res) => {
    const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
    const STRIPE_PRICE_ID = process.env.STRIPE_PRICE_ID; // use a Price ID created in Stripe
    if (!STRIPE_SECRET_KEY || !STRIPE_PRICE_ID) return res.status(500).json({ error: 'Stripe not configured' });
    if (!Stripe) return res.status(500).json({ error: 'Stripe library not installed' });

    try {
        const stripe = Stripe(STRIPE_SECRET_KEY);
        const user = await User.findById(req.userId);
        if (!user) return res.status(404).json({ error: 'User not found' });

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            mode: 'payment',
            line_items: [{ price: STRIPE_PRICE_ID, quantity: 1 }],
            client_reference_id: String(user._id),
            metadata: { userId: String(user._id) },
            success_url: (process.env.SUCCESS_URL || 'http://localhost:3000') + '?checkout=success',
            cancel_url: (process.env.CANCEL_URL || 'http://localhost:3000') + '?checkout=cancel'
        });

        res.json({ url: session.url });
    } catch (err) {
        console.error('Stripe session error:', err);
        res.status(500).json({ error: 'Failed to create checkout session' });
    }
});

/* ---------- LemonSqueezy hosted purchase endpoints ---------- */
// Create a purchase record and return the hosted checkout URL
app.post('/purchase/create', authMiddleware, async (req, res) => {
    try {
        const { productId, priceId, amount = 0, currency = 'USD' } = req.body || {};
        const purchaseRef = uuidv4();
        const purchase = await Purchase.create({
            purchaseRef,
            userId: req.userId,
            productId,
            priceId,
            amount,
            currency,
            status: 'pending'
        });

        const checkoutBase = process.env.LEMONSQUEEZY_CHECKOUT_URL;
        const returnUrl = `${process.env.PAYMENT_SUCCESS_URL}?purchaseRef=${encodeURIComponent(purchaseRef)}`;
        const checkoutUrl = checkoutBase ? `${checkoutBase}?return_url=${encodeURIComponent(returnUrl)}` : null;

        return res.json({ purchaseRef, checkoutUrl });
    } catch (err) {
        console.error('create purchase error', err);
        return res.status(500).json({ error: 'failed to create purchase' });
    }
});

// Verify purchase status
app.get('/purchase/verify', authMiddleware, async (req, res) => {
    const { purchaseRef } = req.query;
    if (!purchaseRef) return res.status(400).json({ error: 'missing purchaseRef' });
    try {
        const purchase = await Purchase.findOne({ purchaseRef, userId: req.userId }).lean();
        if (!purchase) {
            // If the request comes from an Inertia client, instruct a full-location redirect
            if (req.headers['x-inertia']) {
                const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/purchase/verify?purchaseRef=${encodeURIComponent(purchaseRef)}`;
                res.set('X-Inertia-Location', redirectUrl).status(409).end();
                return;
            }
            return res.status(404).json({ error: 'purchase not found' });
        }

        // If request came via Inertia, respond with an Inertia full-location redirect so the client performs a proper navigation
        if (req.headers['x-inertia']) {
            const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/purchase/verify?purchaseRef=${encodeURIComponent(purchaseRef)}`;
            res.set('X-Inertia-Location', redirectUrl).status(409).end();
            return;
        }

        res.json({ purchaseRef: purchase.purchaseRef, status: purchase.status });
    } catch (err) {
        console.error('purchase verify error', err);
        res.status(500).json({ error: 'internal error' });
    }
});

// Admin support: mark a purchase paid (manual recovery)
app.post('/admin/purchase/:purchaseRef/mark-paid', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) return res.status(401).json({ error: 'unauthenticated' });
        if (!user.isAdmin && !user.role?.includes('admin')) return res.status(403).json({ error: 'forbidden' });
        const { purchaseRef } = req.params;
        const purchase = await Purchase.findOne({ purchaseRef });
        if (!purchase) return res.status(404).json({ error: 'purchase not found' });
        purchase.status = 'complete';
        await purchase.save();
        const u = await User.findById(purchase.userId);
        if (u) { u.paid = true; await u.save(); }
        res.json({ ok: true });
    } catch (err) {
        console.error('admin mark paid error', err);
        res.status(500).json({ error: 'failed' });
    }
});

// Dev-only helper: mark a purchase paid without needing admin rights or a gateway webhook.
// Only enabled when NODE_ENV=development or DEV_BYPASS=true to avoid accidental use in production.
app.post('/dev/purchase/mark-paid', async (req, res) => {
    if (!(process.env.NODE_ENV === 'development' || process.env.DEV_BYPASS === 'true')) {
        return res.status(403).json({ error: 'dev endpoint disabled' });
    }

    const { purchaseRef } = req.body || {};
    if (!purchaseRef) return res.status(400).json({ error: 'missing purchaseRef' });

    try {
        const purchase = await Purchase.findOne({ purchaseRef });
        if (!purchase) return res.status(404).json({ error: 'purchase not found' });
        if (purchase.status === 'complete') return res.json({ ok: true, message: 'already complete' });

        purchase.status = 'complete';
        await purchase.save();

        const u = await User.findById(purchase.userId);
        if (u) { u.paid = true; await u.save(); }

        return res.json({ ok: true });
    } catch (err) {
        console.error('dev mark paid error', err);
        return res.status(500).json({ error: 'failed' });
    }
});

// Dev-only helper: mark the current authenticated user as paid (no purchaseRef needed).
// Useful for frontend testing when using the dev bypass token (dev-fake-token).
app.post('/dev/user/mark-paid', authMiddleware, async (req, res) => {
    if (!(process.env.NODE_ENV === 'development' || process.env.DEV_BYPASS === 'true')) {
        return res.status(403).json({ error: 'dev endpoint disabled' });
    }

    try {
        const u = await User.findById(req.userId);
        if (!u) return res.status(404).json({ error: 'user not found' });
        u.paid = true;
        await u.save();

        // Also mark any pending purchases for this user as complete + generate license keys
        const pending = await Purchase.find({ userId: u._id, status: { $ne: 'complete' } });
        for (const p of pending) {
            p.status = 'complete';
            if (!p.licenseKey) {
                p.licenseKey = generateLicenseKey({
                    userId: u._id,
                    email: u.email,
                    productId: p.productId,
                    purchaseRef: p.purchaseRef,
                });
            }
            await p.save();
        }

        // If no purchases exist at all, create one with a license key
        const anyPurchase = await Purchase.findOne({ userId: u._id });
        if (!anyPurchase) {
            const ref = uuidv4();
            await Purchase.create({
                purchaseRef: ref,
                userId: u._id,
                productId: 'rsi',
                status: 'complete',
                licenseKey: generateLicenseKey({
                    userId: u._id,
                    email: u.email,
                    productId: 'rsi',
                    purchaseRef: ref,
                }),
            });
        }

        return res.json({ ok: true });
    } catch (err) {
        console.error('dev mark user paid error', err);
        return res.status(500).json({ error: 'failed' });
    }
});

/* ---------- LemonSqueezy webhook (separate from Stripe webhook) ---------- */
app.post('/lemonsqueezy/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
    if (!secret) {
        console.warn('LEMONSQUEEZY_WEBHOOK_SECRET not configured; ignoring');
        return res.status(200).send('ok');
    }

    const raw = req.body; // Buffer
    const sigHeader = req.headers['x-signature'] || req.headers['x-lemonsqueezy-signature'] || req.headers['x-lemon-signature'];
    if (!sigHeader) {
        console.warn('No signature header in LemonSqueezy webhook', Object.keys(req.headers));
        return res.status(400).send('missing signature');
    }

    const expected = crypto.createHmac('sha256', secret).update(raw).digest('hex');
    try {
        if (!crypto.timingSafeEqual(Buffer.from(sigHeader), Buffer.from(expected))) {
            console.warn('Invalid LemonSqueezy signature', sigHeader, expected);
            return res.status(400).send('invalid signature');
        }
    } catch (e) {
        return res.status(400).send('signature verification failed');
    }

    let payload;
    try { payload = JSON.parse(raw.toString('utf8')); } catch (e) { return res.status(400).send('invalid json'); }

    const gatewayEventId = payload?.id || payload?.data?.id || `${Date.now()}_${Math.random()}`;
    // Idempotency: skip if gatewayEventId already processed
    const existing = await WebhookEvent.findOne({ gatewayEventId });
    if (existing) return res.status(200).send('already processed');

    // store raw event for audit
    await WebhookEvent.create({ gatewayEventId, provider: 'lemonsqueezy', payload, raw });

    // attempt to find purchaseRef in payload metadata
    const purchaseRef = payload?.data?.attributes?.metadata?.purchaseRef || payload?.data?.attributes?.return_url_params?.purchaseRef || payload?.data?.attributes?.purchaseRef;
    try {
        if (purchaseRef) {
            const purchase = await Purchase.findOne({ purchaseRef });
            if (purchase && purchase.status !== 'complete') {
                purchase.status = 'complete';
                purchase.gatewayEventId = gatewayEventId;
                const u = await User.findById(purchase.userId);
                if (u) {
                    u.paid = true;
                    await u.save();
                    // Generate a signed license key for the purchase
                    if (!purchase.licenseKey) {
                        purchase.licenseKey = generateLicenseKey({
                            userId: u._id,
                            email: u.email,
                            productId: purchase.productId,
                            purchaseRef: purchase.purchaseRef,
                        });
                    }
                }
                await purchase.save();
            }
        } else {
            // fallback: try to match by customer email
            const email = payload?.data?.attributes?.customer_email || payload?.data?.attributes?.customer?.email;
            if (email) {
                const u = await User.findOne({ email });
                if (u) {
                    u.paid = true;
                    await u.save();
                    // Create a purchase record with license key for email-matched payments
                    const fallbackRef = uuidv4();
                    await Purchase.create({
                        purchaseRef: fallbackRef,
                        userId: u._id,
                        productId: 'rsi',
                        status: 'complete',
                        gatewayEventId,
                        licenseKey: generateLicenseKey({
                            userId: u._id,
                            email: u.email,
                            productId: 'rsi',
                            purchaseRef: fallbackRef,
                        }),
                    });
                }
            }
        }
    } catch (err) {
        console.error('Error processing LemonSqueezy webhook:', err);
    }

    res.status(200).send('ok');
});

/* ---------- Stripe webhook to mark user paid ---------- */
app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
    const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET;
    if (!STRIPE_SECRET_KEY || !STRIPE_WEBHOOK_SECRET) return res.status(200).send('ok');
    if (!Stripe) return res.status(200).send('ok');

    const stripe = Stripe(STRIPE_SECRET_KEY);
    const sig = req.headers['stripe-signature'];
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error('Webhook signature verification failed.', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle the checkout.session.completed event
    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;
        const userId = session.metadata?.userId || session.client_reference_id;
        if (userId) {
            try {
                await User.findByIdAndUpdate(userId, { paid: true });
                console.log(`Marked user ${userId} as paid via webhook.`);
            } catch (err) {
                console.error('Failed to mark user paid:', err);
            }
        }
    }

    res.json({ received: true });
});

/* ---------- Conversion / upload endpoint (scaffold) ---------- */
// Accept uploaded files to be converted server-side by offline tooling or external services.
// This endpoint stores the file and returns a job token. Actual conversion is out-of-scope for
// an in-repo implementation; use the instructions in backend/CONVERSION.md to wire a converter.
app.post('/api/convert', upload.single('file'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'missing file' });
        const saved = { originalName: req.file.originalname, path: req.file.path, size: req.file.size };
        // In a production pipeline you'd enqueue this file for conversion and return a job id.
        // For now return accepted with a quick advisory message.
        return res.status(202).json({ message: 'File accepted for conversion (scaffold)', file: saved, note: 'See backend/CONVERSION.md for conversion options and next steps.' });
    } catch (err) {
        console.error('convert upload error', err);
        return res.status(500).json({ error: 'upload failed' });
    }
});

/* ---------- Parking Generator Proxy to Python backend ---------- */
const PYTHON_BACKEND_URL = process.env.PYTHON_BACKEND_URL || 'http://127.0.0.1:8000';

app.post('/api/parking/generate', async (req, res) => {
    try {
        const response = await fetch(`${PYTHON_BACKEND_URL}/parking/generate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        console.error('Parking generate proxy error:', err);
        res.status(500).json({ error: 'Failed to connect to parking generator backend' });
    }
});

app.post('/api/parking/circulation', async (req, res) => {
    try {
        const response = await fetch(`${PYTHON_BACKEND_URL}/parking/circulation`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(req.body)
        });
        const data = await response.json();
        res.status(response.status).json(data);
    } catch (err) {
        console.error('Parking circulation proxy error:', err);
        res.status(500).json({ error: 'Failed to connect to parking generator backend' });
    }
});

/* ---------- Listen (Render uses PORT) ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on ${PORT}`);
});
