// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');        // optional but handy
const cookieParser = require('cookie-parser'); // optional
const NodeCache = require('node-cache');
const calcCache = new NodeCache({ stdTTL: 60 }); // cache for 60 seconds

const User = require('./User'); // make sure this file exists (see sample below)

const app = express();

/* ---------- Middleware ---------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('tiny'));

// Allow your local dev + production site
const allowedOrigins = [
    'http://localhost:3000',
    'https://genfabtools.com'
];
app.use(cors({
    origin: (origin, cb) => {
        if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error('CORS blocked'));
    },
    credentials: true
}));

/* ---------- Config ---------- */
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('ERROR: MONGODB_URI environment variable is not set.');
    process.exit(1);
}

mongoose.set('strictQuery', true);
mongoose.connect(MONGODB_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Mongo error:', err.message);
        process.exit(1);
    });

/* ---------- Auth middleware ---------- */
function authMiddleware(req, res, next) {
    const hdr = req.headers.authorization || req.cookies?.token;
    const token = typeof hdr === 'string' && hdr.startsWith('Bearer ')
        ? hdr.slice(7)
        : (typeof hdr === 'string' ? hdr : null);

    if (!token) return res.status(401).json({ error: 'No token' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

/* ---------- Health & misc ---------- */
app.get('/health', (_req, res) => res.status(200).send('ok'));
app.get('/version', (_req, res) => {
    const pkg = require('./package.json');
    res.json({ name: pkg.name, version: pkg.version });
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
        const user = new User({ email, password: hashedPassword, displayName });
        await user.save();
        res.status(201).json({ message: 'User registered' });
    } catch (err) {
        res.status(400).json({ error: 'Registration failed' });
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

/* ---------- Listen (Render uses PORT) ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on ${PORT}`);
});
