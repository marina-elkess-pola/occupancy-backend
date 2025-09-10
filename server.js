require('dns').setDefaultResultOrder('ipv4first');
require('dotenv').config();

const mongoose = require('mongoose');
mongoose.set('strictQuery', true);
mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 })
    .then(() => console.log('MongoDB connected'))
    .catch(err => {
        console.error('Mongo error:', err.message);
        process.exit(1);
    });


// Remove duplicate mongoose.connect (keep only one)
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const NodeCache = require('node-cache');
const calcCache = new NodeCache({ stdTTL: 60 });

const User = require('./User'); // make sure this file exists

const app = express();

/* ---------- Middleware ---------- */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(morgan('tiny'));

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
// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Backend is running!' });
});
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
        const confirmToken = jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });
        const user = new User({ email, password: hashedPassword, displayName, confirmToken });
        await user.save();

        // Send confirmation email
        if (EMAIL_USER && EMAIL_PASS) {
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

        res.status(201).json({ message: 'User registered. Please check your email to confirm your account.' });
    } catch (err) {
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

/* ---------- Listen (Render uses PORT) ---------- */
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on ${PORT}`);
});
