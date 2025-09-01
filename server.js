const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/occupancy', { useNewUrlParser: true, useUnifiedTopology: true });

const User = require('./User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'your_jwt_secret'; // Use env variable in production

// Middleware to verify JWT
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token' });
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch {
        res.status(401).json({ error: 'Invalid token' });
    }
}

// Update profile info (displayName, email)
app.put('/profile', authMiddleware, async (req, res) => {
    const { displayName, email } = req.body;
    try {
        const user = await User.findById(req.userId);
        if (displayName) user.displayName = displayName;
        if (email) user.email = email;
        await user.save();
        res.json({ message: 'Profile updated', user });
    } catch {
        res.status(400).json({ error: 'Profile update failed' });
    }
});

// Change password
app.put('/change-password', authMiddleware, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req.userId);
    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Old password incorrect' });
    user.password = await bcrypt.hash(newPassword, 10);
    await user.save();
    res.json({ message: 'Password changed' });
});

// Upload avatar (base64 string or URL)
app.put('/avatar', authMiddleware, async (req, res) => {
    const { avatar } = req.body;
    try {
        const user = await User.findById(req.userId);
        user.avatar = avatar;
        await user.save();
        res.json({ message: 'Avatar updated', avatar });
    } catch {
        res.status(400).json({ error: 'Avatar update failed' });
    }
});

// Save calculation
app.post('/calculation', authMiddleware, async (req, res) => {
    const { data } = req.body;
    try {
        const user = await User.findById(req.userId);
        user.calculations.push({ data });
        await user.save();
        res.json({ message: 'Calculation saved' });
    } catch {
        res.status(400).json({ error: 'Save failed' });
    }
});

// Get calculation history
app.get('/calculations', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        res.json({ calculations: user.calculations });
    } catch {
        res.status(400).json({ error: 'Fetch failed' });
    }
});

// Delete account
app.delete('/account', authMiddleware, async (req, res) => {
    try {
        await User.findByIdAndDelete(req.userId);
        res.json({ message: 'Account deleted' });
    } catch {
        res.status(400).json({ error: 'Delete failed' });
    }
});

// Register endpoint
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const user = new User({ email, password: hashedPassword });
        await user.save();
        res.status(201).json({ message: 'User registered' });
    } catch (err) {
        res.status(400).json({ error: 'Email already exists' });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid credentials' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

app.listen(5000, () => console.log('Server running on port 5000'));
