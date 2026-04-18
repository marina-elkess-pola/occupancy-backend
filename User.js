// User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    displayName: { type: String, default: '' },
    avatar: { type: String, default: '' }, // URL or base64
    paid: { type: Boolean, default: false }, // whether the user has purchased access
    calculations: [{
        date: { type: Date, default: Date.now },
        data: { type: mongoose.Schema.Types.Mixed }
    }],
    confirmed: { type: Boolean, default: false },
    confirmToken: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
