const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    displayName: { type: String },
    avatar: { type: String }, // URL or base64 string
    calculations: [
        {
            date: { type: Date, default: Date.now },
            data: { type: Object }
        }
    ]
});

module.exports = mongoose.model('User', userSchema);
