const mongoose = require('mongoose');

const WebhookEventSchema = new mongoose.Schema({
    gatewayEventId: { type: String, required: true, unique: true, index: true },
    provider: { type: String },
    payload: { type: Object },
    processedAt: { type: Date },
    raw: { type: Object },
}, { timestamps: true });

module.exports = mongoose.model('WebhookEvent', WebhookEventSchema);
