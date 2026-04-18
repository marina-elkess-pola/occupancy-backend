const mongoose = require('mongoose');

const PurchaseSchema = new mongoose.Schema({
    purchaseRef: { type: String, required: true, unique: true, index: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    productId: { type: String },
    priceId: { type: String },
    currency: { type: String },
    amount: { type: Number },
    status: { type: String, enum: ['pending', 'complete', 'failed'], default: 'pending' },
    licenseKey: { type: String, default: '' },
    machineId: { type: String, default: '' },
    activatedAt: { type: Date },
    gatewayEventId: { type: String, index: true },
    metadata: { type: Object },
}, { timestamps: true });

module.exports = mongoose.model('Purchase', PurchaseSchema);
