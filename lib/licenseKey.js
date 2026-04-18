/**
 * License key generator for GenFabTools products.
 *
 * Each license key is a JWT signed with LICENSE_SECRET (HMAC-SHA256).
 * The Revit plugin validates the signature offline using the same secret
 * embedded (obfuscated) in the binary.  Tampering with any claim
 * (email, product, dates) invalidates the signature.
 *
 * Claims:
 *   sub  – userId
 *   email – user email
 *   product – product identifier (e.g. "rsi")
 *   ref  – purchaseRef (UUID)
 *   iat  – issued-at (epoch seconds)
 */
const jwt = require('jsonwebtoken');

const LICENSE_SECRET = process.env.LICENSE_SECRET || process.env.JWT_SECRET;

/**
 * Generate a signed license key for a completed purchase.
 * @param {{ userId: string, email: string, productId: string, purchaseRef: string }} opts
 * @returns {string} JWT license key (no expiration — perpetual license)
 */
function generateLicenseKey({ userId, email, productId, purchaseRef }) {
    return jwt.sign(
        {
            sub: String(userId),
            email,
            product: productId || 'rsi',
            ref: purchaseRef,
        },
        LICENSE_SECRET,
        { algorithm: 'HS256' }   // no expiresIn → perpetual
    );
}

/**
 * Verify a license key and return its claims, or null if invalid.
 * @param {string} key
 * @returns {object|null}
 */
function verifyLicenseKey(key) {
    try {
        return jwt.verify(key, LICENSE_SECRET, { algorithms: ['HS256'] });
    } catch {
        return null;
    }
}

module.exports = { generateLicenseKey, verifyLicenseKey };
