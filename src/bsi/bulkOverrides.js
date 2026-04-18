/**
 * Bulk override system for BSI room classification.
 *
 * Allows users to fix classification patterns in bulk rather than
 * one room at a time. Overrides take HIGHEST priority — they run
 * before rule-based classification and AI.
 *
 * Override structure:
 *   { pattern: "Unit *", category: "residential" }
 *
 * Pattern syntax (wildcard-based, case-insensitive):
 *   "Unit *"      → matches "Unit 101", "Unit 502A", etc.
 *   "Shop *"      → matches "Shop 1", "Shop Ground Floor"
 *   "Corridor*"   → matches "Corridor", "Corridor (L2)"
 *   "*Kitchen*"   → matches "Staff Kitchen", "Kitchen (L1)"
 *   "Plant Room"  → exact match (no wildcard)
 */

'use strict';

// ── Wildcard → RegExp conversion ─────────────────────────────

/**
 * Convert a user-friendly wildcard pattern to a RegExp.
 *
 *   *  → match any characters (including none)
 *   ?  → match exactly one character
 *
 * Everything else is treated as a literal.
 * Matching is case-insensitive and trims whitespace.
 */
function wildcardToRegex(pattern) {
    const trimmed = pattern.trim();
    // Escape regex special chars EXCEPT * and ?
    const escaped = trimmed.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    // Convert wildcards: * → .*, ? → .
    const regexStr = escaped.replace(/\*/g, '.*').replace(/\?/g, '.');
    return new RegExp(`^${regexStr}$`, 'i');
}

// ── Match a single room name against a pattern ───────────────

function matchesPattern(name, pattern) {
    if (!name || !pattern) return false;
    const regex = wildcardToRegex(pattern);
    return regex.test(name.trim());
}

// ── Apply overrides to a room list ───────────────────────────

/**
 * Apply bulk overrides BEFORE the classification pipeline runs.
 *
 * @param {Array<{ id, name, level?, area? }>} rooms
 * @param {Array<{ pattern: string, category: string }>} overrides
 *        Ordered by priority — first matching override wins.
 *
 * @returns {{
 *   overridden: Array<{ id, name, category, confidence: 1.0, source: 'override', pattern }>,
 *   remaining:  Array<{ id, name, level?, area? }>
 * }}
 */
function applyOverrides(rooms, overrides) {
    if (!overrides || overrides.length === 0) {
        return { overridden: [], remaining: [...rooms] };
    }

    // Pre-compile patterns once (avoids recompiling per room)
    const compiled = overrides.map(o => ({
        regex: wildcardToRegex(o.pattern),
        pattern: o.pattern,
        category: o.category,
    }));

    const overridden = [];
    const remaining = [];

    for (const room of rooms) {
        const name = (room.name || '').trim();
        let matched = false;

        for (const rule of compiled) {
            if (rule.regex.test(name)) {
                overridden.push({
                    id: room.id,
                    name: room.name,
                    category: rule.category,
                    confidence: 1.0,
                    source: 'override',
                    pattern: rule.pattern,
                });
                matched = true;
                break; // first matching override wins
            }
        }

        if (!matched) {
            remaining.push(room);
        }
    }

    return { overridden, remaining };
}

// ── Validate an override before storing ──────────────────────

/**
 * Validate an override entry.
 *
 * @param {{ pattern: string, category: string }} override
 * @param {Set<string>} validCategories
 * @returns {{ valid: boolean, error?: string }}
 */
function validateOverride(override, validCategories) {
    if (!override || typeof override !== 'object') {
        return { valid: false, error: 'Override must be an object' };
    }
    if (!override.pattern || typeof override.pattern !== 'string' || !override.pattern.trim()) {
        return { valid: false, error: 'Pattern is required and must be a non-empty string' };
    }
    if (!override.category || typeof override.category !== 'string') {
        return { valid: false, error: 'Category is required and must be a string' };
    }
    if (validCategories && !validCategories.has(override.category)) {
        return { valid: false, error: `Invalid category "${override.category}"` };
    }
    // Verify the pattern compiles without error
    try {
        wildcardToRegex(override.pattern);
    } catch {
        return { valid: false, error: `Invalid pattern "${override.pattern}"` };
    }
    return { valid: true };
}

module.exports = {
    wildcardToRegex,
    matchesPattern,
    applyOverrides,
    validateOverride,
};
