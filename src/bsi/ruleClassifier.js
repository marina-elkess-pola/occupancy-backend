/**
 * Rule-based room classifier for BSI.
 *
 * Runs BEFORE the AI layer. Rooms that match a deterministic rule
 * skip the Claude API call entirely, saving cost and eliminating
 * classification variance.
 *
 * Design principles:
 *   - Rules are evaluated in priority order (most specific first).
 *   - Each rule can define positive keywords AND negative keywords
 *     (blockers) to avoid false positives.
 *   - Matching is case-insensitive, performed on a normalised
 *     version of the room name (trimmed, lowercased, collapsed
 *     whitespace).
 *   - If no rule matches, returns null so the AI layer handles it.
 */

'use strict';

// ── Rule definitions ────────────────────────────────────────────
//
// Each rule: { category, keywords[], blockers[], confidence }
//
//   keywords  — at least one must appear in the normalised name.
//   blockers  — if ANY appears, the rule is skipped (prevents
//               false positives like "Lobby Shop" → core).
//   confidence — returned when this rule matches (0.90–0.99).
//
// Rules are ordered most-specific-first. The FIRST match wins.
// ---

const RULES = [

    // ── PARKING (very distinctive names) ─────────────────────
    {
        category: 'parking',
        keywords: [
            'parking', 'car park', 'carpark', 'garage', 'car space',
            'bicycle storage', 'bike store', 'bike room', 'bike parking',
            'vehicle ramp',
        ],
        blockers: [],
        confidence: 0.97,
    },

    // ── CORE — vertical infrastructure ───────────────────────
    // Must come before circulation because "lift lobby" is core,
    // but "lobby" alone could be circulation.
    {
        category: 'core',
        keywords: [
            'stair', 'staircase', 'stairwell', 'escape stair', 'fire stair',
            'lift', 'elevator', 'lift shaft', 'elevator shaft',
            'riser', 'shaft', 'service shaft', 'duct',
            'vestibule', 'fire vestibule',
            'lift lobby', 'elevator lobby',
        ],
        blockers: ['shop', 'store', 'retail', 'restaurant', 'café', 'cafe',
            'residential', 'apartment', 'unit', 'office'],
        confidence: 0.95,
    },

    // ── CIRCULATION — horizontal movement ────────────────────
    {
        category: 'circulation',
        keywords: [
            'corridor', 'hallway', 'passage', 'passageway',
            'gallery', 'walkway', 'breezeway', 'arcade',
            'lobby', 'foyer', 'entrance hall', 'atrium',
            'common area', 'shared access',
        ],
        blockers: ['shop', 'store', 'retail', 'restaurant', 'café', 'cafe',
            'lift lobby', 'elevator lobby',
            'residential lobby'],
        confidence: 0.93,
    },

    // ── BOH — back-of-house / services ───────────────────────
    {
        category: 'boh',
        keywords: [
            'plant', 'plant room', 'mechanical', 'electrical',
            'mep', 'ahu', 'hvac', 'chiller', 'boiler',
            'substation', 'switchroom', 'switch room',
            'generator', 'genset', 'transformer',
            'water tank', 'pump room', 'sprinkler',
            'bms', 'server room', 'comms room', 'data room',
            'storage', 'store room', 'storeroom', 'janitor',
            'cleaner', 'cleaners', 'refuse', 'waste', 'bin store',
            'garbage', 'trash', 'rubbish',
            'utility', 'services', 'meter room',
            'laundry', 'linen',
            'security room', 'cctv', 'guard room',
            'loading', 'loading bay', 'loading dock',
            'back of house', 'boh',
        ],
        blockers: ['shop', 'retail store', 'car park', 'parking',
            'retail', 'restaurant'],
        confidence: 0.93,
    },

    // ── AMENITY — shared facilities ──────────────────────────
    {
        category: 'amenity',
        keywords: [
            'gym', 'gymnasium', 'fitness', 'health club',
            'pool', 'swimming', 'lap pool',
            'spa', 'sauna', 'steam room', 'jacuzzi',
            'club', 'clubhouse', 'lounge', 'residents lounge',
            'rooftop terrace', 'sky lounge', 'sky deck',
            'playground', 'play area', 'kids room', 'children',
            'garden', 'communal garden', 'courtyard',
            'bbq', 'barbecue', 'outdoor dining',
            'cinema', 'theater', 'theatre', 'screening room',
            'library', 'reading room', 'study room',
            'multipurpose', 'multi-purpose', 'community room',
            'prayer room', 'mosque', 'chapel', 'meditation',
            'co-working', 'coworking', 'business center', 'business centre',
            'concierge', 'reception', 'mail room', 'mailroom',
            'pocket park', 'park',
        ],
        blockers: ['plant room', 'parking', 'car park'],
        confidence: 0.92,
    },

    // ── RETAIL — commercial / F&B ────────────────────────────
    {
        category: 'retail',
        keywords: [
            'shop', 'store', 'retail', 'showroom',
            'restaurant', 'café', 'cafe', 'coffee',
            'f&b', 'food court', 'food hall',
            'supermarket', 'grocery', 'pharmacy', 'chemist',
            'bakery', 'deli', 'butcher', 'florist',
            'bank', 'atm',
            'salon', 'barber', 'hairdresser', 'beauty',
            'kiosk', 'pop-up', 'market',
            'commercial', 'tenant',
            'kitchen',
            'dining',
            'covered dining',
        ],
        blockers: ['plant room', 'staff kitchen'],
        confidence: 0.92,
    },

    // ── OFFICE — workspace ───────────────────────────────────
    {
        category: 'office',
        keywords: [
            'office', 'workspace', 'workstation',
            'meeting room', 'boardroom', 'conference',
            'open plan', 'open-plan',
            'executive suite', 'corner office',
            'hot desk', 'hotdesk',
        ],
        blockers: ['post office', 'box office', 'ticket office',
            'security office'],
        confidence: 0.93,
    },

    // ── HOSPITALITY — hotel / serviced ───────────────────────
    {
        category: 'hospitality',
        keywords: [
            'hotel', 'hotel room', 'guest room', 'guest suite',
            'suite', 'deluxe', 'superior', 'standard room',
            'serviced apartment', 'apart-hotel', 'aparthotel',
        ],
        blockers: ['en-suite', 'ensuite', 'bathroom'],
        confidence: 0.91,
    },

    // ── RESIDENTIAL — dwelling units ─────────────────────────
    // Last among revenue categories: many room names just say
    // "Unit 501" or "Apartment 3B".
    {
        category: 'residential',
        keywords: [
            'apartment', 'apt', 'unit', 'flat',
            'studio', 'penthouse', 'duplex', 'triplex', 'loft',
            'bedroom', 'bed room', 'master bed',
            'living room', 'living', 'sitting room',
            'kitchen', 'pantry',
            'bathroom', 'en-suite', 'ensuite', 'wc', 'toilet',
            'balcony', 'terrace', 'patio',
            'residential',
            'townhouse', 'town house', 'maisonette',
            'live/work',
        ],
        blockers: ['hotel', 'guest room', 'staff', 'retail',
            'plant room', 'commercial kitchen'],
        confidence: 0.90,
    },
];

// ── Normalise a room name ────────────────────────────────────

function normalise(name) {
    if (!name) return '';
    return name
        .toLowerCase()
        .normalize('NFD').replace(/[\u0300-\u036f]/g, '')  // strip accents: é→e
        .replace(/[^\w\s/&-]/g, ' ')   // strip punctuation except / & -
        .replace(/\s+/g, ' ')           // collapse whitespace
        .trim();
}

// ── Matching helpers ─────────────────────────────────────────

/**
 * Check if `text` contains `phrase` as a whole-word (or whole-phrase)
 * match. Uses word-boundary logic so "lift" won't match "uplift"
 * but will match "lift lobby" and "Lift".
 */
function containsPhrase(text, phrase) {
    // Escape regex special chars in the phrase
    const escaped = phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:^|\\b|\\s)${escaped}(?:\\b|\\s|$)`);
    return re.test(text);
}

// ── Main classifier ──────────────────────────────────────────

/**
 * Classify a single room by rules.
 *
 * @param {{ name: string, level?: string, area?: number }} room
 * @returns {{ category: string, confidence: number, source: 'rule' } | null}
 */
function classifyByRule(room) {
    const text = normalise(room.name);
    if (!text) return null;

    for (const rule of RULES) {
        // Check blockers first — if any blocker phrase is present, skip rule
        const blocked = rule.blockers.some(b => containsPhrase(text, b));
        if (blocked) continue;

        // Check if any keyword matches
        const matched = rule.keywords.some(kw => containsPhrase(text, kw));
        if (matched) {
            return {
                category: rule.category,
                confidence: rule.confidence,
                source: 'rule',
            };
        }
    }

    return null; // no rule matched — defer to AI
}

/**
 * Batch-classify an array of rooms. Returns a Map of id → result.
 * Rooms with no rule match are absent from the map.
 *
 * @param {{ id: string, name: string, level?: string, area?: number }[]} rooms
 * @returns {Map<string, { category: string, confidence: number, source: 'rule' }>}
 */
function classifyBatch(rooms) {
    const results = new Map();
    for (const room of rooms) {
        const result = classifyByRule(room);
        if (result) {
            results.set(room.id, result);
        }
    }
    return results;
}

module.exports = { classifyByRule, classifyBatch, RULES, normalise };
