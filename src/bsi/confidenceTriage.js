/**
 * Confidence triage for BSI classification results.
 *
 * Splits classified rooms into two buckets:
 *   - highConfidence  → auto-resolved, no user review needed
 *   - reviewRequired  → shown to user, grouped by name pattern
 *
 * Designed for large projects (1000+ rooms). All operations are
 * O(n) or O(n log n) — no nested loops over the full set.
 */

'use strict';

// ── Thresholds ───────────────────────────────────────────────

const THRESHOLDS = {
    AI_HIGH: 0.8,      // AI ≥ 0.8 → auto-resolved
    AI_REVIEW: 0.6,    // AI 0.6–0.8 → review (normal priority)
    // AI < 0.6 → review (high priority)
};

// ── Name pattern extraction ──────────────────────────────────

/**
 * Extract a grouping pattern from a room name.
 *
 * "Unit 501"       → "Unit {n}"
 * "Apartment 3B"   → "Apartment {n}"
 * "Stair (L1 - Block 35)" → "Stair (L{n} - Block {n})"
 * "Café Kitchen (L1 - Block 35)" → "Café Kitchen (L{n} - Block {n})"
 *
 * Numbers, optional trailing letters (3B, 12A) and level tags
 * are collapsed to {n} so rooms with the same naming convention
 * land in the same review group.
 */
function extractPattern(name) {
    if (!name) return '(unnamed)';
    return name
        .replace(/\d+[A-Za-z]?/g, '{n}')   // "501" or "3B" → {n}
        .replace(/\{n\}(\s*[-–]\s*\{n\})/g, '{n}') // "{n} - {n}" → "{n}" (ranges)
        .replace(/\s+/g, ' ')
        .trim();
}

// ── Triage function ──────────────────────────────────────────

/**
 * Separate classified rooms into auto-resolved and needs-review.
 *
 * @param {Array<{ id, name, category, confidence, source, uncertain? }>} classifications
 * @returns {{
 *   highConfidence: Array<{ id, name, category, confidence, source }>,
 *   reviewRequired: Array<{
 *     pattern: string,
 *     priority: 'high'|'normal',
 *     suggestedCategory: string,
 *     avgConfidence: number,
 *     rooms: Array<{ id, name, category, confidence, source }>
 *   }>,
 *   stats: {
 *     total: number,
 *     autoResolved: number,
 *     needsReviewCount: number,
 *     percentageAutoResolved: number
 *   }
 * }}
 */
function triageClassifications(classifications) {
    const highConfidence = [];
    const reviewRooms = [];     // flat list before grouping

    // ── Phase 1: Split (single pass, O(n)) ───────────────────

    for (const room of classifications) {
        if (room.source === 'rule') {
            // All rule-based → auto-resolved (deterministic, 0.90+)
            highConfidence.push(room);
            continue;
        }

        // AI-classified: apply confidence thresholds
        if (room.confidence >= THRESHOLDS.AI_HIGH) {
            highConfidence.push(room);
        } else {
            const priority = room.confidence < THRESHOLDS.AI_REVIEW ? 'high' : 'normal';
            reviewRooms.push({ ...room, _priority: priority });
        }
    }

    // ── Phase 2: Group review rooms by name pattern (O(n)) ───

    const groups = new Map();   // pattern → { rooms[], priorities[], categories[] }

    for (const room of reviewRooms) {
        const pattern = extractPattern(room.name);
        let group = groups.get(pattern);
        if (!group) {
            group = { rooms: [], priorities: [], categories: new Map() };
            groups.set(pattern, group);
        }
        group.rooms.push({
            id: room.id,
            name: room.name,
            category: room.category,
            confidence: room.confidence,
            source: room.source,
        });
        group.priorities.push(room._priority);

        // Track category votes for suggested category
        const catCount = group.categories.get(room.category) || 0;
        group.categories.set(room.category, catCount + 1);
    }

    // ── Phase 3: Build grouped review list ───────────────────

    const reviewRequired = [];

    for (const [pattern, group] of groups) {
        // Priority: high if ANY room in group is high priority
        const priority = group.priorities.includes('high') ? 'high' : 'normal';

        // Suggested category: most common AI suggestion in this group
        let suggestedCategory = null;
        let maxVotes = 0;
        for (const [cat, count] of group.categories) {
            if (count > maxVotes) {
                maxVotes = count;
                suggestedCategory = cat;
            }
        }

        // Average confidence across group
        const avgConfidence = group.rooms.reduce((s, r) => s + r.confidence, 0) / group.rooms.length;

        reviewRequired.push({
            pattern,
            priority,
            suggestedCategory,
            avgConfidence: Math.round(avgConfidence * 1000) / 1000,
            count: group.rooms.length,
            rooms: group.rooms,
        });
    }

    // Sort: high priority first, then by count descending (bulk-fix first)
    reviewRequired.sort((a, b) => {
        if (a.priority !== b.priority) return a.priority === 'high' ? -1 : 1;
        return b.count - a.count;
    });

    // ── Stats ────────────────────────────────────────────────

    const total = classifications.length;
    const autoResolved = highConfidence.length;
    const needsReviewCount = reviewRooms.length;

    return {
        highConfidence,
        reviewRequired,
        stats: {
            total,
            autoResolved,
            needsReviewCount,
            percentageAutoResolved: total > 0
                ? Math.round((autoResolved / total) * 1000) / 10
                : 0,
        },
    };
}

module.exports = { triageClassifications, extractPattern, THRESHOLDS };
