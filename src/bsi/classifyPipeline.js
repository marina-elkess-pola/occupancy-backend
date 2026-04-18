/**
 * Classification pipeline: Rule → AI → Merge.
 *
 * Orchestrates the two-phase classification:
 *   Phase 1: Deterministic rule-based matching (instant, free).
 *   Phase 2: Claude AI for remaining ambiguous rooms.
 *   Merge:   Combine into a single ordered result list.
 *
 * Rooms with AI confidence < 0.6 are flagged as "uncertain".
 */

'use strict';

const { classifyBatch } = require('./ruleClassifier');
const { applyOverrides } = require('./bulkOverrides');

const AI_CONFIDENCE_THRESHOLD = 0.6;

/**
 * Run the full classification pipeline.
 *
 * @param {Object}   opts
 * @param {Array}    opts.rooms        — [{ id, name, level?, area? }]
 * @param {Set}      opts.validCategories — Set of allowed category strings
 * @param {Function} opts.callAI       — async (rooms) => { classifications, model, tokens }
 *                                        Injected so the pipeline is transport-agnostic.
 *                                        Must return { classifications: [{ id, category, confidence }],
 *                                                      model: string, tokens: number }
 * @param {Array}    [opts.overrides]   — [{ pattern: string, category: string }]
 *                                        Bulk user overrides. Applied FIRST (highest priority).
 *
 * @returns {Promise<{
 *   classifications: Array<{ id, category, confidence, source: 'rule'|'ai'|'override', uncertain?: boolean }>,
 *   unresolved:      Array,
 *   model:           string|null,
 *   tokens:          number|null,
 *   stats: { total, overrideMatched, ruleMatched, aiClassified, aiUncertain, unresolved }
 * }>}
 */
async function classifyPipeline({ rooms, validCategories, callAI, overrides }) {

    // ── Phase 0: Bulk overrides (highest priority) ───────────
    const { overridden, remaining: afterOverrides } = applyOverrides(rooms, overrides);

    // ── Phase 1: Rule-based classification ───────────────────
    const ruleResults = classifyBatch(afterOverrides);

    const ruleClassified = [];
    const needsAI = [];

    for (const room of afterOverrides) {
        const hit = ruleResults.get(room.id);
        if (hit) {
            ruleClassified.push({ id: room.id, ...hit });
        } else {
            needsAI.push(room);
        }
    }

    // ── Phase 2: AI classification (only unresolved rooms) ───
    let aiClassified = [];
    let aiUnresolved = [];
    let aiModel = null;
    let aiTokens = null;
    let aiUncertain = 0;

    if (needsAI.length > 0) {
        const aiResult = await callAI(needsAI);

        for (const c of aiResult.classifications) {
            if (!c.id || !validCategories.has(c.category)) {
                aiUnresolved.push(c);
                continue;
            }

            const confidence = Math.max(0, Math.min(1, Number(c.confidence) || 0));
            const uncertain = confidence < AI_CONFIDENCE_THRESHOLD;
            if (uncertain) aiUncertain++;

            aiClassified.push({
                id: c.id,
                category: c.category,
                confidence,
                source: 'ai',
                ...(uncertain && { uncertain: true }),
            });
        }

        aiModel = aiResult.model || null;
        aiTokens = aiResult.tokens || null;
    }

    // ── Merge: preserve original room order ──────────────────
    const resultMap = new Map();
    for (const r of overridden) resultMap.set(r.id, r);
    for (const r of ruleClassified) resultMap.set(r.id, r);
    for (const r of aiClassified) resultMap.set(r.id, r);

    const classifications = [];
    for (const room of rooms) {
        const entry = resultMap.get(room.id);
        if (entry) classifications.push(entry);
        // rooms not in either map end up in unresolved
    }

    return {
        classifications,
        unresolved: aiUnresolved,
        model: aiModel,
        tokens: aiTokens,
        stats: {
            total: rooms.length,
            overrideMatched: overridden.length,
            ruleMatched: ruleClassified.length,
            aiClassified: aiClassified.length,
            aiUncertain,
            unresolved: aiUnresolved.length,
        },
    };
}

module.exports = { classifyPipeline, AI_CONFIDENCE_THRESHOLD };
