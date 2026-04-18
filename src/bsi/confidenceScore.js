/**
 * Analysis Confidence Score for BSI.
 *
 * Produces a single 0–100 trust score that tells the user how
 * reliable the current analysis is. The formula is additive
 * (start at 100, apply penalties) so it's easy to explain.
 *
 * Scoring breakdown (100-point budget):
 *
 *   Base                          100
 *   − AI-classified rooms         up to −25  (more AI = less deterministic)
 *   − Uncertain rooms             up to −30  (low-confidence AI is risky)
 *   − Unresolved rooms            up to −20  (completely unclassified)
 *   − Estimated GFA               −15 flat   (no verified area plans)
 *   − Manual override ratio       up to −10  (many overrides = noisy data)
 *
 * The score is clamped to [0, 100] and mapped to a grade:
 *   ≥ 80  → "High"
 *   ≥ 55  → "Medium"
 *   < 55  → "Low"
 */

'use strict';

// ── Grade thresholds ─────────────────────────────────────────

const GRADES = {
    HIGH: 80,
    MEDIUM: 55,
};

// ── Penalty weights ──────────────────────────────────────────

const PENALTIES = {
    AI_CLASSIFIED_MAX: 25,      // penalty scales with % AI-classified
    UNCERTAIN_MAX: 30,          // penalty scales with % uncertain
    UNRESOLVED_MAX: 20,         // penalty scales with % unresolved
    ESTIMATED_GFA: 15,          // flat penalty for estimated GFA
    OVERRIDES_MAX: 10,          // penalty scales with override ratio
    OVERRIDES_THRESHOLD: 0.30,  // >30% overridden = max penalty
};

// ── Main scoring function ────────────────────────────────────

/**
 * Compute the analysis confidence score.
 *
 * @param {Object} input
 * @param {Object} input.stats           — Pipeline stats from classifyPipeline
 * @param {number} input.stats.total
 * @param {number} input.stats.overrideMatched
 * @param {number} input.stats.ruleMatched
 * @param {number} input.stats.aiClassified
 * @param {number} input.stats.aiUncertain
 * @param {number} input.stats.unresolved
 * @param {boolean} input.gfaVerified    — true if GFA comes from area plans
 *
 * @returns {{
 *   score: number,
 *   grade: 'High'|'Medium'|'Low',
 *   breakdown: { base: number, penalties: Object, total: number },
 *   explanation: string
 * }}
 */
function computeConfidenceScore({ stats, gfaVerified = false }) {
    const total = stats.total || 1; // avoid division by zero

    // Ratios (0–1)
    const aiRatio = stats.aiClassified / total;
    const uncertainRatio = stats.aiUncertain / total;
    const unresolvedRatio = stats.unresolved / total;
    const overrideRatio = stats.overrideMatched / total;

    // ── Calculate individual penalties ───────────────────────

    const penalties = {};

    // AI-classified: linear scale, 0% AI → 0 penalty, 100% AI → full penalty
    penalties.aiClassified = Math.round(aiRatio * PENALTIES.AI_CLASSIFIED_MAX);

    // Uncertain: linear scale, heavier weight because these are unreliable
    penalties.uncertain = Math.round(uncertainRatio * PENALTIES.UNCERTAIN_MAX);

    // Unresolved: linear scale, worst case (rooms with no classification at all)
    penalties.unresolved = Math.round(unresolvedRatio * PENALTIES.UNRESOLVED_MAX);

    // GFA: flat penalty if not from verified area plans
    penalties.estimatedGfa = gfaVerified ? 0 : PENALTIES.ESTIMATED_GFA;

    // Overrides: scaled up to threshold, then capped
    // Some overrides are fine (user fixing patterns), too many = noisy input data
    const overrideScale = Math.min(overrideRatio / PENALTIES.OVERRIDES_THRESHOLD, 1);
    penalties.overrides = Math.round(overrideScale * PENALTIES.OVERRIDES_MAX);

    // ── Compute final score ──────────────────────────────────

    const totalPenalty = Object.values(penalties).reduce((sum, p) => sum + p, 0);
    const score = Math.max(0, Math.min(100, 100 - totalPenalty));

    // ── Grade ────────────────────────────────────────────────

    let grade;
    if (score >= GRADES.HIGH) grade = 'High';
    else if (score >= GRADES.MEDIUM) grade = 'Medium';
    else grade = 'Low';

    // ── Human-readable explanation ───────────────────────────

    const explanation = buildExplanation({ stats, total, score, grade, penalties, gfaVerified });

    return {
        score,
        grade,
        breakdown: { base: 100, penalties, total: totalPenalty },
        explanation,
    };
}

// ── Explanation builder ──────────────────────────────────────

function buildExplanation({ stats, total, score, grade, penalties, gfaVerified }) {
    const parts = [];

    const pctRule = Math.round(((stats.ruleMatched + stats.overrideMatched) / total) * 100);
    const pctAI = Math.round((stats.aiClassified / total) * 100);
    const pctUncertain = Math.round((stats.aiUncertain / total) * 100);

    // Lead with grade
    parts.push(`Confidence is ${grade} (${score}%).`);

    // Positive signal
    if (pctRule >= 70) {
        parts.push(`${pctRule}% of rooms resolved deterministically.`);
    }

    // Negative signals (only mention significant ones)
    const reasons = [];
    if (penalties.aiClassified >= 5) reasons.push(`${pctAI}% AI-classified rooms`);
    if (penalties.uncertain >= 5) reasons.push(`${pctUncertain}% uncertain classifications`);
    if (stats.unresolved > 0) reasons.push(`${stats.unresolved} unresolved room(s)`);
    if (!gfaVerified) reasons.push('unverified GFA (estimated)');
    if (penalties.overrides >= 5) reasons.push(`${stats.overrideMatched} manual overrides`);

    if (reasons.length > 0) {
        parts.push('Factors: ' + reasons.join(', ') + '.');
    }

    return parts.join(' ');
}

module.exports = { computeConfidenceScore, GRADES, PENALTIES };
