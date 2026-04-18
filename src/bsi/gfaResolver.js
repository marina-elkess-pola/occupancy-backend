/**
 * GFA source resolver for BSI.
 *
 * Determines the best GFA value for a zone using a strict
 * priority chain:
 *
 *   1. Area Plan  (from Revit area plans)  → high confidence
 *   2. Manual     (user-entered value)     → medium confidence
 *   3. Estimated  (sum of room areas)      → low confidence + warning
 *
 * The resolver NEVER falls back silently — every result carries
 * its source, confidence, and an optional warning so the UI can
 * inform the user.
 */

'use strict';

// ── Source priorities & metadata ─────────────────────────────

const GFA_SOURCES = {
    area_plan: {
        confidence: 'high',
        label: 'Area Plan',
        description: 'Measured from Revit area plans.',
    },
    manual: {
        confidence: 'medium',
        label: 'Manual Entry',
        description: 'User-provided GFA value.',
    },
    estimated: {
        confidence: 'low',
        label: 'Estimated (room sum)',
        description: 'Sum of individual room areas.',
    },
};

// ── Warnings ─────────────────────────────────────────────────

const WARNINGS = {
    estimated: 'GFA is estimated from room areas and may undercount total floor area. '
        + 'Wall thicknesses, shafts, and unmeasured voids are not included. '
        + 'Add area plans or enter GFA manually for more accurate results.',
    manual_no_validation: 'GFA was entered manually and has not been validated against area plans.',
    area_plan_mismatch: 'Area plan GFA differs from room-sum GFA by more than 15%. '
        + 'Check for missing or overlapping rooms.',
    zero_gfa: 'No GFA could be determined for this zone. Check that rooms exist on the assigned levels.',
};

// ── Mismatch threshold ───────────────────────────────────────

const MISMATCH_THRESHOLD = 0.15; // 15%

// ── Main resolver ────────────────────────────────────────────

/**
 * Resolve the best GFA value for a zone.
 *
 * @param {Object}  opts
 * @param {number|null} opts.areaPlanGfa  — GFA from Revit area plans (null if not available)
 * @param {number|null} opts.manualGfa    — user-entered GFA (null if not provided)
 * @param {number}      opts.roomSumGfa   — sum of room areas on this zone's levels
 *
 * @returns {{
 *   value: number,
 *   source: 'area_plan'|'manual'|'estimated',
 *   confidence: 'high'|'medium'|'low',
 *   warning: string|null,
 *   allSources: Array<{ source: string, value: number }>
 * }}
 */
function resolveGfa({ areaPlanGfa = null, manualGfa = null, roomSumGfa = 0 }) {
    const allSources = [];

    if (isValidGfa(areaPlanGfa)) allSources.push({ source: 'area_plan', value: areaPlanGfa });
    if (isValidGfa(manualGfa)) allSources.push({ source: 'manual', value: manualGfa });
    if (roomSumGfa > 0) allSources.push({ source: 'estimated', value: roomSumGfa });

    // ── Priority 1: Area plan ────────────────────────────────
    if (isValidGfa(areaPlanGfa)) {
        let warning = null;

        // Cross-check against room sum to catch modelling issues
        if (roomSumGfa > 0) {
            const diff = Math.abs(areaPlanGfa - roomSumGfa) / areaPlanGfa;
            if (diff > MISMATCH_THRESHOLD) {
                warning = WARNINGS.area_plan_mismatch;
            }
        }

        return {
            value: round2(areaPlanGfa),
            source: 'area_plan',
            confidence: 'high',
            warning,
            allSources,
        };
    }

    // ── Priority 2: Manual entry ─────────────────────────────
    if (isValidGfa(manualGfa)) {
        return {
            value: round2(manualGfa),
            source: 'manual',
            confidence: 'medium',
            warning: WARNINGS.manual_no_validation,
            allSources,
        };
    }

    // ── Priority 3: Room sum estimate ────────────────────────
    if (roomSumGfa > 0) {
        return {
            value: round2(roomSumGfa),
            source: 'estimated',
            confidence: 'low',
            warning: WARNINGS.estimated,
            allSources,
        };
    }

    // ── No GFA at all ────────────────────────────────────────
    return {
        value: 0,
        source: 'estimated',
        confidence: 'low',
        warning: WARNINGS.zero_gfa,
        allSources,
    };
}

// ── Helpers ──────────────────────────────────────────────────

function isValidGfa(value) {
    return value != null && typeof value === 'number' && value > 0 && Number.isFinite(value);
}

function round2(n) {
    return Math.round(n * 100) / 100;
}

module.exports = {
    resolveGfa,
    GFA_SOURCES,
    WARNINGS,
    MISMATCH_THRESHOLD,
};
