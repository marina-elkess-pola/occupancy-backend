/**
 * Efficiency explanation generator for BSI.
 *
 * Produces a structured, human-readable explanation of how
 * building efficiency is calculated. Adapts wording based on
 * zone typology and GFA source.
 *
 * Target audience: architects (not surveyors). The language
 * avoids jargon like "RICS 6th edition" unless it helps.
 */

'use strict';

// ── Category definitions ─────────────────────────────────────

const NLA_CATEGORIES = ['residential', 'retail', 'office', 'hospitality'];
const EXCLUDED_CATEGORIES = ['core', 'circulation', 'boh', 'amenity'];

// ── Typology-specific wording ────────────────────────────────

const TYPOLOGY_CONTEXT = {
    residential: {
        nlaLabel: 'Net Lettable Area (apartments, studios, duplexes)',
        typicalRange: '78–85%',
        note: 'Tall residential towers typically lose 2–4% efficiency due to additional lift cores and refuge floors.',
    },
    retail: {
        nlaLabel: 'Net Lettable Area (shops, F&B, commercial tenancies)',
        typicalRange: '80–90%',
        note: 'Retail podiums tend to be more efficient due to simple floor plates and minimal core.',
    },
    office: {
        nlaLabel: 'Net Lettable Area (office workspace, meeting rooms)',
        typicalRange: '75–82%',
        note: 'Office floors with central cores are typically more efficient than side-core layouts.',
    },
    hospitality: {
        nlaLabel: 'Net Lettable Area (guest rooms, suites)',
        typicalRange: '62–72%',
        note: 'Hotels have lower efficiency due to double-loaded corridors and larger BOH requirements.',
    },
};

const DEFAULT_CONTEXT = {
    nlaLabel: 'Net Lettable Area (revenue-generating spaces)',
    typicalRange: '70–85%',
    note: 'Efficiency varies significantly by building type, height, and core configuration.',
};

// ── GFA source wording ───────────────────────────────────────

const GFA_SOURCE_TEXT = {
    area_plan: 'GFA is taken from Revit area plans, which provides the most accurate measurement.',
    room_sum: 'GFA is estimated by summing individual room areas. This may undercount total floor area if rooms do not cover the full slab (e.g. wall thicknesses, unmeasured voids). Use area plans for more accurate results.',
};

// ── Main function ────────────────────────────────────────────

/**
 * Generate a structured efficiency explanation.
 *
 * @param {Object}  opts
 * @param {string}  [opts.typology]   — 'residential'|'retail'|'office'|'hospitality' (zone primaryUse)
 * @param {string}  [opts.gfaSource]  — 'area_plan'|'room_sum'
 * @param {string}  [opts.presetLabel] — e.g. 'GFA-based (UAE / Dubai Municipality)'
 * @param {number}  [opts.efficiency]  — current calculated efficiency (0–1), for context
 *
 * @returns {{
 *   formula: string,
 *   includedAreas: string[],
 *   excludedAreas: string[],
 *   assumptions: string[],
 *   disclaimer: string,
 *   typologyNote: string|null,
 *   gfaNote: string
 * }}
 */
function generateEfficiencyExplanation({
    typology = null,
    gfaSource = 'room_sum',
    presetLabel = null,
    efficiency = null,
} = {}) {
    const ctx = TYPOLOGY_CONTEXT[typology] || DEFAULT_CONTEXT;

    // ── Formula ──────────────────────────────────────────────

    const formula = 'Efficiency (%) = NLA ÷ GFA × 100';

    // ── Included / excluded areas ────────────────────────────

    const includedAreas = NLA_CATEGORIES.map(cat => {
        const labels = {
            residential: 'Residential (apartments, studios, townhouses)',
            retail: 'Retail (shops, restaurants, commercial)',
            office: 'Office (workspace, meeting rooms)',
            hospitality: 'Hospitality (hotel rooms, suites)',
        };
        return labels[cat];
    });

    const excludedAreas = EXCLUDED_CATEGORIES.map(cat => {
        const labels = {
            core: 'Core (stairs, lifts, risers, shafts)',
            circulation: 'Circulation (corridors, lobbies, atriums)',
            boh: 'Back-of-House (plant, storage, services)',
            amenity: 'Amenity (gym, pool, communal areas)',
        };
        return labels[cat];
    });

    // ── Assumptions ──────────────────────────────────────────

    const assumptions = [
        'NLA includes only revenue-generating lettable space.',
        'GFA includes all enclosed floor area on the measured levels.',
        'Parking areas are excluded from both NLA and efficiency calculation.',
        'Unclassified rooms are excluded from NLA but included in room-sum GFA.',
    ];

    if (gfaSource === 'room_sum') {
        assumptions.push(
            'GFA is estimated from room areas — may not include wall thicknesses or unmeasured areas.'
        );
    }

    if (typology && ctx.typicalRange) {
        assumptions.push(
            `Typical ${typology} efficiency range: ${ctx.typicalRange}.`
        );
    }

    // ── Disclaimer ───────────────────────────────────────────

    let disclaimer = 'This is an indicative efficiency estimate for early-stage design comparison.';
    disclaimer += ' It is not a certified measurement and does not comply with RICS, BOMA, or IPMS standards.';
    disclaimer += ' For formal area reporting, engage a qualified surveyor.';

    if (presetLabel) {
        disclaimer += ` Benchmarks are based on the "${presetLabel}" preset.`;
    }

    // ── Typology note ────────────────────────────────────────

    const typologyNote = ctx.note || null;

    // ── GFA note ─────────────────────────────────────────────

    const gfaNote = GFA_SOURCE_TEXT[gfaSource] || GFA_SOURCE_TEXT.room_sum;

    // ── Efficiency context (if provided) ─────────────────────

    if (efficiency != null && ctx.typicalRange) {
        const pct = Math.round(efficiency * 100);
        assumptions.push(
            `Current calculated efficiency: ${pct}% (typical range: ${ctx.typicalRange}).`
        );
    }

    return {
        formula,
        includedAreas,
        excludedAreas,
        assumptions,
        disclaimer,
        typologyNote,
        gfaNote,
    };
}

module.exports = {
    generateEfficiencyExplanation,
    NLA_CATEGORIES,
    EXCLUDED_CATEGORIES,
};
