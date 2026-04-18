/**
 * BSI Benchmarks — preset-based building efficiency targets.
 *
 * Each preset defines per-typology efficiency / core / circulation ranges
 * and adjusts for buildingHeight: "low" (≤5 floors), "mid" (6–20), "high" (21+).
 *
 * Height adjustments:
 *   - Taller buildings need more core (lifts, risers, refuge floors)
 *     and slightly more circulation, so efficiency drops.
 *   - "low" gets a small bonus, "high" gets a penalty.
 */

// ── Height adjustment deltas (applied to min/target/max) ────────
const HEIGHT_ADJUSTMENTS = {
    low: { efficiency: 0.01, core: -0.01, circulation: -0.005 },
    mid: { efficiency: 0.00, core: 0.00, circulation: 0.00 },
    high: { efficiency: -0.02, core: 0.02, circulation: 0.01 },
};

// ── 6 Presets (5 standard + custom) ─────────────────────────────
const PRESETS = {
    dubai_residential_tower: {
        id: 'dubai_residential_tower',
        label: 'GFA-based (UAE / Dubai Municipality)',
        description: 'Uses Gross Floor Area per Dubai Municipality guidelines. NLA/GFA efficiency for residential towers with podium retail and basement parking.',
        region: 'GCC',
        denominatorType: 'GEA',  // v1.5: all presets use GEA; future: GIA support
        typologies: {
            residential: {
                efficiency: { min: 0.78, target: 0.82, max: 0.85 },
                core: { min: 0.08, target: 0.10, max: 0.13 },
                circulation: { min: 0.04, target: 0.06, max: 0.08 },
            },
            retail: {
                efficiency: { min: 0.85, target: 0.90, max: 0.92 },
                core: { min: 0.04, target: 0.05, max: 0.07 },
                circulation: { min: 0.02, target: 0.03, max: 0.05 },
            },
            office: {
                efficiency: { min: 0.80, target: 0.83, max: 0.87 },
                core: { min: 0.08, target: 0.09, max: 0.11 },
                circulation: { min: 0.03, target: 0.04, max: 0.06 },
            },
            hospitality: {
                efficiency: { min: 0.62, target: 0.68, max: 0.72 },
                core: { min: 0.12, target: 0.14, max: 0.16 },
                circulation: { min: 0.15, target: 0.18, max: 0.22 },
            },
        },
    },

    uk_mixed_use: {
        id: 'uk_mixed_use',
        label: 'GIA-based (UK / RICS)',
        description: 'Uses Gross Internal Area per RICS measurement standards. NIA/GIA efficiency for mid-rise mixed-use with residential, office and ground-floor retail.',
        region: 'UK',
        denominatorType: 'GIA',  // v1.5: falls back to GEA; future: subtract wall thickness
        typologies: {
            residential: {
                efficiency: { min: 0.76, target: 0.80, max: 0.83 },
                core: { min: 0.09, target: 0.11, max: 0.14 },
                circulation: { min: 0.05, target: 0.07, max: 0.09 },
            },
            retail: {
                efficiency: { min: 0.82, target: 0.87, max: 0.90 },
                core: { min: 0.04, target: 0.06, max: 0.08 },
                circulation: { min: 0.03, target: 0.04, max: 0.06 },
            },
            office: {
                efficiency: { min: 0.78, target: 0.82, max: 0.85 },
                core: { min: 0.09, target: 0.10, max: 0.12 },
                circulation: { min: 0.04, target: 0.05, max: 0.07 },
            },
            hospitality: {
                efficiency: { min: 0.60, target: 0.65, max: 0.70 },
                core: { min: 0.13, target: 0.15, max: 0.18 },
                circulation: { min: 0.15, target: 0.18, max: 0.22 },
            },
        },
    },

    gcc_commercial_tower: {
        id: 'gcc_commercial_tower',
        label: 'GFA-based (GCC / Commercial)',
        description: 'Uses Gross Floor Area per GCC commercial standards. NLA/GFA efficiency for office/commercial towers with retail podium.',
        region: 'GCC',
        denominatorType: 'GEA',
        typologies: {
            residential: {
                efficiency: { min: 0.78, target: 0.82, max: 0.85 },
                core: { min: 0.08, target: 0.10, max: 0.13 },
                circulation: { min: 0.04, target: 0.06, max: 0.08 },
            },
            retail: {
                efficiency: { min: 0.86, target: 0.91, max: 0.93 },
                core: { min: 0.03, target: 0.04, max: 0.06 },
                circulation: { min: 0.02, target: 0.03, max: 0.05 },
            },
            office: {
                efficiency: { min: 0.82, target: 0.85, max: 0.88 },
                core: { min: 0.07, target: 0.08, max: 0.10 },
                circulation: { min: 0.03, target: 0.04, max: 0.06 },
            },
            hospitality: {
                efficiency: { min: 0.62, target: 0.68, max: 0.72 },
                core: { min: 0.12, target: 0.14, max: 0.16 },
                circulation: { min: 0.15, target: 0.18, max: 0.22 },
            },
        },
    },

    hotel_resort: {
        id: 'hotel_resort',
        label: 'GFA-based (Hotel / Hospitality)',
        description: 'Uses Gross Floor Area for hospitality benchmarks. NLA/GFA efficiency for hotels and resorts with generous circulation and amenity.',
        region: 'Global',
        denominatorType: 'GEA',
        typologies: {
            residential: {
                efficiency: { min: 0.75, target: 0.79, max: 0.82 },
                core: { min: 0.09, target: 0.11, max: 0.14 },
                circulation: { min: 0.06, target: 0.08, max: 0.10 },
            },
            retail: {
                efficiency: { min: 0.82, target: 0.87, max: 0.90 },
                core: { min: 0.04, target: 0.06, max: 0.08 },
                circulation: { min: 0.03, target: 0.04, max: 0.06 },
            },
            office: {
                efficiency: { min: 0.78, target: 0.82, max: 0.85 },
                core: { min: 0.08, target: 0.10, max: 0.12 },
                circulation: { min: 0.04, target: 0.05, max: 0.07 },
            },
            hospitality: {
                efficiency: { min: 0.58, target: 0.63, max: 0.68 },
                core: { min: 0.13, target: 0.16, max: 0.19 },
                circulation: { min: 0.16, target: 0.20, max: 0.24 },
            },
        },
    },

    european_apartment: {
        id: 'european_apartment',
        label: 'GIA-based (Europe / IPMS)',
        description: 'Uses Gross Internal Area per IPMS standards. NIA/GIA efficiency for mid-rise European residential with compact core.',
        region: 'EU',
        denominatorType: 'GIA',  // v1.5: falls back to GEA; future: subtract wall thickness
        typologies: {
            residential: {
                efficiency: { min: 0.80, target: 0.84, max: 0.87 },
                core: { min: 0.07, target: 0.09, max: 0.11 },
                circulation: { min: 0.03, target: 0.05, max: 0.07 },
            },
            retail: {
                efficiency: { min: 0.84, target: 0.89, max: 0.92 },
                core: { min: 0.03, target: 0.05, max: 0.07 },
                circulation: { min: 0.02, target: 0.03, max: 0.05 },
            },
            office: {
                efficiency: { min: 0.79, target: 0.83, max: 0.86 },
                core: { min: 0.08, target: 0.09, max: 0.11 },
                circulation: { min: 0.03, target: 0.05, max: 0.07 },
            },
            hospitality: {
                efficiency: { min: 0.60, target: 0.66, max: 0.71 },
                core: { min: 0.12, target: 0.14, max: 0.17 },
                circulation: { min: 0.14, target: 0.17, max: 0.21 },
            },
        },
    },

    boma_us: {
        id: 'boma_us',
        label: 'BOMA (US)',
        description: 'Building Owners and Managers Association standard. Uses Rentable Area as denominator and Usable Area as numerator. Common in US commercial real estate. Note: BOMA load factors are not yet calculated in v1.5 — this preset uses standard efficiency ratios. Full BOMA load factor support comes in v1.6.',
        region: 'US',
        denominatorType: 'BOMA_RENTABLE',
        typologies: {
            residential: {
                efficiency: { min: 0.78, target: 0.84, max: 0.90 },
                core: { min: 0.06, target: 0.08, max: 0.11 },
                circulation: { min: 0.03, target: 0.05, max: 0.07 },
            },
            retail: {
                efficiency: { min: 0.70, target: 0.80, max: 0.92 },
                core: { min: 0.03, target: 0.05, max: 0.08 },
                circulation: { min: 0.02, target: 0.04, max: 0.06 },
            },
            office: {
                efficiency: { min: 0.75, target: 0.82, max: 0.88 },
                core: { min: 0.07, target: 0.09, max: 0.12 },
                circulation: { min: 0.03, target: 0.05, max: 0.07 },
            },
            hospitality: {
                efficiency: { min: 0.60, target: 0.66, max: 0.72 },
                core: { min: 0.12, target: 0.14, max: 0.17 },
                circulation: { min: 0.14, target: 0.17, max: 0.21 },
            },
        },
    },

    custom: {
        id: 'custom',
        label: 'Custom',
        description: 'User-defined benchmarks. All typology targets default to zero — override via the settings panel.',
        region: 'Custom',
        denominatorType: 'GEA',
        typologies: {
            residential: {
                efficiency: { min: 0, target: 0, max: 1 },
                core: { min: 0, target: 0, max: 1 },
                circulation: { min: 0, target: 0, max: 1 },
            },
            retail: {
                efficiency: { min: 0, target: 0, max: 1 },
                core: { min: 0, target: 0, max: 1 },
                circulation: { min: 0, target: 0, max: 1 },
            },
            office: {
                efficiency: { min: 0, target: 0, max: 1 },
                core: { min: 0, target: 0, max: 1 },
                circulation: { min: 0, target: 0, max: 1 },
            },
            hospitality: {
                efficiency: { min: 0, target: 0, max: 1 },
                core: { min: 0, target: 0, max: 1 },
                circulation: { min: 0, target: 0, max: 1 },
            },
        },
    },
};

/** Default preset when none specified */
const DEFAULT_PRESET = 'dubai_residential_tower';

/** Primary use types that generate revenue */
const REVENUE_CATEGORIES = new Set(['residential', 'retail', 'office', 'hospitality']);

/** All valid BSI categories */
const ALL_CATEGORIES = new Set([
    'residential', 'retail', 'office', 'hospitality',
    'core', 'circulation', 'parking', 'amenity', 'boh', 'unclassified',
]);

/** Non-benchmarked zone types (efficiency = N/A) */
const NON_BENCHMARKED = new Set(['parking', 'amenity', 'boh', 'unclassified']);

/**
 * Clamp a range so min ≤ target ≤ max and all stay within [0, 1].
 */
function clampRange(obj) {
    const clamp = v => Math.round(Math.max(0, Math.min(1, v)) * 10000) / 10000;
    return {
        min: clamp(obj.min),
        target: clamp(obj.target),
        max: clamp(obj.max),
    };
}

/**
 * Apply height adjustment to a typology benchmark.
 */
function adjustForHeight(typologyBenchmark, heightCategory) {
    const adj = HEIGHT_ADJUSTMENTS[heightCategory] || HEIGHT_ADJUSTMENTS.mid;
    return {
        efficiency: clampRange({
            min: typologyBenchmark.efficiency.min + adj.efficiency,
            target: typologyBenchmark.efficiency.target + adj.efficiency,
            max: typologyBenchmark.efficiency.max + adj.efficiency,
        }),
        core: clampRange({
            min: typologyBenchmark.core.min + adj.core,
            target: typologyBenchmark.core.target + adj.core,
            max: typologyBenchmark.core.max + adj.core,
        }),
        circulation: clampRange({
            min: typologyBenchmark.circulation.min + adj.circulation,
            target: typologyBenchmark.circulation.target + adj.circulation,
            max: typologyBenchmark.circulation.max + adj.circulation,
        }),
    };
}

/**
 * Determine height category from number of above-ground floors.
 */
function classifyHeight(buildingHeight) {
    if (typeof buildingHeight === 'string') {
        const h = buildingHeight.toLowerCase();
        if (h === 'low' || h === 'mid' || h === 'high') return h;
    }
    const floors = Number(buildingHeight);
    if (!floors || floors <= 5) return 'low';
    if (floors <= 20) return 'mid';
    return 'high';
}

/**
 * Pick the best benchmark for a zone's primary use within a preset.
 * Returns null for parking/amenity zones (not benchmarked).
 *
 * @param {string} primaryUse - Zone primary use (residential, retail, etc.)
 * @param {string} presetId - Preset identifier (defaults to dubai_residential_tower)
 * @param {string|number} buildingHeight - "low"/"mid"/"high" or floor count
 * @returns {{ efficiency, core, circulation } | null}
 */
function getBenchmarkForZone(primaryUse, presetId, buildingHeight) {
    if (NON_BENCHMARKED.has(primaryUse)) return null;

    const preset = PRESETS[presetId] || PRESETS[DEFAULT_PRESET];
    const typology = preset.typologies[primaryUse];
    if (!typology) {
        // Fallback: try residential as a safe default
        const fallback = preset.typologies.residential;
        if (!fallback) return null;
        return adjustForHeight(fallback, classifyHeight(buildingHeight));
    }

    return adjustForHeight(typology, classifyHeight(buildingHeight));
}

/**
 * Return the list of available presets (for GET /presets endpoint).
 */
function getPresetList() {
    return Object.values(PRESETS).map(p => ({
        id: p.id,
        label: p.label,
        description: p.description,
        region: p.region,
        denominatorType: p.denominatorType,
        typologies: Object.keys(p.typologies),
    }));
}

module.exports = {
    PRESETS,
    DEFAULT_PRESET,
    HEIGHT_ADJUSTMENTS,
    REVENUE_CATEGORIES,
    ALL_CATEGORIES,
    NON_BENCHMARKED,
    getBenchmarkForZone,
    getPresetList,
    classifyHeight,
};
