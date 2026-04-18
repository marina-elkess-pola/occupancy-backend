const express = require('express');
const router = express.Router();
const Anthropic = require('@anthropic-ai/sdk');
const { PRESETS, DEFAULT_PRESET, REVENUE_CATEGORIES, ALL_CATEGORIES, NON_BENCHMARKED, getBenchmarkForZone, getPresetList, classifyHeight } = require('./benchmarks');
const { classifyBatch } = require('./ruleClassifier');
const { classifyPipeline } = require('./classifyPipeline');
const { resolveGfa } = require('./gfaResolver');
const { computeConfidenceScore } = require('./confidenceScore');
const { triageClassifications } = require('./confidenceTriage');

/* ---------- TEMPORARY debug snapshot (remove later) ---------- */
let _lastDebugSnapshot = null;

/* ---------- Anthropic Claude client (lazy init) ---------- */
let _anthropic;
function getClaude() {
    if (!_anthropic) {
        const apiKey = process.env.ANTHROPIC_API_KEY;
        if (!apiKey) throw new Error('ANTHROPIC_API_KEY not configured');
        _anthropic = new Anthropic({ apiKey });
    }
    return _anthropic;
}

/* ================================================================
   GET /api/bsi/health
   Instant health check — no DB or AI dependency.
   ================================================================ */
router.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        version: '1.1'
    });
});

/* ================================================================
   POST /api/bsi/analyze
   Pure calculation — no AI call. Takes areas + zones, returns
   per-zone efficiency analysis scored against benchmarks.
   ================================================================ */
router.post('/analyze', async (req, res) => {
    const timeout = setTimeout(() => {
        if (!res.headersSent) {
            res.status(504).json({
                error: 'Analysis timeout',
                message: 'Analysis took longer than 4 minutes. Try with fewer rooms or check AI service.',
                partial: true
            });
        }
    }, 240000);
    try {
        const { projectName, areas, zones, financial, preset, buildingHeight } = req.body || {};

        if (!areas || !Array.isArray(areas) || areas.length === 0) {
            return res.status(400).json({ error: 'areas array is required' });
        }
        if (!zones || !Array.isArray(zones) || zones.length === 0) {
            return res.status(400).json({ error: 'zones array is required' });
        }

        // Validate categories
        for (const a of areas) {
            if (a.category && !ALL_CATEGORIES.has(a.category)) {
                return res.status(400).json({ error: `Invalid category "${a.category}" on area "${a.name}"` });
            }
        }

        // --- Build per-zone tallies ---
        const zoneResults = zones.map(zone => {
            const levelSet = new Set(zone.levels.map(Number));
            const zoneAreas = areas.filter(a => levelSet.has(Number(a.levelNumber)));

            const breakdown = {};
            let roomGFA = 0;
            let totalNLA = 0;

            for (const a of zoneAreas) {
                const cat = a.category || 'unclassified';
                breakdown[cat] = (breakdown[cat] || 0) + a.area;
                roomGFA += a.area;
                if (REVENUE_CATEGORIES.has(cat)) totalNLA += a.area;
            }

            // Resolve GFA through priority chain: area_plan → manual → estimated
            const gfaResult = resolveGfa({
                areaPlanGfa: zone.gfa,       // from Revit area plans (via BsiApiClient)
                manualGfa: zone.manualGfa,   // user-entered override (optional)
                roomSumGfa: roomGFA,
            });
            const totalGFA = gfaResult.value;
            const gfaSource = gfaResult.source;
            const gfaConfidence = gfaResult.confidence;
            const gfaWarning = gfaResult.warning;

            const efficiency = totalGFA > 0 ? totalNLA / totalGFA : 0;
            const benchmark = getBenchmarkForZone(zone.primaryUse, preset || DEFAULT_PRESET, buildingHeight);

            let status = 'on_target';
            if (!benchmark) {
                status = 'not_applicable';
            } else if (efficiency < benchmark.efficiency.min) {
                status = 'below_benchmark';
            } else if (efficiency > benchmark.efficiency.max) {
                status = 'above_benchmark';
            }

            // Core & circulation ratios
            const coreRatio = totalGFA > 0 ? (breakdown.core || 0) / totalGFA : 0;
            const circRatio = totalGFA > 0 ? (breakdown.circulation || 0) / totalGFA : 0;

            // Parking stall estimate: 28 m² per stall (structured parking incl. circulation).
            // API areas are always in m² so divide GFA directly by 28.
            const stallCount = zone.primaryUse === 'parking' && totalGFA > 0
                ? Math.floor(totalGFA / 28)
                : null;

            return {
                name: zone.name,
                primaryUse: zone.primaryUse,
                levels: zone.levels,
                gfa: round2(totalGFA),
                nla: round2(totalNLA),
                core: round2(breakdown.core || 0),
                circulation: round2(breakdown.circulation || 0),
                efficiency: round4(efficiency),
                coreRatio: round4(coreRatio),
                circulationRatio: round4(circRatio),
                benchmark: benchmark ? benchmark.efficiency : null,
                status,
                gfaSource,
                gfaConfidence,
                gfaWarning,
                breakdown,
                stallCount,
            };
        });

        // --- Whole-building summary ---
        const totalGFA = zoneResults.reduce((s, z) => s + z.gfa, 0);
        const totalNLA = zoneResults.reduce((s, z) => s + z.nla, 0);
        const blendedEfficiency = totalGFA > 0 ? totalNLA / totalGFA : 0;
        const unclassifiedCount = areas.filter(a => !a.category || a.category === 'unclassified').length;

        // --- Financial estimates (optional) ---
        let financialResult = null;
        if (financial) {
            financialResult = {};
            for (const zone of zoneResults) {
                if (zone.primaryUse === 'residential' && financial.residential_price_per_sqm) {
                    financialResult.residential_revenue = (financialResult.residential_revenue || 0) +
                        zone.nla * financial.residential_price_per_sqm;
                }
                if (zone.primaryUse === 'retail' && financial.retail_rent_per_sqm_year) {
                    financialResult.retail_annual_rent = (financialResult.retail_annual_rent || 0) +
                        zone.nla * financial.retail_rent_per_sqm_year;
                }
                if (zone.primaryUse === 'office' && financial.office_rent_per_sqm_year) {
                    financialResult.office_annual_rent = (financialResult.office_annual_rent || 0) +
                        zone.nla * financial.office_rent_per_sqm_year;
                }
                if (zone.primaryUse === 'parking' && financial.parking_price_per_space) {
                    const approxSpaces = Math.floor(zone.nla / 25); // ~25m² per space
                    financialResult.parking_revenue = (financialResult.parking_revenue || 0) +
                        approxSpaces * financial.parking_price_per_space;
                }
            }
        }

        const analyzeResponse = {
            projectName: projectName || 'Untitled',
            summary: {
                totalGFA: round2(totalGFA),
                totalNLA: round2(totalNLA),
                blendedEfficiency: round4(blendedEfficiency),
                zoneCount: zoneResults.length,
                areaCount: areas.length,
                unclassifiedCount,
                gfaSource: zoneResults.some(z => z.gfaSource === 'area_plan') ? 'area_plan' : 'room_sum',
            },
            zones: zoneResults,
            financial: financialResult,
            preset: preset || DEFAULT_PRESET,
            buildingHeight: classifyHeight(buildingHeight),
        };

        // TEMPORARY: capture debug snapshot
        if (!_lastDebugSnapshot) _lastDebugSnapshot = {};
        _lastDebugSnapshot.analyze = analyzeResponse;
        _lastDebugSnapshot.inputRooms = areas;
        _lastDebugSnapshot.inputZones = zones;
        _lastDebugSnapshot.timestamp = new Date().toISOString();

        clearTimeout(timeout);
        return res.json(analyzeResponse);
    } catch (err) {
        clearTimeout(timeout);
        if (!res.headersSent) {
            console.error('BSI analyze error:', err);
            return res.status(500).json({
                error: 'Analysis failed',
                message: err.message,
                stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
            });
        }
    }
});

/* ================================================================
   POST /api/bsi/classify
   AI-powered auto-classification. Sends area names, sizes, levels
   to Claude and returns predicted categories with confidence.
   ================================================================ */
router.post('/classify', async (req, res) => {
    const timeout = setTimeout(() => {
        if (!res.headersSent) {
            res.status(504).json({
                error: 'Classification timeout',
                message: 'Classification took longer than 4 minutes. Try with fewer rooms.',
                partial: true
            });
        }
    }, 240000);
    try {
        const { areas, overrides } = req.body || {};
        if (!areas || !Array.isArray(areas) || areas.length === 0) {
            return res.status(400).json({ error: 'areas array is required' });
        }

        // Limit batch size to control token cost
        if (areas.length > 500) {
            return res.status(400).json({ error: 'Maximum 500 areas per classify request' });
        }

        const validCategories = ALL_CATEGORIES;

        // AI caller — injected into the pipeline so the orchestrator
        // stays transport-agnostic and testable.
        async function callAI(rooms) {
            const catList = Array.from(validCategories);
            const areaList = rooms.map(a =>
                `ID: ${a.id} | Name: "${a.name}" | Level: ${a.level || 'unknown'} | Area: ${a.area}m²`
            ).join('\n');

            const systemPrompt = `You are an expert architectural space classifier for building scheme analysis.
Given a list of spaces (with name, level, area), classify each into exactly ONE category.

Valid categories: ${catList.join(', ')}

Rules:
- "residential": apartments, units, studios, penthouses, bedrooms
- "retail": shops, stores, F&B, showrooms, restaurants, cafés
- "office": offices, workspaces, co-working, meeting rooms
- "hospitality": hotel rooms, suites, serviced apartments
- "core": stairs, lifts/elevators, risers, shafts, lobbies, vestibules
- "circulation": corridors, hallways, galleries, shared access paths
- "parking": car parks, bicycle storage, loading bays
- "amenity": gyms, pools, lounges, rooftop terraces, playgrounds, communal gardens
- "boh": plant rooms, MEP, storage, refuse, loading docks, cleaners' rooms
- "unclassified": only if truly ambiguous

LOBBY CLASSIFICATION RULES:
- Any room named 'Lobby', 'Residential Lobby', 'Main Lobby', 'Building Lobby', 'Entrance Lobby', or 'Reception' MUST be classified as 'core'.
- A lobby is shared building infrastructure used for access and circulation. It is NEVER 'residential', 'retail', or any sellable category.
- The only exception is 'Hotel Lobby' in a hotel zone, which should be 'circulation'.

Respond with a JSON array. Each element: { "id": "<area_id>", "category": "<category>", "confidence": <0.0-1.0> }
Return ONLY the JSON array, no markdown fences, no explanation.`;

            const claude = getClaude();
            const completion = await claude.messages.create({
                model: 'claude-sonnet-4-20250514',
                max_tokens: 4096,
                temperature: 0.1,
                system: systemPrompt,
                messages: [
                    { role: 'user', content: `Classify these ${rooms.length} spaces:\n${areaList}` },
                ],
            });

            const raw = completion.content[0]?.text?.trim();
            let parsed;
            try {
                parsed = JSON.parse(raw);
            } catch {
                console.error('BSI classify: failed to parse AI response:', raw);
                throw new Error('AI returned invalid JSON');
            }

            return {
                classifications: parsed,
                model: completion.model,
                tokens: (completion.usage?.input_tokens || 0) + (completion.usage?.output_tokens || 0) || null,
            };
        }

        // Run the pipeline: overrides → rules → AI (only unresolved) → merge
        const result = await classifyPipeline({
            rooms: areas,
            validCategories,
            callAI,
            overrides: Array.isArray(overrides) ? overrides : undefined,
        });

        // Post-classification safety net: lobbies must be core (or circulation)
        for (const c of result.classifications) {
            const room = areas.find(a => a.id === c.id);
            const roomName = room?.name || '';
            if (roomName.toLowerCase().includes('lobby') && c.category !== 'core' && c.category !== 'circulation') {
                console.log(`BSI: Auto-corrected "${roomName}" from "${c.category}" to "core" (lobby rule)`);
                c.category = 'core';
                c.confidence = 0.95;
                c.source = c.source || 'rule';
            }
        }

        console.log(`BSI classify: ${result.stats.ruleMatched} rule, ${result.stats.aiClassified} AI (${result.stats.aiUncertain} uncertain), ${result.stats.unresolved} unresolved`);

        // Compute analysis confidence score
        const confidence = computeConfidenceScore({ stats: result.stats, gfaVerified: false });

        // Triage: split into auto-resolved and needs-review groups
        // Attach room names to classifications for pattern grouping
        const classWithNames = result.classifications.map(c => {
            const room = areas.find(a => a.id === c.id);
            return { ...c, name: room?.name || c.id };
        });
        const triage = triageClassifications(classWithNames);

        const classifyResponse = { ...result, confidence, triage };

        // TEMPORARY: capture classify snapshot
        if (!_lastDebugSnapshot) _lastDebugSnapshot = {};
        _lastDebugSnapshot.classify = classifyResponse;
        _lastDebugSnapshot.classifyInputRooms = areas;

        clearTimeout(timeout);
        return res.json(classifyResponse);
    } catch (err) {
        clearTimeout(timeout);
        console.error('BSI classify error:', err);
        if (!res.headersSent) {
            if (err.message === 'ANTHROPIC_API_KEY not configured') {
                return res.status(503).json({ error: 'AI service not configured' });
            }
            if (err.message === 'AI returned invalid JSON') {
                return res.status(502).json({ error: err.message });
            }
            return res.status(500).json({
                error: 'Classification failed',
                message: err.message,
                stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
            });
        }
    }
});

/* ================================================================
   POST /api/bsi/advise
   AI Design Advisor. Takes analysis + optional zoneId, returns
   actionable suggestions with severity and quantified metric impact.
   ================================================================ */
router.post('/advise', async (req, res) => {
    try {
        const { analysis, zoneId, projectGoal } = req.body || {};
        console.log('BSI advise: incoming body keys:', Object.keys(req.body || {}));
        console.log('BSI advise: analysis zones count:', analysis?.zones?.length, 'zoneId:', zoneId || '(all)', 'goal:', projectGoal || '(default)');
        if (!analysis || !Array.isArray(analysis.zones) || analysis.zones.length === 0) {
            return res.status(400).json({ error: 'analysis object with non-empty zones array is required' });
        }

        const claude = getClaude();

        // Filter to a single zone if zoneId provided
        let targetZones = analysis.zones;
        if (zoneId) {
            targetZones = analysis.zones.filter(z => z.name === zoneId);
            if (targetZones.length === 0) {
                return res.status(400).json({ error: `Zone "${zoneId}" not found in analysis` });
            }
        }

        // Build a condensed context string for the AI
        const zoneContext = targetZones.map(z => {
            const bm = z.benchmark;
            const gfa = z.gfa || 0;
            const nla = z.nla || 0;
            const eff = Number(z.efficiency) || 0;
            const lines = [
                `Zone "${z.name || 'Unknown'}" (${z.primaryUse || 'unknown'}${z.levels?.length ? ', levels ' + z.levels[0] + '–' + z.levels[z.levels.length - 1] : ''}):`,
            ];

            if (bm && typeof bm.min === 'number') {
                lines.push(`  GFA=${gfa}m² NLA=${nla}m² Eff=${(eff * 100).toFixed(1)}% (benchmark ${(bm.min * 100).toFixed(0)}–${(bm.max * 100).toFixed(0)}%)`);
                const targetEff = typeof bm.target === 'number' ? bm.target : (bm.min + bm.max) / 2;
                const gap = targetEff - eff;
                if (gap > 0 && gfa > 0) {
                    lines.push(`  → Gap to target: ${(gap * 100).toFixed(1)}pp = ~${Math.round(gap * gfa)}m² recoverable NLA`);
                }
            } else {
                lines.push(`  GFA=${gfa}m² NLA=${nla}m² — not benchmarked`);
            }

            lines.push(`  Core=${z.core || 0}m² (${(((z.coreRatio || 0)) * 100).toFixed(1)}%) Circ=${z.circulation || 0}m² (${(((z.circulationRatio || 0)) * 100).toFixed(1)}%)`);
            lines.push(`  Status: ${z.status || 'unknown'}`);

            if (z.stallCount != null) {
                lines.push(`  Estimated parking stalls: ~${z.stallCount}`);
            }

            return lines.join('\n');
        }).join('\n\n');

        console.log('BSI advise: zone context built OK, length:', zoneContext.length);

        const summary = analysis.summary || {};
        const summaryContext = summary.totalGFA != null
            ? `Whole building: GFA=${summary.totalGFA}m² NLA=${summary.totalNLA || 0}m² Blended Eff=${((Number(summary.blendedEfficiency) || 0) * 100).toFixed(1)}% Zones=${summary.zoneCount || 0} Unclassified=${summary.unclassifiedCount || 0}`
            : '';

        const focusInstruction = zoneId
            ? `\nFOCUS: The user is asking specifically about zone "${zoneId}" ONLY. All suggestions MUST be about this zone — do NOT discuss other zones. You may mention whole-building context briefly for comparison, but every suggestion must target "${zoneId}".`
            : '';

        // Build goal-specific interpretation lens
        const GOAL_PROMPTS = {
            max_efficiency: `PROJECT GOAL: Maximum Efficiency. The client's priority is minimizing core and circulation to maximize NLA/GFA ratio. Flag ANY area where efficiency can be improved. Treat "on target" zones as still having room for optimization. Suggest aggressive core consolidation and circulation reduction strategies.`,
            balanced: `PROJECT GOAL: Balanced. The client wants industry-standard efficiency that balances sellable area with good livability and circulation. Evaluate against benchmark midpoints. Only flag zones significantly below target.`,
            max_yield: `PROJECT GOAL: Maximum Unit Yield. The client wants to maximize the number of sellable/lettable units. Prioritize suggestions that increase NLA and enable more units (smaller corridors, combined cores, efficient unit layouts). Quantify potential additional units where possible.`,
            premium: `PROJECT GOAL: Premium / Spacious. The client accepts lower efficiency for a luxury positioning. Generous lobbies, wider corridors, and premium amenity spaces are EXPECTED and should NOT be flagged as problems. Only flag truly excessive waste. Efficiency 5-8% below benchmark may be acceptable.`,
            custom: `PROJECT GOAL: Custom. The client has set their own benchmark targets. Evaluate strictly against the provided custom benchmarks rather than industry defaults.`,
        };
        const goalInstruction = GOAL_PROMPTS[projectGoal] || GOAL_PROMPTS.balanced;

        const systemPrompt = `You are a senior architectural efficiency consultant powered by AI.
You receive a building scheme analysis with per-zone efficiency data and benchmarks.
Provide actionable, specific suggestions to improve building efficiency and revenue.

${goalInstruction}

For EVERY suggestion you MUST include ALL of these fields:
- "zone": which zone it applies to (or "whole_building")
- "severity": "critical" | "high" | "medium" | "low" | "info"
- "type": short snake_case identifier (e.g. "circulation_overallocation", "core_oversized", "efficiency_below_target")
- "message": 2-4 sentences with CONCRETE numbers. State the current value, the target, the gap, and what action to take. Example: "Core area is 450m² (12.1% of GFA), exceeding the 10% benchmark target by 78m². Consolidating the two secondary stair cores could recover ~60m² of NLA. At 15,000 AED/m² this adds ~900,000 AED in sellable area."
- "metric_impact": object with quantified estimates (use 0 if not applicable):
  - "efficiency_delta": number (e.g. 0.02 means +2 percentage points)
  - "area_delta_m2": number (e.g. 60 means 60m² recovered NLA)
  - "revenue_delta": number (e.g. 900000 means 900k in project currency, 0 if no financial data)
${focusInstruction}
Also provide a "narrative" field (2-4 sentences): an executive summary of the ${zoneId ? 'zone' : 'building'}'s performance vs benchmarks, highlighting the most impactful opportunity.

Respond with a JSON object: { "suggestions": [...], "narrative": "..." }
Return ONLY valid JSON, no markdown fences, no explanation.`;

        const userMessage = `Analyze this building scheme and provide improvement suggestions:

${summaryContext}

${zoneContext}

${analysis.financial ? `Financial: ${JSON.stringify(analysis.financial)}` : 'No financial data provided.'}`;

        console.log('BSI advise: calling Claude...');
        const completion = await claude.messages.create({
            model: 'claude-sonnet-4-20250514',
            max_tokens: 4096,
            temperature: 0.3,
            system: systemPrompt,
            messages: [
                { role: 'user', content: userMessage },
            ],
        });

        let raw = (completion.content[0]?.text || '').trim();
        console.log('BSI advise: Claude response received, length:', raw.length);

        // Strip markdown fences if Claude wrapped the JSON
        if (raw.startsWith('```')) {
            raw = raw.replace(/^```(?:json)?\s*/, '').replace(/\s*```$/, '');
        }

        let result;
        try {
            result = JSON.parse(raw);
        } catch (parseErr) {
            console.error('BSI advise: failed to parse AI response:', raw?.substring(0, 500));
            return res.status(502).json({ error: 'AI returned invalid JSON', detail: parseErr.message });
        }

        // Sanitize and ensure metric_impact on every suggestion
        const validSeverities = new Set(['critical', 'high', 'medium', 'low', 'info']);
        const suggestions = Array.isArray(result.suggestions) ? result.suggestions.map(s => ({
            zone: s.zone || 'whole_building',
            severity: validSeverities.has(s.severity) ? s.severity : 'medium',
            type: s.type || 'general',
            message: s.message || '',
            metric_impact: {
                efficiency_delta: Number(s.metric_impact?.efficiency_delta) || 0,
                area_delta_m2: Number(s.metric_impact?.area_delta_m2) || 0,
                revenue_delta: Number(s.metric_impact?.revenue_delta) || 0,
            },
        })) : [];

        return res.json({
            suggestions,
            narrative: result.narrative || '',
            zoneId: zoneId || null,
            model: completion.model,
            tokens: (completion.usage?.input_tokens || 0) + (completion.usage?.output_tokens || 0) || null,
        });
    } catch (err) {
        console.error('BSI advise error:', err);
        if (err.message === 'ANTHROPIC_API_KEY not configured') {
            return res.status(503).json({ error: 'AI service not configured' });
        }
        // Surface Anthropic-specific errors
        if (err.status === 401) {
            return res.status(503).json({ error: 'AI authentication failed — check API key' });
        }
        if (err.status === 429) {
            return res.status(429).json({ error: 'AI rate limit exceeded — try again shortly' });
        }
        if (err.status === 404) {
            return res.status(502).json({ error: 'AI model not available' });
        }
        return res.status(500).json({ error: 'Advisory failed', detail: err.message });
    }
});

/* ================================================================
   GET /api/bsi/presets
   Return available benchmark presets for the client UI.
   ================================================================ */
router.get('/presets', (req, res) => {
    return res.json({ presets: getPresetList(), default: DEFAULT_PRESET });
});

/* ================================================================
   GET /api/bsi/debug-last  (TEMPORARY — remove after debugging)
   Returns the full last analysis snapshot.
   ================================================================ */
router.get('/debug-last', (req, res) => {
    if (!_lastDebugSnapshot) {
        return res.status(404).json({ error: 'No analysis has been run yet' });
    }
    return res.json(_lastDebugSnapshot);
});

/* ---------- Helpers ---------- */
function round2(n) { return Math.round(n * 100) / 100; }
function round4(n) { return Math.round(n * 10000) / 10000; }

module.exports = router;
