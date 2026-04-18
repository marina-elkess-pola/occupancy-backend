// Parking layout generator: stalls, streets, junctions
// Units in feet; boundary as polygon [{x,y},...]

const { bboxFromPolygon } = require('./geometry');

function generateIterations(boundary, constraints) {
    const cfg = normalizeConstraints(constraints);
    const bbox = bboxFromPolygon(boundary);
    const iterations = [];

    // Iteration A: single central aisle horizontally, two rows of stalls
    iterations.push(generateCentralAisle(bbox, cfg));

    // Iteration B: two parallel aisles, three rows of stalls
    iterations.push(generateDoubleAisle(bbox, cfg));

    // Iteration C: vertical orientation
    iterations.push(generateVerticalAisle(bbox, cfg));

    return iterations;
}

function normalizeConstraints(c) {
    return {
        stallWidth: Number(c?.stallWidth ?? 9),
        stallLength: Number(c?.stallLength ?? 18),
        aisleWidth: Number(c?.aisleWidth ?? 24),
        angleDeg: Number(c?.angleDeg ?? 90),
        entry: c?.entry || null,
    };
}

function generateCentralAisle(bbox, cfg) {
    const cy = bbox.minY + bbox.height / 2;
    const margin = cfg.stallLength / 2 + cfg.aisleWidth / 2;
    const leftX = bbox.minX + 10;
    const rightX = bbox.maxX - 10;
    const streets = [
        seg({ x: leftX, y: cy }, { x: rightX, y: cy }),
    ];
    const junctions = [
        seg({ x: leftX, y: cy }, { x: leftX, y: cy + cfg.aisleWidth / 2 }),
        seg({ x: rightX, y: cy }, { x: rightX, y: cy - cfg.aisleWidth / 2 }),
    ];
    const stalls = stallRowsAlong(bbox, cy, cfg);
    return assembleSolution('central-aisle', bbox, cfg, streets, junctions, stalls);
}

function generateDoubleAisle(bbox, cfg) {
    const cy = bbox.minY + bbox.height / 2;
    const dy = cfg.aisleWidth + cfg.stallLength;
    const y1 = cy + dy / 2;
    const y2 = cy - dy / 2;
    const leftX = bbox.minX + 10;
    const rightX = bbox.maxX - 10;
    const streets = [seg({ x: leftX, y: y1 }, { x: rightX, y: y1 }), seg({ x: leftX, y: y2 }, { x: rightX, y: y2 })];
    const junctions = [seg({ x: leftX, y: y1 }, { x: leftX, y: y1 + cfg.aisleWidth / 2 }), seg({ x: rightX, y: y2 }, { x: rightX, y: y2 - cfg.aisleWidth / 2 })];
    const stalls = [...stallRowsAlong(bbox, y1, cfg), ...stallRowsAlong(bbox, y2, cfg)];
    return assembleSolution('double-aisle', bbox, cfg, streets, junctions, stalls);
}

function generateVerticalAisle(bbox, cfg) {
    const cx = bbox.minX + bbox.width / 2;
    const topY = bbox.maxY - 10;
    const botY = bbox.minY + 10;
    const streets = [seg({ x: cx, y: botY }, { x: cx, y: topY })];
    const junctions = [seg({ x: cx, y: botY }, { x: cx + cfg.aisleWidth / 2, y: botY })];
    const stalls = stallColumnsAlong(bbox, cx, cfg);
    return assembleSolution('vertical-aisle', bbox, cfg, streets, junctions, stalls);
}

function stallRowsAlong(bbox, aisleY, cfg) {
    const rows = [];
    // upper row centerline
    const upperY = aisleY + cfg.aisleWidth / 2 + cfg.stallLength / 2;
    const lowerY = aisleY - cfg.aisleWidth / 2 - cfg.stallLength / 2;
    const xStart = bbox.minX + 10;
    const xEnd = bbox.maxX - 10;
    const spacing = cfg.stallWidth;
    for (let x = xStart; x <= xEnd - spacing; x += spacing) {
        rows.push(stallRect({ x: x, y: upperY }, spacing, cfg.stallLength));
        rows.push(stallRect({ x: x, y: lowerY }, spacing, cfg.stallLength));
    }
    return rows;
}

function stallColumnsAlong(bbox, aisleX, cfg) {
    const cols = [];
    const yStart = bbox.minY + 10;
    const yEnd = bbox.maxY - 10;
    const spacing = cfg.stallWidth;
    const xLeft = aisleX - cfg.aisleWidth / 2 - cfg.stallLength / 2;
    const xRight = aisleX + cfg.aisleWidth / 2 + cfg.stallLength / 2;
    for (let y = yStart; y <= yEnd - spacing; y += spacing) {
        cols.push(stallRect({ x: xLeft, y: y }, cfg.stallLength, spacing));
        cols.push(stallRect({ x: xRight, y: y }, cfg.stallLength, spacing));
    }
    return cols;
}

function seg(a, b) { return { from: a, to: b }; }

function stallRect(origin, w, h) {
    const x = origin.x, y = origin.y;
    return {
        polygon: [
            { x: x, y: y },
            { x: x + w, y: y },
            { x: x + w, y: y + h },
            { x: x, y: y + h },
        ],
    };
}

function assembleSolution(name, bbox, cfg, streets, junctions, stalls) {
    return {
        name,
        bbox,
        constraints: cfg,
        streets,
        junctions,
        stalls,
    };
}

module.exports = { generateIterations };
