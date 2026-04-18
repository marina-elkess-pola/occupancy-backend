// Basic geometry utils for parking generator

function polygonArea(points) {
    let area = 0;
    for (let i = 0, j = points.length - 1; i < points.length; i++) {
        const p = points[i], q = points[j];
        area += (q.x + p.x) * (q.y - p.y);
        j = i;
    }
    return Math.abs(area) * 0.5;
}

function bboxFromPolygon(points) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const p of points) { minX = Math.min(minX, p.x); minY = Math.min(minY, p.y); maxX = Math.max(maxX, p.x); maxY = Math.max(maxY, p.y); }
    return { minX, minY, maxX, maxY, width: maxX - minX, height: maxY - minY };
}

function clamp(val, min, max) { return Math.max(min, Math.min(max, val)); }

module.exports = { polygonArea, bboxFromPolygon, clamp };
