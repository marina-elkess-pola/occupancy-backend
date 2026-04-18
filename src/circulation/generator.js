// Rectangle-based circulation generator for surface parking
// Constraints in feet

function generateCirculationRect(siteRect, constraints = {}) {
    const minX = Number(siteRect?.minX ?? 0);
    const minY = Number(siteRect?.minY ?? 0);
    const maxX = Number(siteRect?.maxX ?? 100);
    const maxY = Number(siteRect?.maxY ?? 60);
    const width = maxX - minX;
    const height = maxY - minY;
    if (width <= 0 || height <= 0) {
        return { segments: [], meta: { error: 'Invalid site rectangle' } };
    }

    const stallWidth = Number(constraints?.stallWidth ?? 9);
    const stallLength = Number(constraints?.stallLength ?? 18);
    const aisleWidth = Number(constraints?.aisleWidth ?? 24);
    const angleDeg = Number(constraints?.angleDeg ?? 90);

    // Entry at midpoint of bottom edge
    const entry = { x: minX + width / 2, y: minY };

    // Simple layout: central drive aisle horizontally across the site
    const centerY = minY + height / 2;
    const centerline = [
        { from: { x: minX + 10, y: centerY }, to: { x: maxX - 10, y: centerY } },
    ];

    // Connector from entry point up to centerline
    const connector = [
        { from: { x: entry.x, y: entry.y }, to: { x: entry.x, y: centerY } },
    ];

    // End bulbs/connectors at each end (simple perpendicular stubs)
    const endStubs = [
        { from: { x: minX + 10, y: centerY }, to: { x: minX + 10, y: centerY + aisleWidth / 2 } },
        { from: { x: maxX - 10, y: centerY }, to: { x: maxX - 10, y: centerY - aisleWidth / 2 } },
    ];

    // Optionally compute stall row centerlines above/below the aisle (not returned as circulation segments for now)
    const upperRowY = centerY + aisleWidth / 2 + stallLength / 2;
    const lowerRowY = centerY - aisleWidth / 2 - stallLength / 2;

    const segments = [...connector, ...centerline, ...endStubs];

    return {
        ok: true,
        segments,
        meta: {
            siteRect: { minX, minY, maxX, maxY },
            constraints: { stallWidth, stallLength, aisleWidth, angleDeg },
            rows: { upperRowY, lowerRowY },
            entry,
        },
    };
}

module.exports = { generateCirculationRect };
