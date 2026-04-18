// Minimal local bridge service for ParkCore ↔ Revit add-in
// Uses HTTP + WebSocket for low-latency messaging.

const http = require('http');
const WebSocket = require('ws');

const PORT = process.env.BRIDGE_PORT || 7090;

const server = http.createServer((req, res) => {
    if (req.method === 'GET' && req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
    }
    res.writeHead(404);
    res.end();
});

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
    ws.on('message', (data) => {
        let msg;
        try { msg = JSON.parse(data.toString()); } catch { msg = { type: 'raw', data: data.toString() }; }
        // Echo for now; later route to backend and Revit add-in
        if (msg && msg.type) {
            ws.send(JSON.stringify({ ok: true, echo: msg }));
        } else {
            ws.send(JSON.stringify({ ok: true, echo: data.toString() }));
        }
    });
    ws.send(JSON.stringify({ ready: true }));
});

server.listen(PORT, () => {
    console.log(`ParkCore Bridge listening on http://localhost:${PORT}`);
});
