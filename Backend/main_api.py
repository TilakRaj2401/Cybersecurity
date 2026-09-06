"""Simple FastAPI-based API surface for the IoT NIDS backend.

Exposes a health endpoint and a WebSocket that streams mock alerts
for development and testing.
"""

import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="IoT NIDS Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
def health_check():
    """Return a simple health status for the API and processing engine."""
    return {"status": "operational", "engine": "running"}

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Accept a websocket connection and stream mock alert payloads periodically.

    This endpoint is intended for development and demonstration; it sends a
    simple JSON alert every two seconds until the client disconnects.
    """

    await websocket.accept()
    counter = 0
    try:
        while True:
            await asyncio.sleep(2)
            counter += 1
            alert_payload = {
                "id": counter,
                "rule_id": "ML-ANOMALY-01",
                "severity": "Critical" if counter % 3 == 0 else "Medium",
                "src_ip": f"192.168.1.{10 + counter}",
                "message": "High entropy payload volume detected"
            }
            await websocket.send_json(alert_payload)
    except WebSocketDisconnect:
        print("Client disconnected from WebSocket.")
