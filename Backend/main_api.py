"""Simple FastAPI-based API surface for the IoT NIDS backend.

Exposes a health endpoint and a WebSocket that streams mock alerts
for development and testing.
"""

import asyncio
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from Backend.timeseries_logger import IncidentLogger, display_events_table


async def produce_demo_alerts(app: FastAPI):
    """Generate, log, print, and broadcast demo alerts while the API is running."""
    counter = 0
    while True:
        await asyncio.sleep(2)
        counter += 1
        alert_payload = {
            "id": counter,
            "rule_id": "ML-ANOMALY-01",
            "severity": "Critical" if counter % 3 == 0 else "Medium",
            "src_ip": f"192.168.1.{10 + counter}",
            "message": "High entropy payload volume detected",
        }
        incident_logger = app.state.incident_logger
        incident_logger.log_event(
            alert_payload["rule_id"],
            alert_payload["severity"],
            alert_payload["src_ip"],
            alert_payload["message"],
        )
        display_events_table(incident_logger.fetch_recent(1))

        for websocket in tuple(app.state.alert_clients):
            try:
                await websocket.send_json(alert_payload)
            except WebSocketDisconnect:
                app.state.alert_clients.discard(websocket)


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.incident_logger = IncidentLogger()
    app.state.alert_clients = set()
    alert_task = asyncio.create_task(produce_demo_alerts(app))
    try:
        yield
    finally:
        alert_task.cancel()
        with suppress(asyncio.CancelledError):
            await alert_task
        app.state.incident_logger.conn.close()


app = FastAPI(title="IoT NIDS Backend", lifespan=lifespan)

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
    """Stream demo alerts to clients while they are connected."""
    await websocket.accept()
    app.state.alert_clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        print("Client disconnected from WebSocket.")
    finally:
        app.state.alert_clients.discard(websocket)
