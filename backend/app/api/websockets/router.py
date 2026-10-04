"""Real-time WebSockets API Router for SOC Live Feed."""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.websockets import ws_manager

router = APIRouter()


@router.websocket("/ws/live-feed")
async def websocket_live_feed(websocket: WebSocket):
    """Real-time live telemetry stream WebSocket endpoint."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open and await ping/heartbeat messages
            data = await websocket.receive_text()
            # Echo heartbeat acknowledgment
            await websocket.send_json({"type": "PONG", "received": data})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
