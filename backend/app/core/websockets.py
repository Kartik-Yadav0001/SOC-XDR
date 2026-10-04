"""Real-time WebSocket connection manager for live SOC event streaming."""

import json
from typing import List, Dict, Any, Optional
from fastapi import WebSocket, WebSocketDisconnect
import structlog

logger = structlog.get_logger("sentinelx.ws")


class ConnectionManager:
    """Manages active client WebSocket connections and broadcasts real-time SOC updates."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accept incoming WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("websocket_connected", client_count=len(self.active_connections))

    def disconnect(self, websocket: WebSocket):
        """Remove disconnected WebSocket from active pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("websocket_disconnected", client_count=len(self.active_connections))

    async def broadcast(self, message: Dict[str, Any]):
        """Broadcast JSON message payload to all connected clients."""
        if not self.active_connections:
            return

        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as err:
                logger.warning("websocket_send_failed", error=str(err))
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

    async def broadcast_alert(self, alert_dict: Dict[str, Any]):
        """Broadcast new alert event notification."""
        payload = {
            "type": "ALERT_CREATED",
            "data": alert_dict,
        }
        await self.broadcast(payload)

    async def broadcast_incident(self, incident_dict: Dict[str, Any]):
        """Broadcast incident status update notification."""
        payload = {
            "type": "INCIDENT_UPDATED",
            "data": incident_dict,
        }
        await self.broadcast(payload)


ws_manager = ConnectionManager()
