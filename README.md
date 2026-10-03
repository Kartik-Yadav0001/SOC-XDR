## SentinelX Enterprise SOC & XDR Platform

This is a functional cybersecurity platform for Security Operations Centers (SOC) and Extended Detection & Response (XDR).

## Sprint 1 — Foundation

**What was built:**
- Complete repository structure
- Docker Compose with PostgreSQL, Redis, OpenSearch, Nginx, Prometheus, Grafana
- FastAPI application with health endpoint
- SQLAlchemy models: User, Endpoint, SecurityEvent, Alert, Incident, Indicator, IncidentTimeline, AuditLog
- Configuration system with environment variables
- Structured JSON logging
- Pydantic schemas for API validation
- Alert service, Incident service, Event service
- Detection engine with 8 detection rules (DETECTION-001 through DETTECTION-008)
- Database initialization with seed users

**Seed users:**
| Username | Role | Password |
|---|---|---|
| superadmin | SUPER_ADMIN | AdminSentinelX!2026 |
| soc_manager | SOC_MANAGER | ManagerSentinelX!2026 |
| soc_analyst | SOC_ANALYST | AnalystSentinelX!2026 |
| incident_responder | INCIDENT_RESPONDER | IRSentinelX!2026 |
| viewer | VIEWER | ViewerSentinelX!2026 |

## Running the Platform

```bash
# Start all services
docker compose up -d

# Check health
curl http://localhost/api/v1/health

# Access API docs
http://localhost/docs

# Access Grafana
http://localhost:3001 (admin / Grafana!2026)
```

## Architecture
- **Backend:** FastAPI + SQLAlchemy + PostgreSQL + Redis
- **Frontend:** Next.js (planned for Sprint 9)
- **Detection:** Rule-based engine with 8 initial detections
- **Storage:** PostgreSQL (relational), OpenSearch (telemetry/search)
- **Monitoring:** Prometheus + Grafana