Docker Compose for SentinelX development environment."""

from docker_compose_builder import DockerComposeBuilder

compose = DockerComposeBuilder(version="3.8")

# PostgreSQL
compose.add_service(
    name="postgres",
    image="postgres:16-alpine",
    ports=["5432:5432"],
    environment={
        "POSTGRES_DB": "sentinelx",
        "POSTGRES_USER": "sentinelx",
        "POSTGRES_PASSWORD": "SentinelX!DB2026",
    },
    volumes=["postgres_data:/var/lib/postgresql/data"],
    healthcheck={"test": ["CMD-SHELL", "pg_isready -U sentinelx"], "interval": "10s", "timeout": "5s", "retries": 5},
    restart="always",
)

# Redis
compose.add_service(
    name="redis",
    image="redis:7-alpine",
    ports=["6379:6379"],
    healthcheck={"test": ["CMD", "redis-cli", "ping"], "interval": "10s", "timeout": "5s", "retries": 5},
    restart="always",
)

# OpenSearch
compose.add_service(
    name="opensearch",
    image="opensearchproject/opensearch:2.12.0",
    ports=["9200:9200", "9600:9600"],
    environment={
        "discovery.type": "single-node",
        "OPENSEARCH_INITIAL_ADMIN_PASSWORD": "OpenSearch!2026",
        "plugins.security.disabled": "true",
        "ES_JAVA_OPTS": "-Xms512m -Xmx512m",
    },
    volumes=["opensearch_data:/usr/share/opensearch/data"],
    healthcheck={"test": ["CMD", "curl", "-f", "http://localhost:9200/_cluster/health"], "interval": "15s", "timeout": "5s", "retries": 10},
    restart="always",
)

# Backend (will be overridden by Dockerfile)
compose.add_service(
    name="backend",
    build={"context": "../backend", "dockerfile": "Dockerfile"},
    ports=["8000:8000"],
    environment={
        "DATABASE_URL": "postgresql://sentinelx:SentinelX!DB2026@postgres:5432/sentinelx",
        "REDIS_URL": "redis://redis:6379/0",
        "OPENSEARCH_URL": "http://opensearch:9200",
        "JWT_SECRET": "${JWT_SECRET:-dev-jwt-secret-change-in-production}",
        "JWT_REFRESH_SECRET": "${JWT_REFRESH_SECRET:-dev-refresh-secret-change-in-production}",
        "ENVIRONMENT": "development",
        "DEMO_MODE": "true",
    },
    depends_on={"postgres": {"condition": "service_healthy"}, "redis": {"condition": "service_healthy"}, "opensearch": {"condition": "service_healthy"}},
    volumes=["./backend:/app", "/app/venv"],
    restart="unless-stopped",
)

# Frontend
compose.add_service(
    name="frontend",
    build={"context": "../frontend", "dockerfile": "Dockerfile"},
    ports=["3000:3000"],
    environment={"NEXT_PUBLIC_API_URL": "http://localhost:8000/api/v1"},
    depends_on={"backend": {"condition": "service_started"}},
    restart="unless-stopped",
)

# Nginx
compose.add_service(
    name="nginx",
    image="nginx:alpine",
    ports=["80:80", "443:443"],
    volumes=["./infrastructure/nginx/nginx.conf:/etc/nginx/nginx.conf:ro"],
    depends_on={"frontend": {"condition": "service_started"}, "backend": {"condition": "service_started"}},
    restart="unless-stopped",
)

# Prometheus
compose.add_service(
    name="prometheus",
    image="prom/prometheus:latest",
    ports=["9090:9090"],
    volumes=["./infrastructure/prometheus/prometheus.yml:/etc/prometheus/prometheus.yml:ro"],
    restart="unless-stopped",
)

# Grafana
compose.add_service(
    name="grafana",
    image="grafana/grafana:latest",
    ports=["3001:3000"],
    environment={"GF_SECURITY_ADMIN_PASSWORD": "Grafana!2026"},
    volumes=["grafana_data:/var/lib/grafana"],
    depends_on={"prometheus": {"condition": "service_started"}},
    restart="unless-stopped",
)

# Volumes
compose.add_volume("postgres_data")
compose.add_volume("opensearch_data")
compose.add_volume("grafana_data")

# Networks
compose.add_network("sentinelx_network")

# Generate
compose.generate("docker-compose.yml")