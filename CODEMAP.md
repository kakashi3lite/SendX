# Code Map

```
/ (Python)
├── main.py              # FastAPI application, routes and middleware
├── storage.py           # Storage abstraction with in-memory/Redis backends
├── ai_security.py       # AI security middleware and utilities
├── templates/           # Jinja2 templates for index and view pages
├── static/              # Static assets (JS/CSS)
├── docs/                # Additional project documentation
├── Dockerfile           # Container build
├── docker-compose.yml   # Local orchestration with optional Redis
└── .github/workflows/ci-cd.yml # CI for lint, test, Docker build
```

## Ownership
- Default maintainer: `@kakashi3lite`

## Entrypoints
- `main.py` with `uvicorn main:app`
- `create_release_*` scripts for packaging assets

## Data Flow
1. Client submits encrypted payload to API.
2. `main.py` validates and sends to `storage.py` backend.
3. Retrieval endpoints fetch and delete secrets.
4. AI security middleware inspects payloads before storage.
