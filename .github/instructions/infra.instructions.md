---
applyTo: "{Dockerfile,docker-compose.yml,.github/workflows/**}"
---
- Use minimal base images and pin versions.
- Avoid embedding secrets; use GitHub Secrets or env vars.
- Keep CI jobs idempotent and fast; reuse caching where possible.
