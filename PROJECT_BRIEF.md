# Project Brief

SendX is a zero-knowledge, one-time secret sharing service built with FastAPI. Users submit encrypted payloads that are stored temporarily and can be retrieved exactly once. The server never sees plaintext and enforces automatic expiration, AI security scanning, and rate limiting.

## Domain & Purpose
- Secure transfer of sensitive information using client-side encryption.
- Secrets are deleted after first retrieval or when their TTL expires.

## Key Flows
1. **Create secret** – client POSTs ciphertext and TTL; server stores and returns secret ID.
2. **Retrieve secret** – client GETs `/api/secret/{id}` to fetch and invalidate.
3. **Generate QR** – optional QR code for sharing secret URLs.
4. **Health check** – system status at `/api/health`.

## Public Interfaces
- HTTP REST API via FastAPI.
- HTML templates served for `/` and `/view` pages.

See [API_CATALOG.md](API_CATALOG.md) for endpoint details and [CODEMAP.md](CODEMAP.md) for module layout.

## Environments
- **Development:** In-memory storage, run with `uvicorn main:app --reload`.
- **Production:** Docker container with Redis storage and AI security middleware enabled.
