# Security Overview

## ASVS Level 2 Checklist
| Control | Status | Notes |
|---------|--------|-------|
| Authentication (2.1) | N/A | Public API uses secret URLs instead of user auth |
| Session Management (2.2) | N/A | No sessions maintained |
| Access Control (4.1) | Pass | Rate limits and one-time secret access enforced in `main.py` |
| Input Validation (5.1) | Gap | Lacks centralized validation; lint reports syntax errors |
| Output Encoding (5.3) | Pass | Strict CSP and security headers in `main.py` |
| Cryptographic Storage (6.4) | Pass | Secrets encrypted client-side; server stores ciphertext only |
| Error Handling (10.3) | Gap | Generic 500 responses; limited logging for storage errors |
| Logging & Monitoring (10.5) | Gap | No centralized logging or alerting configured |
| Data Protection (9.1) | Pass | TTL and one-time retrieval delete data |
| Communications Security (9.2) | Pass | HTTPS assumed; HSTS header set |
| Configuration (12.1) | Gap | No enforcement of secure defaults for `STORAGE_TYPE` or `HMAC_KEY` |
| Dependency Management (14.2) | Gap | No automated vulnerability scanning |
| Security Testing (16.1) | Gap | No tests covering security middleware |

## Secret Handling
- Secrets are stored encrypted with TTL and consumed on first read.
- Environment variables (`HMAC_KEY`, `STORAGE_TYPE`, `REDIS_URL`) control cryptographic operations.

## Hotspots
- `ai_security.py` contains large regex patterns; ensure updates are reviewed for ReDoS.
- `main.py` SyntaxError prevents linting; fix to maintain CI integrity.
