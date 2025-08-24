# Test Matrix

## Frameworks
- **pytest** – unit and integration tests
- **flake8** – linting (style and syntax)

## Current Status
- No test files present; `pytest` collects 0 tests.
- Linting reports numerous style issues and a syntax error in `main.py`.

## Suggested Coverage
| Area | Suggested Tests |
|------|-----------------|
| Storage | Unit tests for `put`, `get_once`, and `ttl` across backends |
| API | Integration tests for create/retrieve flow and QR generation |
| Security | Tests verifying AI security middleware blocks malicious payloads |
| Rate Limiting | Ensure limits return `429` after threshold |
| Error Paths | Invalid secret IDs, expired secrets, oversized payloads |

Add tests under a `/tests` directory with fixtures for in-memory storage and mocked Redis.
