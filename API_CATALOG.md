# API Catalog

| Method | Path | Description | Request | Response | Auth | Rate Limit |
|--------|------|-------------|---------|----------|------|------------|
| GET | `/` | Render index page | n/a | HTML | None | n/a |
| GET | `/view` | Render secret view page | query `id` | HTML | None | n/a |
| POST | `/api/create` | Create secret | `{ciphertext, ttl}` | `{success, secret_id, expires_in_hours}` | None | 10/min IP |
| GET | `/api/secret/{secret_id}` | Retrieve and delete secret | path `secret_id` | `{success, ciphertext}` | None | 20/min IP |
| GET | `/api/qr/{secret_id}` | QR code for secret URL | path `secret_id` | PNG stream | None | 5/min IP |
| GET | `/api/health` | Service health info | n/a | status JSON | None | unlimited |

Requests/Responses are JSON unless noted. All endpoints served over HTTPS.
