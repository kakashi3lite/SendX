# Data Model

## SecretRecord
Stored secrets use a simple schema defined in `storage.py`.

| Field | Type | Description |
|-------|------|-------------|
| `ciphertext` | `str` | Base64-encoded encrypted payload |
| `iv` | `str?` | Optional AES-GCM IV when provided |
| `exp` | `int` | Expiration timestamp (UNIX seconds) |
| `consumed` | `bool` | Marked true once retrieved |

No additional metadata or user identifiers are persisted.
