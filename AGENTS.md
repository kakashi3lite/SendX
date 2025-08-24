# Agent Handbook

## Repository Overview
- **Language:** Python 3.11+
- **Framework:** FastAPI
- **Package manager:** `pip` / `pyproject.toml`

## Directory Structure
- `main.py` – FastAPI application and API endpoints
- `storage.py` – pluggable storage backends
- `ai_security.py` – AI security middleware
- `templates/` – HTML templates
- `static/` – front-end assets
- `docs/` – additional documentation

## Coding Standards
- Format Python with **Black** (line length 88)
- Lint with **flake8** (max line length 127)
- Prefer async/await and type hints
- Use environment variables for secrets and config

## Build & Test
- Install: `pip install -r requirements.txt`
- Lint: `flake8 .`
- Test: `pytest`
- Run dev server: `uvicorn main:app --reload`

## Prompt Patterns
1. State the task and target file paths explicitly.
2. Provide before/after examples when modifying code.
3. Run lint and tests after changes and include outputs.

## Notes
- Use `rg` (ripgrep) for code search.
- Avoid committing secrets or credentials.
