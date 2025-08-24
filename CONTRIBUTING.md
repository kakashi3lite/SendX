# Contributing

We welcome pull requests!

## Development Workflow
1. Fork and clone the repository.
2. Create a virtualenv and install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install flake8 pytest
   ```
3. Run lint and tests before committing:
   ```bash
   flake8 .
   pytest
   ```
4. Commit using concise imperative messages (e.g., "fix: handle missing TTL").
5. Submit a Pull Request targeting `main`.

## Code Style
- Format with **Black** (line length 88).
- Keep imports sorted and remove unused ones.

## Issue Triage
- Use labels: `bug`, `enhancement`, `security`, `docs`.
