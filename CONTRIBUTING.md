# Contributing to Warden

Thanks for your interest in improving Warden! This project welcomes bug reports,
feature ideas, detection rules, and code.

## Ways to contribute

- **Report a bug** or request a feature via [issues](https://github.com/ForrestLasiter/warden/issues) (templates provided).
- **Add detection content** — new YARA rules under `warden/rules/` are among the
  most valuable contributions. Keep them conservative (low false-positive) and
  set a `severity` metadata field.
- **Improve heuristics, the sweep, or the dashboard.**
- **Report a security issue** — see [SECURITY.md](SECURITY.md). Please don't file
  vulnerabilities as public issues.

## Development setup

```bash
git clone https://github.com/ForrestLasiter/warden
cd warden
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Warden targets **Python 3.10+** and depends only on `yara-x`, `typer`, `rich`,
`pefile`, `psutil`, `httpx`, and `cryptography`. The dashboard uses the standard
library only — please don't add a web framework.

## Before you open a pull request

Run what CI runs:

```bash
ruff check .
mypy --platform linux warden && mypy --platform win32 warden && mypy --platform darwin warden
bandit -q -r warden -c pyproject.toml
pytest -q --cov
```

- All of the above pass.
- New behavior has a test (see `tests/`). Anything that parses untrusted input —
  a file format, a state file, a request — also gets a property test in
  `tests/test_fuzz.py` asserting it never raises and stays within its bounds.
- **Fail closed.** If something can't be checked, the scan must say so
  (`unknown` / incomplete, exit 2) — never report clean.
- **No new network calls** outside `warden/net.py`, and none that happen without
  the user opting in. No telemetry, ever.
- Don't shell out with a shell, and never put a file name into a command string.
- Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) if your change touches the
  scanner, quarantine, dashboard, scheduler, rule packs or the release pipeline.
- YARA rule changes: verify they don't fire on large legitimate binaries. The
  command/script rules are guarded with `filesize < 2MB` for exactly this reason.
- Keep the CLI and dashboard in sync when you add a capability to the core.
- Match the existing code style (type hints, docstrings that explain *why*).

## Accessibility

The dashboard conforms to **WCAG 2.1 AA** ([docs/ACCESSIBILITY.md](docs/ACCESSIBILITY.md)).
If you touch the UI, preserve keyboard navigation, focus visibility, ARIA
roles/live-regions, color contrast in **both** themes, and
`prefers-reduced-motion`.

- `pytest tests/test_accessibility.py` recomputes every colour pair from
  `style.css` for both themes. If you add a colour combination, add it to the
  pair list there. Use the `--*-solid` tokens for filled controls with white
  text; the plain `--accent` / `--danger` are for text and icons.
- Before a UI change is merged, run the browser audit
  (`python packaging/a11y_audit.py <axe.min.js>`) - it must report 0 violations.
- Never put important information only in the toast; it disappears. The page runs under a strict
Content-Security-Policy: no inline scripts, styles or event handlers, and
untrusted text goes in with `textContent`, never `innerHTML`.

## Commit messages

Write a clear subject line and a body explaining the change. Reference issues
where relevant (`Fixes #12`).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
