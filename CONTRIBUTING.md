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
`pefile`, `psutil`, and `httpx`. The dashboard uses the standard library only —
please don't add a web framework.

## Before you open a pull request

- `pytest -q` passes.
- New behavior has a test where practical (see `tests/`).
- YARA rule changes: verify they don't fire on large legitimate binaries. The
  command/script rules are guarded with `filesize < 2MB` for exactly this reason.
- Keep the CLI and dashboard in sync when you add a capability to the core.
- Match the existing code style (type hints, docstrings that explain *why*).

## Accessibility

The dashboard targets **WCAG 2.1 AA**. If you touch the UI, preserve keyboard
navigation, focus visibility, ARIA roles/live-regions, color contrast in both
themes, and `prefers-reduced-motion`.

## Commit messages

Write a clear subject line and a body explaining the change. Reference issues
where relevant (`Fixes #12`).

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
