# Releasing Warden

For maintainers. A release is a version tag; everything else is automated by
`.github/workflows/release.yml`.

## 1. Before tagging

1. **Version** — bump it in both places (they must match):
   - `warden/__init__.py` → `__version__`
   - `pyproject.toml` → `[project] version`
2. **Changelog** — move the `Unreleased` notes in `CHANGELOG.md` under a new
   `## [x.y.z] - YYYY-MM-DD` heading.
3. **Dependencies changed?** Regenerate the hash-locked build requirements:
   ```bash
   uv pip compile --universal --generate-hashes --no-annotate \
       requirements-release.in -o requirements-release.txt
   pip-audit --require-hashes --disable-pip -r requirements-release.txt
   ```
4. **Checks** — the same ones CI runs:
   ```bash
   pip install -e ".[dev]"
   ruff check .
   mypy --platform linux warden && mypy --platform win32 warden && mypy --platform darwin warden
   bandit -q -r warden -c pyproject.toml
   pytest -q --cov --cov-fail-under=70
   shellcheck scripts/*.sh
   pwsh -c "Invoke-ScriptAnalyzer -Path scripts -Recurse -Settings scripts/PSScriptAnalyzerSettings.psd1"
   ```
5. Merge to `main` through a pull request with CI green on every platform.

## 2. Tag

```bash
git switch main && git pull
git tag -a v0.5.0 -m "Warden 0.5.0"
git push origin v0.5.0
```

Release tags (`v*`) are protected by a repository ruleset: they cannot be moved
or deleted once pushed. A bad release is fixed by a new patch version, never by
re-tagging.

## 3. What the workflow produces

| Asset | Built on |
| --- | --- |
| `warden-windows-x64.exe` | `windows-latest` |
| `warden-linux-x64` | `ubuntu-latest` |
| `warden-linux-arm64` | `ubuntu-24.04-arm` |
| `warden-macos-arm64` | `macos-latest` (Apple Silicon) |
| `warden-macos-x64` | `macos-15-intel` |
| `SHA256SUMS`, `SHA256SUMS.sig`, `SHA256SUMS.pem` | checksums + Sigstore keyless signature |
| `warden.spdx.json`, `warden.cdx.json` | SBOMs |

Each build installs dependencies with `pip install --require-hashes`, runs
PyInstaller, and **smoke-tests the binary** (version, engine status, offline
privacy report, key generation — which proves the crypto library is bundled —
self-inspection, and a clean scan) before it is uploaded. SLSA build provenance
is attested for every binary. All third-party Actions are pinned to commit SHAs.

## 4. After the workflow finishes

1. Verify the release as a user would:
   ```bash
   gh release download v0.5.0 --dir /tmp/warden-0.5.0
   scripts/verify-release.sh /tmp/warden-0.5.0
   ```
   (see [VERIFY.md](VERIFY.md) for what it checks).
2. Run each installer on a clean machine/VM if the installer changed:
   - Windows: `irm …/install.ps1 | iex`, then double-click the Desktop shortcut.
   - Linux/macOS: `curl -fsSL …/install.sh | sh`, then `warden version`.
3. Edit the GitHub Release notes (paste the changelog section).

## 5. Platform notes

- **No paid code signing.** Binaries are not Authenticode-signed and not
  Apple-notarized. Windows SmartScreen shows "unrecognized app" and macOS
  Gatekeeper blocks the first launch (right-click → Open, or
  `xattr -d com.apple.quarantine warden`). The README says so; integrity is
  provided by the checksum, the Sigstore signature and provenance instead.
- **Windows on ARM** uses the x64 build under emulation (`yara-x` publishes no
  Windows ARM64 wheel). The installer says so when it detects ARM64.
- **Other platforms** (32-bit, musl/Alpine, BSD): run from source —
  `pip install .` needs a `yara-x` wheel or a Rust toolchain.

## 6. If a release is bad

1. Mark the GitHub Release as a pre-release (or delete the *release*, not the
   tag) so `releases/latest` stops serving it to the installers.
2. Fix forward: publish `x.y.(z+1)`.
3. If the problem is a security issue, publish a GitHub Security Advisory.
