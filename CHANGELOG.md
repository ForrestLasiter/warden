# Changelog

All notable changes to Warden are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.4] - 2026-09-28

### Changed
- **Double-clicking the packaged Windows binary now opens the dashboard.**
  Previously a double-click just flashed a console window and closed (Warden is a
  CLI, so with no arguments it printed help and exited). When the exe is launched
  from Explorer with no arguments it now starts `warden gui`; run from a terminal
  (or with arguments) it still behaves as a normal CLI. On an error it keeps the
  window open so the message is readable.

## [0.4.3] - 2026-09-28

### Supply chain
- **Pinned all third-party GitHub Actions to commit SHAs** (checkout, setup-python,
  upload/download-artifact, action-gh-release) so a moved tag can't inject code.
- **Hash-locked, version-pinned build dependencies** in `requirements-release.txt`
  (a universal `uv pip compile --generate-hashes` lock covering all four target
  platforms). The release workflow installs with `pip install --require-hashes`
  then `pip install --no-deps .`, so a compromised or broken upstream dependency
  release can't enter a published binary.

## [0.4.2] - 2026-09-27

Second adversarial code-review pass — the issues that survived the first review.

### Security
- **Executable-hijack fix:** PowerShell (signature checks) and `schtasks` are now
  invoked by absolute system path, so a `powershell.exe`/`schtasks.exe` planted in
  the working directory can't be run instead (a conditional local RCE the first
  pass left open by fixing only argument injection).
- **Quarantine TOCTOU closed:** the file is hashed **as it is copied** and the
  operation aborts unless those bytes match the scan hash — the stored copy
  provably corresponds to the detection. Quarantine now **fails closed** when the
  scan hash is missing instead of proceeding unvalidated.
- **Concurrency:** quarantine index and schedule registry updates are serialized
  with a cross-platform file lock, so concurrent operations can't lose each
  other's update.

### Correctness
- Engine **load** failures (e.g. a YARA ruleset that won't compile) now mark the
  scan degraded (`warnings`, exit 2) instead of silently reducing coverage.
- **System sweep** now extracts interpreter-hosted payloads (`wscript evil.vbs`,
  `rundll32 evil.dll,Run`, `powershell -File …`) instead of only the signed
  interpreter — closing a class of missed script/DLL persistence.
- Dashboard **`min_severity`** is now validated (400 on invalid) and actually
  applied as the client-side result filter.
- Scheduled scans pass the target after `--` and as an absolute path (no CLI
  arg-injection, no wrong-CWD resolution); `schedule remove` cleans orphaned OS
  tasks.

### Reliability / performance
- Content-skipped files (media/VM images) are no longer fully hashed.
- Malformed `Content-Length` → clean 400; string booleans in config are coerced.

### Supply chain
- Releases now publish `SHA256SUMS`; the one-line installers verify the download
  against it before installing.

## [0.4.1] - 2026-09-27

### Added
- **ARM64 Linux binaries** (`warden-linux-arm64`) built on GitHub's ARM runners
  and published to Releases; `install.sh` now serves them for aarch64. CI also
  runs on ARM64 Linux.

### Removed
- Dropped the "signed binaries" roadmap item (code-signing certificates are a
  paid service and out of scope for this project).

## [0.4.0] - 2026-09-27

Security & reliability hardening from a full code review. No breaking changes to
the CLI surface; new exit code `2` means "a file could not be fully scanned."

### Security
- **Fixed a PowerShell command injection** in the system sweep: a crafted
  filename (e.g. in Downloads/Temp) could execute code during `warden sweep`.
  The path is now passed via an environment variable, never interpolated.
- **Fixed a crontab command injection** in the scheduler: schedule target/name
  are now shell-quoted and strictly validated (also blocks Windows task-namespace
  traversal and cron-line injection via newlines).
- **Hardened the dashboard:** `Host`-header validation (blocks DNS rebinding),
  constant-time token compare, 1 MiB body cap, concurrent-job cap, strict
  history-id validation, robust static-path containment, and quarantine by
  server-side `{job,index}` handle instead of a client-supplied path (removes an
  arbitrary-file-deletion vector).
- **Config secrets:** `~/.warden` and `config.json` (which holds the VirusTotal
  key) are created owner-only (0o700/0o600) on POSIX.

### Reliability / correctness
- **Detection now fails safe:** an engine that errors marks the file `unknown`
  (never `clean`); ClamAV exit code 2 is treated as an error, not clean; scans
  exit non-zero when a file couldn't be fully scanned.
- **Durable quarantine:** neutralized copy is fsync'd and the original removed
  last; the file is re-validated (hash/symlink) before removal; restore refuses
  to overwrite or follow symlinks; a corrupt index rebuilds from sidecars.
- **Atomic writes** (temp + fsync + rename) for config, quarantine index,
  schedules, history, and the reputation cache; malformed config no longer
  crashes Warden; reputation cache entries expire so stale negatives can't mask
  new malware.
- Content and hash now come from a single consistent read for in-memory files.

### Performance
- Bounded pefile parsing and script-token scanning on large files.

## [0.3.3] - 2026-09-27

### Added
- Overview **empty state**: before the first scan, the dashboard shows a shield
  illustration, a short intro, and one-click actions instead of blank cards.

### Changed
- Regenerated screenshots and the screenshot script's demo path to use a neutral
  `C:\Users\Public\WardenDemo` location (no personal username in public images).

## [0.3.2] - 2026-09-27

### Changed
- **Redesigned dashboard** into a proper app shell: a persistent sidebar with
  icon navigation, an **Overview** landing page with stat cards (engines active,
  scans run, threats, quarantined) and a recent-activity feed, and quick-action
  tiles. Everything is now card-based with clear dividers and visual hierarchy
  instead of a single centered form. Fully responsive (sidebar collapses to a
  top bar on small screens) and still WCAG 2.1 AA. Refreshed screenshots.

## [0.3.1] - 2026-09-27

### Added
- `warden config` command group to view and change settings without hand-editing
  JSON: `show`, `get` (`--reveal`), `set`, `unset`, `path`, and `set-vt-key`
  (hidden prompt so the key stays out of shell history; enables online lookups
  by default). Secret values are masked in output.

## [0.3.0] - 2026-09-27

### Added
- **Opt-in online hash reputation.** `warden lookup <file|hash>` checks a single
  file or hash; `--online` enriches any scan or sweep. Two providers, chosen
  automatically: Team Cymru's Malware Hash Registry (keyless, over DNS-over-HTTPS)
  and VirusTotal (optional free API key via `WARDEN_VT_API_KEY` or config).
  Results are cached in `~/.warden/cache/`; every lookup is off by default and
  sends only a hash, never the file.
- Dashboard scan form gained an "Check hashes online" opt-in toggle.
- `ScanContext` now computes SHA-1 alongside SHA-256 in a single pass.

### Changed
- Enabled GitHub Discussions.

## [0.2.0] - 2026-09-27

### Added
- Brand identity: shield logo, app icon on the Windows binary, favicon and
  logo in the dashboard, and a dashboard footer showing the version.
- One-line installers for Windows (`install.ps1`) and Linux/macOS (`install.sh`)
  that fetch the right binary from the latest release.
- Community health files: Contributing guide, Security policy, Code of Conduct,
  issue/PR templates, and this changelog.
- Documentation: screenshots and an overhauled README.

### Changed
- Default branch renamed from `master` to `main`.
- Normalized line endings across the repo via `.gitattributes`.

## [0.1.0] - 2026-09-27

### Added
- On-demand scanning of files and folders with four engines: YARA (yara-x),
  structural heuristics, local SHA-256 hash reputation, and optional ClamAV.
- Safe, reversible quarantine (XOR-neutralized storage; never hard-deletes
  without confirmation).
- System sweep of autoruns, running processes, scheduled tasks, Temp, and
  Downloads, with an unsigned-executable-in-writable-location heuristic.
- Scheduled scans via Windows Task Scheduler / Unix crontab, plus saved scan
  history.
- Accessible web dashboard (`warden gui`) — WCAG 2.1 AA, light/dark/system theme.
- Standalone Windows/Linux/macOS binaries published to GitHub Releases via CI.

[Unreleased]: https://github.com/ForrestLasiter/warden/compare/v0.4.4...HEAD
[0.4.4]: https://github.com/ForrestLasiter/warden/compare/v0.4.3...v0.4.4
[0.4.3]: https://github.com/ForrestLasiter/warden/compare/v0.4.2...v0.4.3
[0.4.2]: https://github.com/ForrestLasiter/warden/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/ForrestLasiter/warden/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/ForrestLasiter/warden/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/ForrestLasiter/warden/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/ForrestLasiter/warden/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/ForrestLasiter/warden/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ForrestLasiter/warden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ForrestLasiter/warden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ForrestLasiter/warden/releases/tag/v0.1.0
