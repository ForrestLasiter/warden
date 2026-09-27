# Changelog

All notable changes to Warden are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ForrestLasiter/warden/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/ForrestLasiter/warden/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/ForrestLasiter/warden/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ForrestLasiter/warden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ForrestLasiter/warden/releases/tag/v0.1.0
