# Changelog

All notable changes to Warden are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/ForrestLasiter/warden/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/ForrestLasiter/warden/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ForrestLasiter/warden/releases/tag/v0.1.0
