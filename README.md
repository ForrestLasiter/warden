<div align="center">

<img src="assets/logo.svg" alt="Warden" width="300">

### Open-source, on-demand malware scanner for Windows, Linux & macOS

No subscription. No telemetry. No lock-in.

[![CI](https://github.com/ForrestLasiter/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/ForrestLasiter/warden/actions/workflows/ci.yml)
[![Release binaries](https://github.com/ForrestLasiter/warden/actions/workflows/release.yml/badge.svg)](https://github.com/ForrestLasiter/warden/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Latest release](https://img.shields.io/github/v/release/ForrestLasiter/warden?sort=semver)](https://github.com/ForrestLasiter/warden/releases)

[**Download**](#download) · [**Quickstart**](#quickstart) · [**Dashboard**](#dashboard) · [**How it works**](#how-it-works) · [**Docs**](#usage)

</div>

---

Warden scans a file, a folder, or your whole drive and tells you what looks
malicious — using [YARA](https://virustotal.github.io/yara/) rules, structural
heuristics, hash reputation, and (optionally) [ClamAV](https://www.clamav.net/).
It ships as a clean command-line tool **and** an accessible local web dashboard.

> **Warden is a second opinion you own.** It's an *on-demand* scanner, not a
> real-time resident antivirus, and it's **not a replacement for Microsoft
> Defender** (which is free and built into Windows — keep it on). Warden is for
> people who want to inspect their system with a transparent tool they control.

<div align="center">
<img src="docs/images/dashboard-dark.png" alt="Warden dashboard showing a scan with flagged files" width="49%">
<img src="docs/images/dashboard-light.png" alt="Warden scan history in light mode" width="49%">
</div>

## Download

Grab a standalone binary — **no Python required** — from the
[**Releases**](https://github.com/ForrestLasiter/warden/releases/latest) page, or
install with one line:

**Windows** (PowerShell):
```powershell
irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 | iex
```

**Linux / macOS**:
```bash
curl -fsSL https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.sh | sh
```

| Platform | File |
| --- | --- |
| Windows x64 | `warden-windows-x64.exe` |
| Linux x64 | `warden-linux-x64` |
| macOS (Apple Silicon) | `warden-macos-arm64` |

On first run Windows SmartScreen may warn about an unsigned binary — Warden is
unsigned, and the source is right here for you to build yourself.

## Quickstart

```bash
warden gui                          # open the dashboard (easiest)
warden scan ~/Downloads             # scan a folder from the terminal
warden sweep                        # auto-scan where malware hides
```

## What it detects

Warden runs every file past up to four independent engines and reports the worst
verdict, rated **Info → Low → Medium → High → Critical**:

| Engine | What it does | Requires |
| --- | --- | --- |
| **YARA** | Rule-based pattern matching (VirusTotal's `yara-x`). Ships with starter rules; drop in community packs. | built in |
| **Heuristics** | Structural red flags: fake double extensions (`invoice.pdf.exe`), packed PE sections, risky imports, obfuscated scripts, high entropy. | built in |
| **Hash reputation** | SHA-256 against a local known-bad list (feed it MalwareBazaar exports). | built in |
| **ClamAV** | Millions of signatures via `clamscan`/`clamdscan`. | optional — install ClamAV |

## Dashboard

`warden gui` opens a local dashboard (bound to `127.0.0.1`, protected by a
per-session token) for scans, sweeps, history, and quarantine — with live
progress and one-click isolation. It's built to **WCAG 2.1 AA**: full keyboard
navigation, visible focus, ARIA roles and live regions, `prefers-reduced-motion`,
and a **light / dark / system** theme toggle that remembers your choice. No
Electron, no dependencies beyond the Python standard library.

## Usage

```bash
warden scan <path>                   # scan a file or folder
warden scan C:\ --min-severity high  # scan a whole drive, only loud findings
warden scan .\Downloads --quarantine # scan, then offer to isolate anything flagged
warden scan .\Downloads --json out.json --save   # machine-readable + saved to history

warden sweep                         # scan autoruns, processes, tasks, Temp, Downloads
warden sweep --quick                 # faster: top-level temp/downloads + executables only

warden quarantine list               # see isolated files
warden quarantine restore <id>       # put one back
warden quarantine delete <id>        # permanently remove (asks first)

warden history list                  # past scans/sweeps
warden history show <id>             # threats from a saved report

warden schedule add nightly --kind sweep --frequency daily --at 03:00
warden schedule list
warden schedule remove nightly

warden status                        # which engines are active
warden update-rules                  # how to add YARA rules & hash feeds
```

`warden scan` / `warden sweep` exit **1** when any Medium+ threat is found and
**0** when clean — handy for scripts and scheduled runs.

## How it works

Each file is inspected once — read into memory and hashed a single time — then
passed to every available engine. Findings are aggregated into a verdict per file
and a report per scan. The same core powers the CLI, the sweep, the scheduler,
and the dashboard.

- **On-demand, not resident.** No kernel driver, no background hooks. Warden runs
  when you ask it to. This is a deliberate design choice: real-time protection is
  what Defender already does well.
- **Safe by default.** Quarantine never runs a file and never hard-deletes
  without explicit confirmation. Quarantined copies are XOR-neutralized so they
  can't execute, and restore is byte-for-byte identical.
- **Private.** Nothing leaves your machine. Online hash lookups are opt-in and
  off by default.

## Adding detection content

Drop files into `~/.warden/rules/` (`C:\Users\<you>\.warden\rules\` on Windows):

- `*.yar` / `*.yara` — extra YARA rules. Great sources:
  [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
  [Yara-Rules/rules](https://github.com/Yara-Rules/rules).
- `malware_hashes.txt` — one SHA-256 per line (`hash  optional-label`). Export
  from [MalwareBazaar](https://bazaar.abuse.ch/).

Rule severity comes from a `severity` metadata field on each rule
(`"low"`–`"critical"`). For the full ClamAV signature set, install ClamAV, run
`freshclam`, and Warden picks it up automatically.

## Testing it works (safely)

Use the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) —
a harmless, industry-standard string every scanner flags. Warden ships a YARA
rule for it.

> ⚠️ Windows Defender deletes an EICAR file the instant it's written to disk. To
> test on-disk detection, create it in a Defender-excluded folder, or trust the
> bundled unit test which checks the pattern in memory.

## Install (dev)

```bash
git clone https://github.com/ForrestLasiter/warden
cd warden
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Unix:     source .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

Build a standalone binary yourself:

```bash
pip install pyinstaller
pyinstaller packaging/warden.spec --noconfirm   # -> dist/warden(.exe)
```

## Roadmap

- [x] On-demand file/folder scan (YARA + heuristics + hash + ClamAV)
- [x] Safe, reversible quarantine
- [x] System sweep (autoruns, processes, scheduled tasks, Temp, Downloads)
- [x] Scheduled scans with saved history
- [x] Accessible web dashboard (WCAG 2.1 AA, light/dark)
- [x] Standalone Windows/Linux/macOS binaries on the Releases page
- [ ] Opt-in online hash reputation lookup
- [ ] Signed binaries (quiet SmartScreen / Gatekeeper)
- [ ] ARM64 Linux builds

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). New YARA
rules under `warden/rules/` are especially valuable. Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) and report security issues per our
[Security policy](SECURITY.md).

## License

[MIT](LICENSE). Warden bundles no third-party signatures; ClamAV and any rule
packs you add carry their own licenses.
