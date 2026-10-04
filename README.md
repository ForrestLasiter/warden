<div align="center">

<img src="assets/logo.svg" alt="Warden" width="300">

### Open-source, on-demand malware scanner for Windows, Linux & macOS

No subscription. No telemetry. No lock-in.

[![CI](https://github.com/ForrestLasiter/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/ForrestLasiter/warden/actions/workflows/ci.yml)
[![Release binaries](https://github.com/ForrestLasiter/warden/actions/workflows/release.yml/badge.svg)](https://github.com/ForrestLasiter/warden/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Latest release](https://img.shields.io/github/v/release/ForrestLasiter/warden?sort=semver)](https://github.com/ForrestLasiter/warden/releases)

[**Download**](#download) · [**Quickstart**](#quickstart) · [**Dashboard**](#dashboard) · [**How it works**](#how-it-works) · [**Docs**](#documentation)

</div>

---

Warden scans a file, a folder, or your whole drive and tells you what looks
malicious — using [YARA](https://virustotal.github.io/yara/) rules, structural
heuristics, document and archive inspection, hash reputation, and (optionally)
[ClamAV](https://www.clamav.net/). It ships as a clean command-line tool **and**
an accessible local web dashboard.

> ### Warden is not real-time antivirus
>
> Warden is an **on-demand** scanner: it checks files **when you ask it to** (or
> on a schedule you set). It does **not** watch your computer in the background,
> and it **cannot stop a malicious file from running**.
>
> **Keep your operating system's built-in protection turned on** — Microsoft
> Defender on Windows (free and already installed), XProtect on macOS. Warden is
> a second opinion you own and can read the source of, not a replacement.
>
> "Clean" means *nothing Warden knows about was found* — not that a file is safe.

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
| Windows x64 (also Windows on ARM, via built-in emulation) | `warden-windows-x64.exe` |
| Linux x64 | `warden-linux-x64` |
| Linux ARM64 | `warden-linux-arm64` |
| macOS, Apple Silicon | `warden-macos-arm64` |
| macOS, Intel | `warden-macos-x64` |

**Not comfortable with the command line?** Use the one-line installer above — it
puts a **"Warden" icon on your Desktop** (and Start Menu / applications menu).
Double-click it to open the dashboard in your browser; no terminal needed. When
you're finished, click **Quit Warden** in the page.

The installers verify the download against the release's `SHA256SUMS` and **stop
if it can't be verified**. Run one again at any time to **upgrade**; the previous
version is kept and comes back automatically if the new one won't start.

**Prefer to read a script before running it?** Download it, look, then run:

```bash
curl -fsSLO https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.sh
less install.sh
sh install.sh
```
```powershell
irm https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.ps1 -OutFile install.ps1
notepad .\install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Options (`sh install.sh --help`):

| Linux / macOS | Windows | |
| --- | --- | --- |
| `--install-dir DIR` | `-InstallDir DIR` | Install somewhere else |
| `--version v0.5.0` | `-Version v0.5.0` | A specific release instead of the latest |
| `--no-shortcuts` | `-NoShortcuts` | No Desktop / menu launcher |
| `--no-path` | `-NoPath` | Leave `PATH` alone |
| `--rollback` | `-Rollback` | Switch back to the previously installed version |
| `--uninstall` | `-Uninstall` | Remove Warden (your `~/.warden` data is kept) |
| `--allow-unverified` | `-AllowUnverified` | Install even if the checksum can't be fetched — not advised; a checksum *mismatch* is always refused |

With the one-liner, pass them like `… | sh -s -- --no-shortcuts`, or on Windows
set e.g. `$env:WARDEN_NO_SHORTCUTS=1` first.

> **You will see a warning the first time you run it.** Warden's binaries are
> **not** code-signed with a paid certificate, so Windows SmartScreen says
> "Windows protected your PC" (choose *More info → Run anyway*) and macOS says the
> developer cannot be verified (right-click the file → *Open*). That is expected.
> If you want proof the file is genuine, every release is checksummed, signed
> with [Sigstore](https://www.sigstore.dev/) and carries build provenance — see
> [Verifying a release](docs/VERIFY.md). Or build it yourself from this source.

Other systems (32-bit, Alpine/musl, BSD): [run from source](#install-dev).

## Quickstart

```bash
warden gui                          # open the dashboard (easiest)
warden scan ~/Downloads             # scan a folder from the terminal
warden sweep                        # auto-scan where malware hides
warden privacy                      # see exactly what Warden stores and sends
```

## What it detects

Warden runs every file past up to five independent engines and reports the worst
verdict, rated **Info → Low → Medium → High → Critical**:

| Engine | What it does | Requires |
| --- | --- | --- |
| **YARA** | Rule-based pattern matching (VirusTotal's `yara-x`). Ships with starter rules; add your own or install signed [rule packs](docs/RULE_PACKS.md). | built in |
| **Heuristics** | Fake double extensions (`invoice.pdf.exe`), obfuscated scripts, high entropy, and executable structure for **PE, ELF and Mach-O**: packer sections, writable+executable segments, risky imports, missing signatures. | built in |
| **Documents** | **Office macros** (legacy and modern formats: finds and decompresses VBA, flags auto-run macros that launch programs or download), remote-template injection, **PDF** JavaScript / launch actions / embedded files, **RTF** embedded objects. | built in |
| **Hash reputation** | SHA-256 against a local known-bad list, plus opt-in online lookups (see below). | built in |
| **ClamAV** | Millions of signatures via `clamscan`/`clamdscan`. Warden reports the signature database's age and warns when it is stale. | optional — install ClamAV |

It also looks **inside archives** — zip (and jar/docx/apk…), tar, tar.gz/bz2/xz,
gzip, bzip2, xz, nested up to three levels — entirely in memory, with hard limits
that defeat decompression bombs. A finding inside an archive names the member
(`bundle.zip!/docs/invoice.pdf.exe`).

For files it flags, Warden shows **what the file is** (format, architecture) and
**who signed it** (Authenticode publisher on Windows, `codesign` identity on
macOS), so you can tell a real threat from a false alarm on a signed program.

`warden inspect <file>` shows all of that for any file, without a verdict.

### System sweep

`warden sweep` gathers the places malware uses to start itself and to hide, then
scans them:

| Platform | What is swept |
| --- | --- |
| Windows | Registry Run/RunOnce keys, Startup folders, Scheduled Tasks (including the script or DLL an interpreter is told to run), running processes, Temp, Downloads |
| Linux | systemd units (system and user), cron (system, spool, your crontab), XDG autostart, shell start-up files, init scripts, `/etc/ld.so.preload`, running processes, `/tmp`, Downloads |
| macOS | LaunchAgents and LaunchDaemons, login items, cron and periodic scripts, shell start-up files, running processes, `/tmp`, Downloads |

Each start-up entry is also judged on *what it launches*: downloading and piping
to a shell, reverse-shell patterns, running from a world-writable folder, hidden
executables, library injection. On Linux and macOS, run the sweep with `sudo` for
full coverage — locations Warden could not read are listed, and the sweep is
reported incomplete rather than clean.

## Dashboard

`warden gui` opens a local dashboard for scans, sweeps, history, and quarantine —
with live progress, a **Cancel** button, and one-click isolation. It targets
**WCAG 2.1 AA** (self-assessed): keyboard navigation, visible focus, ARIA roles
and live regions, `prefers-reduced-motion`, and a **light / dark / system** theme
toggle. No Electron, no dependencies beyond the Python standard library.

**It is local-only.** The server binds to `127.0.0.1` and refuses any other
address; other devices on your network cannot reach it. It validates the `Host`
header (blocks DNS rebinding), requires a per-session token on every API call,
refuses cross-origin requests, sends a strict Content-Security-Policy, caps
request size, concurrent scans and scan duration, and only quarantines files it
actually scanned. Restoring a quarantined file re-scans it first and asks again
if it is still detected. **Quit Warden** in the sidebar stops the server.

It is **not** hardened against other programs already running as you — see the
[threat model](docs/THREAT_MODEL.md).

## Usage

```bash
warden scan <path>                    # scan a file or folder
warden scan C:\ --min-severity high   # scan a whole drive, only loud findings
warden scan ./Downloads --quarantine  # scan, then offer to isolate anything flagged
warden scan ./Downloads --json out.json --save   # machine-readable + saved to history
warden scan suspicious.exe --online   # also check hashes against online reputation
warden scan /data --timeout 600 --max-files 50000   # bounded scan
warden scan ./x.zip --no-archives     # don't look inside archives
warden --offline scan ~/Downloads     # guarantee no network use for this run

warden inspect suspicious.exe         # hashes, format, signature, archive contents
warden lookup suspicious.exe          # look up one file's reputation online
warden lookup <sha256-or-sha1>        # ...or just a hash

warden sweep                          # persistence, processes, tasks, Temp, Downloads
warden sweep --quick                  # faster: top-level temp/downloads + executables only

warden quarantine list                # see isolated files
warden quarantine restore <id> --rescan   # re-check with current rules, then put it back
warden quarantine rescan --all        # re-check everything in quarantine
warden quarantine delete <id>         # permanently remove (asks first)
warden quarantine purge --older-than 30d  # clean up old items (asks first)
warden quarantine export <id> sample.wq --password   # portable, neutralized bundle
warden quarantine import sample.wq --password

warden history list                   # past scans/sweeps
warden history show <id>              # threats from a saved report
warden history prune --keep 20        # delete older reports

warden schedule add nightly --kind sweep --frequency daily --at 03:00
warden schedule list
warden schedule doctor                # will my scheduled scans actually run?
warden schedule test nightly          # run one now, the way the OS scheduler would
warden schedule remove nightly

warden rules list                     # signed rule packs: install / verify / rollback
warden rules install acme-core-12.wrp
warden rules rollback acme-core

warden status                         # engines, signature freshness, network state
warden privacy                        # what is stored locally, what can be sent
warden config show                    # view settings (secrets masked)
warden config set-vt-key              # store a VirusTotal API key (hidden prompt)
warden config set offline true        # change any setting
```

### Exit codes

`warden scan` and `warden sweep` exit with:

| Code | Meaning |
| --- | --- |
| `0` | Clean — everything was checked and nothing was flagged |
| `1` | One or more threats (Medium or higher) found |
| `2` | **Incomplete** — something could not be checked (unreadable paths, an engine error, a failed rule set, a cancelled or timed-out scan). Never treat `2` as clean. |

Press **Ctrl+C** once during a scan to stop gracefully and get a report of what
was covered so far (exit `2`).

### Settings

`warden config set <name> <value>`:

| Setting | Default | Meaning |
| --- | --- | --- |
| `online_hash_lookup` | `false` | Check hashes online on every scan |
| `offline` | `false` | Hard switch: never use the network |
| `use_clamav` | `true` | Use ClamAV if it is installed |
| `scan_archives` | `true` | Look inside archives |
| `check_signatures` | `true` | Look up the publisher signature of flagged executables |
| `follow_symlinks` | `false` | Follow symlinks while walking folders |
| `max_scan_bytes` | 100 MB | Largest file read for content scanning |
| `quarantine_encryption` | `false` | Seal newly quarantined files with AES-256-GCM |
| `quarantine_retention_days` | `0` | Age used by `quarantine purge --expired` |

## How it works

Files that fit within `max_scan_bytes` are read **once** and hashed from that
same buffer, so the recorded SHA-256 always matches the bytes that were scanned.
Larger files are hashed in full while content engines see the first
`max_scan_bytes`. Findings are aggregated into a per-file verdict and a per-scan
report. The same core powers the CLI, the sweep, the scheduler, and the dashboard.

- **On-demand, not resident.** No kernel driver, no background hooks. Warden runs
  when you ask it to.
- **Fails safe, not open.** A file is `clean`, `threat` or `unknown` — never
  just two. If an engine errors, a rule set fails to load, a folder can't be
  read, or a scan is cut short, the scan is reported **incomplete** and exits
  `2`. A crashed or missing engine can't turn into a false "all clear", and the
  report says exactly what was skipped and why.
- **Never executes or extracts what it scans.** Archives, documents and
  executables are parsed in memory by bounded, pure-Python readers. These parsers
  are continuously fuzz-tested against hostile and mutated input.
- **Reversible, verifiable quarantine.** Quarantine hashes the file **as it
  copies it** and aborts unless those bytes match the scan, writes the copy
  durably and removes the original **last**, so a crash can't lose your file.
  Restore re-verifies the hash, refuses to overwrite an existing file or follow a
  symlink, and can re-scan first. The stored copy is XOR-neutralized by default
  (obfuscation, so it can't run by accident) or sealed with **AES-256-GCM** if
  you enable `quarantine_encryption`.
- **Careful with external tools.** System utilities Warden calls (PowerShell for
  signature checks, `schtasks`, `codesign`) are invoked by **absolute path** with
  no shell, and file names are never interpolated into commands.
- **Local-first.** Nothing leaves your machine unless you opt into online
  reputation (off by default). `--offline` makes that a guarantee.

## Privacy

**No telemetry, analytics, crash reports, update checks or accounts — there is no
code for any of it.** By default Warden makes no network connections at all.

What stays on your computer, in `~/.warden`:

- **Scan history contains absolute file paths** (plus hashes and findings) for
  every file in every saved scan. Paths can reveal your user name and folder
  names — look a report over before sharing it.
- **Quarantine keeps a copy of each isolated file** together with its original
  path, hash and findings.
- A cache of hashes you looked up online, your settings, and your schedules.

`warden privacy` shows all of this for your installation, and how to erase it.
Full details: [docs/PRIVACY.md](docs/PRIVACY.md).

## Online reputation (opt-in)

Warden can ask an online service whether a file is known malware. This is **off
by default**; enable it per run with `--online`, or with
`warden config set online_hash_lookup true`. It sends the file's **hash** — never
the file, its name or its path — and results are cached in `~/.warden/cache/`.

Two providers, chosen automatically:

- **Team Cymru Malware Hash Registry** (default, **no API key**) — returns an AV
  detection percentage for known-bad files over DNS-over-HTTPS (via Cloudflare's
  resolver, which therefore sees the hash queries). Works out of the box.
- **VirusTotal** (optional, richer — aggregates 70+ engines) — get a **free** API
  key at [virustotal.com](https://www.virustotal.com/) (Sign up → API key), then
  store it with a hidden prompt (keeps it out of shell history):

  ```bash
  warden config set-vt-key            # prompts for the key, enables online lookups
  ```

  The key is kept in your OS secret store (Windows DPAPI, macOS Keychain,
  libsecret), not in a config file. The free tier is rate-limited, so Warden caps
  and caches lookups. You can also set `WARDEN_VT_API_KEY` in your environment.

Files inside archives are never looked up. To rule out network use entirely:
`warden --offline …`, `WARDEN_OFFLINE=1`, or `warden config set offline true`.

## Adding detection content

**Your own rules:** drop files into `~/.warden/rules/`
(`C:\Users\<you>\.warden\rules\` on Windows):

- `*.yar` / `*.yara` — extra YARA rules. Great sources:
  [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base),
  [Yara-Rules/rules](https://github.com/Yara-Rules/rules).
- `malware_hashes.txt` — one SHA-256 per line (`hash  optional-label`). Export
  from [MalwareBazaar](https://bazaar.abuse.ch/).

**Signed rule packs:** versioned bundles that are signature-checked before
install, refuse downgrades, can be rolled back, and are re-verified on every
scan. See [docs/RULE_PACKS.md](docs/RULE_PACKS.md).

Rule severity comes from a `severity` metadata field on each rule
(`"low"`–`"critical"`). For the full ClamAV signature set, install ClamAV and run
`freshclam`; Warden picks it up automatically and `warden status` shows how old
the signatures are.

## Limitations

Stated plainly, so you can decide what to rely on:

- **Not real-time.** See the box at the top.
- **Detection is signature- and heuristic-based.** New, packed or targeted
  malware can be missed; legitimate software can be flagged. Treat results as
  advice, and `unknown` / incomplete as "go and look", not "fine".
- **Things Warden cannot inspect:** password-protected archives and documents
  (reported, not opened), 7z and RAR archives (ClamAV handles these if
  installed), content past the first `max_scan_bytes` of a very large file,
  Excel 4.0 (XLM) macros, and PDF content hidden in compressed object streams.
- **A sweep only looks where it knows to look.** Windows services, WMI
  subscriptions and COM hijacks, Linux udev rules and kernel modules, and browser
  extensions are not enumerated.
- **Malware already running as you can defeat any user-space scanner**, Warden
  included.
- **Binaries are not code-signed** (no paid certificates) — verify them instead.

The full analysis is in the [threat model](docs/THREAT_MODEL.md).

## Testing it works (safely)

Use the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) —
a harmless, industry-standard string every scanner flags. Warden ships a YARA
rule for it.

> ⚠️ Windows Defender deletes an EICAR file the instant it's written to disk. To
> test on-disk detection, create it in a Defender-excluded folder, or trust the
> bundled unit test which checks the pattern in memory.

A harmless alternative that needs no exclusions: create an empty file named
`invoice.pdf.exe` and scan it — the double-extension heuristic flags it.

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

Build a standalone binary yourself (this is also how to get one for a platform
that has no published build):

```bash
pip install pyinstaller
pyinstaller packaging/warden.spec --noconfirm   # -> dist/warden(.exe)
```

Warden needs Python 3.10+ and a `yara-x` wheel for your platform (published for
Windows x64, Linux x64/ARM64 and macOS x64/ARM64) or a Rust toolchain to build it.

## Documentation

| | |
| --- | --- |
| [Threat model](docs/THREAT_MODEL.md) | What Warden defends against, how, and what it doesn't |
| [Privacy](docs/PRIVACY.md) | What is stored, what can be sent, how to erase it |
| [Verifying a release](docs/VERIFY.md) | Checksums, Sigstore signature, build provenance, SBOM |
| [Rule packs](docs/RULE_PACKS.md) | Building, signing, installing and rolling back detection content |
| [Releasing](docs/RELEASING.md) | How a release is cut (for maintainers) |
| [Security policy](SECURITY.md) | How to report a vulnerability |
| [Changelog](CHANGELOG.md) | What changed in each version |

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). New YARA
rules under `warden/rules/` are especially valuable. Please read the
[Code of Conduct](CODE_OF_CONDUCT.md) and report security issues per our
[Security policy](SECURITY.md).

## License

[MIT](LICENSE). Warden bundles no third-party signatures; ClamAV and any rule
packs you add carry their own licenses.
