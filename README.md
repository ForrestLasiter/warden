# Warden

**Open-source, on-demand malware scanner for Windows/Linux/macOS.** No subscription, no telemetry, no lock-in. Warden stands on the shoulders of the open-source giants — [YARA](https://virustotal.github.io/yara/) rules and (optionally) [ClamAV](https://www.clamav.net/) — and adds structural heuristics and hash reputation, wrapped in a clean CLI (GUI coming).

> A warden guards what matters. Warden keeps watch over your filesystem.

Warden is an **on-demand scanner**: you point it at a file, folder, or your whole drive and it tells you what's suspicious. It is *not* a real-time resident AV and is **not a replacement for Windows Defender** (which is free and built into Windows 11 — keep it on). Think of Warden as a second opinion you fully own and control.

---

## What it detects

Warden runs every file past up to four independent engines and reports the worst verdict:

| Engine | What it does | Needs |
| --- | --- | --- |
| **YARA** | Pattern/rule matching (VirusTotal's `yara-x`). Ships with starter rules; drop in community rule packs. | built in |
| **Heuristics** | Structural red flags: fake double extensions (`invoice.pdf.exe`), packed PE sections, risky imports, obfuscated scripts, high entropy. | built in |
| **Hash reputation** | SHA-256 against a local known-bad list (feed it MalwareBazaar exports, etc.). | built in |
| **ClamAV** | Millions of signatures via `clamscan`/`clamdscan`. | optional — install ClamAV |

Findings are rated **Info → Low → Medium → High → Critical**. Anything Medium+ counts as a threat.

## Install (dev)

```bash
git clone https://github.com/ForrestLasiter/warden
cd warden
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -e .
```

## Usage

```bash
warden status                        # which engines are active
warden scan C:\Users\me\Downloads    # scan a folder
warden scan suspicious.exe           # scan one file
warden scan C:\ --min-severity high  # scan a whole drive, only loud findings
warden scan .\Downloads --quarantine # scan, then offer to isolate anything flagged
warden scan .\Downloads --json report.json   # machine-readable output

warden sweep                         # auto-scan autoruns, processes, tasks, Temp, Downloads
warden sweep --quick                 # faster: top-level temp/downloads + executables only
warden sweep --quarantine            # sweep, then offer to isolate anything flagged

warden quarantine list               # see isolated files
warden quarantine restore <id>       # put one back
warden quarantine delete <id>        # permanently remove (asks first)

warden update-rules                  # how to add YARA rules & hash feeds
```

`warden scan` exits **1** if any Medium+ threat is found, **0** if clean — handy for scripts and scheduled runs.

## Quarantine is safe and reversible

Quarantined files are **XOR-neutralized** (the stored copy can't execute) and recorded with full metadata. Warden never permanently deletes anything unless you explicitly run `quarantine delete` and confirm. Restore is byte-for-byte identical to the original.

## Testing it works (safely)

Use the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) — a harmless industry-standard string every scanner flags. Warden ships a YARA rule for it.

> ⚠️ Windows Defender will delete an EICAR file the moment you write it to disk. To test on-disk detection, create it inside a folder you've added to Defender's exclusions, or just trust the bundled unit test which checks the pattern in memory.

## Adding detection content

Drop files into `~/.warden/rules/` (`C:\Users\<you>\.warden\rules\`):

- `*.yar` / `*.yara` — extra YARA rules. Great sources: [Neo23x0/signature-base](https://github.com/Neo23x0/signature-base), [Yara-Rules/rules](https://github.com/Yara-Rules/rules).
- `malware_hashes.txt` — one SHA-256 per line (`hash  optional-label`). Export from [MalwareBazaar](https://bazaar.abuse.ch/).

Rule severity is controlled by a `severity` metadata field on each YARA rule (`"low"`–`"critical"`).

For the full ClamAV signature set: install ClamAV, run `freshclam`, and Warden picks it up automatically.

## Roadmap

- [x] On-demand file/folder scan (YARA + heuristics + hash + ClamAV)
- [x] Safe, reversible quarantine
- [x] **System sweep** — auto-scan the high-value spots (startup/autoruns, scheduled tasks, Temp, Downloads, running processes; flags unsigned executables in user-writable locations)
- [ ] **Scheduled scans** (Windows Task Scheduler / cron integration) with history
- [ ] **GUI dashboard** — results, threats, history, one-click quarantine (WCAG 2.1 AA)
- [ ] Opt-in online hash reputation lookup

## Contributing

Issues and PRs welcome. Good first contributions: new YARA rules under `warden/rules/`, heuristics, or ClamAV integration testing.

## License

MIT. Warden bundles no third-party signatures; ClamAV and any rule packs you add carry their own licenses.
