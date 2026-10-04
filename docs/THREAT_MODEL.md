# Warden threat model

This document says what Warden is designed to protect against, how, and — just as
important — what it does **not** protect against. It is written for people
deciding whether to rely on Warden, and for contributors deciding whether a
change weakens a guarantee.

## 1. What Warden is (and is not)

Warden is an **on-demand** scanner: it examines files when you ask it to (or when
a schedule you created fires). It has no kernel driver, no file-system filter and
no background service.

| Warden is | Warden is not |
| --- | --- |
| A second opinion you run on files, folders or a system sweep | Real-time / on-access protection — it cannot block a file as it runs |
| A transparent set of detectors (YARA, heuristics, hashes, optional ClamAV) | A replacement for your OS antivirus (keep Microsoft Defender / XProtect on) |
| A reversible quarantine for files it flagged | A sandbox, an EDR, or a remediation tool for an already-compromised machine |

**If malware is already running with your privileges, it can defeat any
user-space scanner** — including Warden — by tampering with the scanner, its
rules, its state or its output. Warden's guarantees are about *files at rest that
have not yet run*, and about *not making things worse*.

## 2. Assets

1. **The user's files.** Warden must never lose, corrupt, overwrite or execute them.
2. **The verdict.** A file must never be reported clean because something
   failed, was skipped silently, or was tampered with.
3. **The user's privacy.** Paths, hashes and file contents stay on the machine
   unless the user explicitly opts in.
4. **The machine's integrity.** Running Warden must not give an attacker code
   execution, privilege, persistence or a network foothold.
5. **Release integrity.** A user must be able to tell that a binary was built
   from this repository by its release workflow.

## 3. Actors and trust boundaries

| Actor | Trust | Notes |
| --- | --- | --- |
| The user at the keyboard | Trusted | Confirms destructive actions. |
| **Scanned content** (files, archive members, document parts, names, metadata) | **Hostile** | The core threat: built by an attacker specifically to break the scanner. |
| Web pages open in the user's browser | Hostile | Can send requests to `127.0.0.1`. |
| Other devices on the network | Hostile | Must not reach the dashboard at all. |
| Remote services (reputation providers, a rule-pack URL) | Untrusted | Responses are parsed defensively; never executed. |
| Rule-pack publishers | Trusted **only** via a key the user added | See §4.9. |
| Other processes running as the same user | **Outside the boundary** | They share the user's files, memory and loopback interface. See §5. |
| Administrator / root, the OS, hardware | Trusted | |
| GitHub Actions, PyPI, Sigstore | Trusted for releases, with pinning (§4.11) | |

## 4. Threats and mitigations

### 4.1 Hostile files attacking the parsers

*Threat:* a crafted file crashes Warden, hangs it, exhausts memory, or gets code
execution through a parser.

- All Warden-authored parsing (PE/ELF/Mach-O metadata, OLE compound files, VBA
  decompression, OOXML, PDF, RTF, archives, plists, crontabs, unit files) is
  **pure Python over an in-memory buffer**: no native extraction, no shelling out
  on file content, nothing is rendered or executed.
- Every parser is **bounded**: file-size caps, header/section/stream counts,
  FAT-chain length with cycle detection, decompressed-output caps, member counts.
- Each engine runs inside a catch-all: an exception becomes an `engine-error`
  finding for that file (status `unknown`), never a crash and never `clean`.
- Property-based fuzz tests (`tests/test_fuzz.py`) assert "never raises, never
  exceeds its bounds" for every parser, on random and mutated-valid input.
- Third-party parsers are limited to `pefile` (pure Python), `yara-x` (Rust,
  memory-safe) and — optionally, as a **separate process** — ClamAV.

*Residual risk:* a bug in `yara-x`, `pefile`, CPython or ClamAV. Warden does not
sandbox or privilege-separate the scanning process; a full sweep run as
root/administrator scans with those privileges.

### 4.2 Archives

*Threat:* decompression bombs, path traversal ("zip slip"), symlink/device
members, recursive nesting, forged size headers.

- **Nothing is ever extracted to disk.** Members are read into memory only, so
  traversal names, links and device nodes are inert.
- Declared sizes are not trusted: reads are capped and a running total of real
  decompressed bytes enforces limits — 2,000 members, 64 MiB per member, 256 MiB
  per top-level file, 200:1 ratio, 3 nesting levels.
- Hitting a limit **stops the walk and is reported** (`archive-partially-scanned`,
  or `archive-bomb-suspected` at Medium). Encrypted members are reported
  (`encrypted-archive-member`), never silently skipped.
- Archive members never trigger online lookups (one archive could otherwise fan
  out into thousands of queries).

*Residual risk:* 7z and RAR are not opened (ClamAV does, if installed);
password-protected content cannot be inspected by design; a file larger than
`max_scan_bytes` is hashed but not unpacked.

### 4.3 Evasion and "silent clean"

*Threat:* the scan misses part of the target and still says "clean".

- A result is **clean / threat / unknown** — never two-valued. Engine errors,
  unreadable paths, engines that failed to load, a tampered rule pack, a
  cancelled or timed-out scan all make the report **incomplete**: exit code `2`,
  an "INCOMPLETE" banner in the CLI and the dashboard, and `coverage.complete:
  false` in JSON.
- Skips are counted and shown: by extension, oversized, unreadable, symlinks,
  archive members not inspected.
- Symlinks are not followed by default; directory walks have a visited-inode
  cycle guard and a depth limit.

*Residual risk:* detection is signature- and heuristic-based. Novel, packed or
polymorphic malware, in-memory-only threats, fileless persistence outside the
locations the sweep knows, PDF object streams, Excel 4.0 (XLM) macros and
anything beyond the first `max_scan_bytes` of a file can be missed. **"Clean"
means "nothing Warden knows about was found", not "safe".**

### 4.4 Quarantine

*Threat:* losing the user's file; quarantining the wrong bytes; a quarantined
file running; restore overwriting something or writing through a symlink; a
tampered store.

- **Hash-while-copy:** the file is hashed as it is copied and the copy is kept
  only if the hash equals the scanned hash (closes the scan→quarantine race).
  Without a scan hash, quarantine refuses (fail closed).
- **Durable ordering:** blob → metadata → index → delete original *last*, each
  fsync'd; a crash leaves either the untouched original or a complete record.
- **Not runnable:** stored XOR-neutralized (`.qbin`) or, optionally, sealed with
  AES-256-GCM (`.qenc`; chunked, per-entry key via HKDF, bound to the entry id,
  truncation/reordering detected). The machine key lives in the OS secret store.
- **Verified restore:** the decoded bytes are re-hashed against the recorded
  hash before anything appears at the destination; restore never follows a
  symlink and never overwrites (atomic no-clobber publish).
- **Re-scan before restore** (`--rescan`, and always in the dashboard): restoring
  something still detected needs explicit confirmation.
- Entry ids are validated before they become file names. Imported bundles are
  untrusted: their payload must match their own hash, and their recorded path is
  never used as a restore destination.
- Permanent deletion always requires confirmation.

*Residual risk:* XOR is obfuscation, not confidentiality or integrity — choose
`quarantine_encryption` if either matters. On systems without a keychain, the
key falls back to an owner-only (0600) file. Anyone with your user privileges can
read or delete the quarantine folder.

### 4.5 Local dashboard

*Threat:* another device, a malicious web page, or DNS rebinding drives the
dashboard (start scans, delete or restore quarantined files, shut it down).

- Binds to loopback only; any other bind address is **refused**.
- `Host` must be loopback (defeats DNS rebinding).
- A random per-session token is required on every API call, compared in
  constant time; it is delivered in the page and unreadable cross-origin.
- State-changing requests with a foreign `Origin` or a cross-site
  `Sec-Fetch-Site` are refused.
- Strict `Content-Security-Policy` (`default-src 'none'`, no inline script or
  style, no framing, no form posts), `nosniff`, `no-store`, COOP/CORP.
- All untrusted strings (paths, member names, rule metadata) are inserted as
  text nodes, never as HTML.
- Quarantine acts only on results the server itself produced (job id + index),
  never on a client-supplied path.
- Bounded: 1 MiB bodies, 2 concurrent jobs (race-free), 4 h / 2,000,000 files per
  job, cancellable, 30 s socket timeout, bounded job-result memory.

*Residual risk:* **the token is not a defence against local malware.** Any
process already running as you can reach `127.0.0.1` and, with enough effort,
read the token. There is no TLS and there are no accounts — by design it is a
single-user, same-machine tool. Stop it when you are done ("Quit Warden").

### 4.6 Scheduler

*Threat:* command injection into `schtasks`/crontab via a schedule name or
target path; a hijacked `schtasks.exe`; a corrupted registry file feeding the OS
scheduler.

- Names are restricted to `[A-Za-z0-9_-]{1,64}`; targets reject quotes, NUL and
  newlines, are made absolute and passed after `--`; every crontab argument is
  `shlex`-quoted (a property test checks the target always remains exactly one
  shell argument).
- `schtasks.exe` and PowerShell are invoked by absolute path under `%SystemRoot%`.
- Registry entries are **re-validated on every load**; malformed entries are
  dropped rather than handed to the OS.
- Scheduled runs never auto-quarantine.
- `warden schedule doctor` reports missing/disabled/moved tasks, failed runs,
  orphaned tasks and a stopped cron daemon.

### 4.7 System sweep and external tools

*Threat:* attacker-controlled file *names* or command lines reaching a shell;
planted binaries being executed in place of system tools.

- No shell is ever used. Paths reach PowerShell through an environment variable,
  never interpolated into script text; `codesign` receives an absolute path.
- Persistence definitions (units, plists, crontabs) are parsed as text; the
  programs they name are scanned, never run.

*Residual risk:* persistence mechanisms Warden does not enumerate (see
`warden/persistence.py` for the list — notably udev rules, kernel modules, PAM,
browser extensions, macOS configuration profiles, WMI subscriptions, services
and COM hijacks on Windows).

### 4.8 Configuration, state and secrets

*Threat:* a malformed or hostile `config.json`, index or history file crashes
Warden or sets a pathological limit; secrets leak.

- Every state file is loaded defensively (type-checked, clamped, defaults on
  error) and written atomically (temp file + fsync + rename) under a
  cross-process lock. Fuzz tests feed each loader arbitrary JSON.
- The data directory is `0700`; state files are `0600` on POSIX.
- The VirusTotal API key and the quarantine key are stored in the OS secret
  store (DPAPI / Keychain / libsecret), with a `0600` file fallback; the key is
  never written to `config.json` and is masked in output.

*Residual risk:* anyone who can write to `~/.warden` as you can change settings
(for example widen `skip_extensions`) or add rules. That is the "local malware"
boundary in §5.

### 4.9 Rule packs

*Threat:* a malicious or downgraded rule pack blinds the scanner; a pack escapes
its directory; rules are altered after install.

- Packs install only with a valid **Ed25519** signature from a key in the user's
  trust store (unsigned needs `--allow-unsigned`).
- Versions are monotonic: an older or equal version is refused (replay /
  downgrade) unless explicitly allowed; `rollback` is a deliberate user action.
- Before activation: manifest hash check of every file, strict member-name
  confinement, size limits, and a full YARA compile. Failure changes nothing.
- Installed files are **re-hashed at every scanner start**; an altered or planted
  file means the pack is not loaded and the scan is reported degraded.
- Rule-pack URLs must be HTTPS and are refused in offline mode.

*Residual risk:* trust is only as good as the publisher's key custody. There is
no hosted official feed and no revocation service — you remove a key with
`warden rules untrust`. Files you drop into the user rules folder are trusted
without a signature.

### 4.10 Network and privacy

*Threat:* data leaving the machine without consent.

- No network use by default. **No telemetry, analytics, crash reporting, update
  checks or accounts exist in the code.**
- All network access goes through one module (`warden/net.py`): HTTPS only,
  bounded responses, and a hard **offline mode** (`--offline`,
  `WARDEN_OFFLINE=1`, or `offline: true`) that fails before a socket opens.
- Opt-in reputation sends only a SHA-1/SHA-256 — never contents, names or paths.

*Residual risk:* a hash reveals to the provider (and, for the keyless provider,
to the DNS-over-HTTPS resolver) that you possess a specific file. See
[PRIVACY.md](PRIVACY.md).

### 4.11 Installers and releases

*Threat:* a tampered binary, a compromised dependency or CI action, a moved tag.

- Third-party Actions are pinned to commit SHAs; build dependencies are
  version-pinned and hash-locked (`pip install --require-hashes`).
- Releases publish `SHA256SUMS`, a Sigstore keyless signature bound to the
  release workflow's identity, SLSA build provenance, and SPDX + CycloneDX SBOMs.
- Release tags are protected by a repository ruleset. `main` accepts changes
  only through pull requests, and changes to the release pipeline, installers
  and dependency locks require code-owner review (`.github/CODEOWNERS`).
- The installers verify the checksum and **fail closed** if it cannot be
  verified; a mismatch is always fatal.
- CI runs ruff, mypy, bandit, pip-audit, ShellCheck, PSScriptAnalyzer and the
  test suite on Linux (x64, ARM64), Windows and macOS (Apple Silicon, Intel),
  Python 3.10–3.14.

*Residual risk:* with a single maintainer, "code-owner review" of their own
change is an admin bypass recorded on the pull request, not an independent
review; a compromised maintainer account defeats it. The binaries are **not Authenticode-signed or Apple-notarized**
(those require paid certificates, which this project does not buy), so Windows
SmartScreen and macOS Gatekeeper will warn. Verify with [VERIFY.md](VERIFY.md).
`curl | sh` / `irm | iex` trust GitHub's TLS for the *installer script* itself.

## 5. Explicitly out of scope

- **Malware already executing as the user or as administrator.** It can read the
  dashboard token, edit `~/.warden`, kill Warden, or patch its output.
- **Real-time prevention.** Warden cannot stop a file from running.
- **Kernel-level threats, bootkits, firmware implants.**
- **Physical access** and other users with administrative rights.
- **Guaranteed detection.** No scanner offers this.
- **Disinfection.** Warden isolates files; it does not repair a compromised system.

## 6. Reporting

Found a way to break one of the guarantees above? Please report it privately —
see [SECURITY.md](../SECURITY.md).
