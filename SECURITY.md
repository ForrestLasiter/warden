# Security Policy

Warden is a security tool, so we take its own security seriously.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, report them privately through GitHub's built-in vulnerability reporting:

1. Go to the [Security tab](https://github.com/ForrestLasiter/warden/security/advisories/new).
2. Click **Report a vulnerability**.
3. Describe the issue, affected versions, and steps to reproduce.

You'll get an acknowledgement as soon as possible. We'll work with you on a fix
and coordinate disclosure. Please give us reasonable time to address the issue
before any public disclosure.

## Scope

The [threat model](docs/THREAT_MODEL.md) lists the guarantees Warden makes. A way
to break any of them is a vulnerability. In particular:

- **Hostile files.** A crafted file, archive, document, file name or archive
  member name that makes Warden execute code, write outside its data folder,
  hang or exhaust memory beyond its documented limits, crash, or inject into
  terminal/dashboard output.
- **Silent clean.** Any way to make a scan report `clean` / exit `0` when part of
  the target was not actually examined.
- **Quarantine.** A quarantined file running; restore overwriting an existing
  file, following a symlink or writing somewhere the user did not choose; a
  tampered or swapped stored copy being restored without detection; losing the
  original file.
- **Dashboard.** Being reachable from another device, or driveable by a web page
  (CSRF, DNS rebinding, XSS, a Content-Security-Policy bypass).
- **Scheduler / sweep.** Command or argument injection through schedule names,
  target paths, or file names found on disk.
- **Rule packs.** Installing a pack without a valid signature, downgrading, a
  pack writing outside its directory, or an altered installed pack being loaded.
- **Privacy.** Any network request made without the user opting in, anything
  beyond a hash being sent, or a request made while offline mode is on.
- **Audit trail.** A secret or file content written to the audit log; an edit,
  removal or reordering of entries that `warden audit verify` does not detect
  (rewriting the entire chain is a documented limit, not a vulnerability).
- **Releases and installers.** A way to make an installer accept a binary that
  does not match the published checksum, or a weakness in the release pipeline.

### Out of scope

- Attacks that require malware **already running as the same user** (or as
  administrator) — for example reading the dashboard's session token from another
  local process, or editing files under `~/.warden`. The threat model explains
  why no user-space scanner can defend against that.
- **Missed detections and false positives.** These are expected in any scanner
  and are best filed as regular issues (a sample hash and the rule name help).
- The unsigned-binary warnings from Windows SmartScreen and macOS Gatekeeper.
  Warden deliberately does not buy code-signing certificates; verify downloads
  with the checksum, Sigstore signature and build provenance instead
  ([docs/VERIFY.md](docs/VERIFY.md)).
- Vulnerabilities in ClamAV or other software Warden can optionally call —
  report those upstream (but do tell us if Warden's *use* of them is unsafe).

## Supported versions

Warden is pre-1.0; security fixes land on the latest release. Please test against
the newest version before reporting.

## How Warden is checked

Every change runs, on Linux (x64 and ARM64), Windows and macOS (Apple Silicon and
Intel) with Python 3.10–3.14:

- the test suite, including property-based fuzz tests of every parser and every
  state-file loader, with a coverage floor;
- `ruff`, `mypy` (for all three target platforms), `bandit`, and CodeQL
  (Python, the dashboard's JavaScript, and the workflows);
- `pip-audit` against the hash-locked release dependencies - also weekly, so a
  newly disclosed vulnerability in a pinned dependency is caught without a commit;
- `ShellCheck` and `PSScriptAnalyzer` on the installers;
- accessibility rules for the dashboard (colour contrast in both themes, markup).

The repository's supply-chain practices are scored publicly by the
[OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/ForrestLasiter/warden).

Releases are built from hash-pinned dependencies by SHA-pinned GitHub Actions,
and ship with `SHA256SUMS`, a Sigstore signature, SLSA build provenance and
SBOMs. Release tags are protected.

## A note on detection

Warden is an **on-demand scanner**, not a real-time antivirus, and it is not a
replacement for your operating system's built-in protection (e.g. Microsoft
Defender). It cannot stop a file from running.
