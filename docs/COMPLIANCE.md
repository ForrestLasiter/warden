# Compliance: what applies to Warden, and what Warden does for yours

People ask "is Warden SOC 2 / ISO 27001 / HIPAA compliant?" The accurate answer
has two halves, and this page keeps them apart:

1. **Standards that apply to Warden itself** — as a piece of software you
   download. Warden meets these (accessibility, open-source licensing, supply
   chain integrity, vulnerability disclosure). Section A.
2. **Standards that apply to _organisations_** — SOC 2, ISO 27001, HIPAA, PCI
   DSS and the like. **No software can be "compliant" with these, and Warden
   holds no certification or attestation under any of them.** An organisation is
   assessed; a tool can only help it meet particular controls. Section B maps
   what Warden contributes and — just as important — what it does not.

Nothing here is legal advice. Control numbers are given so you can find the text;
your auditor decides what satisfies it.

## At a glance

| Standard | Does it apply to Warden itself? | Status |
| --- | --- | --- |
| **ADA / Section 508 / WCAG 2.1 AA / EN 301 549** (accessibility) | Yes | Dashboard audited to WCAG 2.1 AA, no known failures — [ACCESSIBILITY.md](ACCESSIBILITY.md) |
| **Open-source license obligations** of bundled software | Yes | Met: notices ship in every binary (`warden licenses`) |
| **SLSA** (build integrity) | Yes | Build Level 2 provenance on every release binary |
| **SBOM** (NTIA minimum elements; SPDX, CycloneDX) | Yes | Published with every release |
| **OpenSSF Scorecard** | Yes | Runs weekly; results public |
| **Coordinated vulnerability disclosure** (ISO/IEC 29147 style) | Yes | [SECURITY.md](../SECURITY.md); private reporting enabled |
| **NIST SSDF** (SP 800-218) | Yes, voluntarily | Practices mapped below; not attested |
| **SOC 2** | No — it assesses a service organisation | No report exists. Control mapping in Section B |
| **ISO/IEC 27001** | No — it certifies a management system | Not certified. Control mapping in Section B |
| **HIPAA** | No — Warden is not a covered entity or business associate, and receives no data | Guidance for use around PHI in Section B |
| **PCI DSS** | No | Helps with part of Requirement 5 and 10; **not sufficient alone** |
| **GDPR / CCPA** | The project processes no personal data | Notes for users in Section B |
| **FIPS 140-3** | Only if you require validated cryptography | **Not validated** |
| **EU Cyber Resilience Act** | Not for free, non-commercial open source | Notes in Section A |
| **AV-TEST / AV-Comparatives / VB100 / AMTSO** | No | **Never tested. Warden makes no detection-rate claims** |
| **Common Criteria, FedRAMP, CMMC** | No | Not evaluated |

---

## Section A — Standards Warden itself meets

### A.1 Accessibility (ADA, Section 508, WCAG 2.1 AA, EN 301 549)

The dashboard was audited against all WCAG 2.1 A and AA success criteria with
axe-core and scripted keyboard, reflow, contrast and target-size checks, in both
themes and at desktop and phone widths. The audit found and fixed real failures;
there are no known ones now. Colour-contrast and markup rules run in CI on every
change. The full criterion-by-criterion table, the method, and its limits (it is
a self-assessment, not tested by assistive-technology users) are in
[ACCESSIBILITY.md](ACCESSIBILITY.md).

### A.2 Open-source license compliance

Warden is MIT-licensed. Its binaries also contain the Python runtime, the YARA-X
engine and a set of libraries under BSD, MIT, Apache-2.0, MPL-2.0, PSF and ISC
licenses. All of these permit redistribution provided their copyright notices
and license texts accompany the copy, so:

- every release binary carries the notices for exactly the versions inside it
  (generated at build time): `warden licenses` lists them, `warden licenses
  --full` prints every license text;
- no bundled component is under a license that restricts how you may use Warden
  or requires Warden's source to be under different terms. (`certifi` is
  MPL-2.0, a file-level license satisfied by shipping it unmodified with its
  notice; PyInstaller's bootloader carries an explicit exception for bundled
  applications.)

### A.3 Supply-chain integrity

| Practice | What Warden does |
| --- | --- |
| **SLSA v1.0 Build Level 2** | Release binaries are built on GitHub-hosted runners and carry signed build-provenance attestations (`gh attestation verify`). Level 3 (a hardened, isolated build platform) is **not** claimed. |
| **Signed release** | `SHA256SUMS` is signed keylessly with Sigstore; the certificate binds it to this repository's release workflow. |
| **SBOM** | SPDX and CycloneDX documents attached to every release. |
| **Pinned inputs** | Third-party Actions pinned to commit SHAs; build dependencies version-pinned and hash-locked. |
| **All-or-nothing publishing** | Nothing is attached to a release unless every platform built and passed its smoke test. |
| **Protected branches and tags** | `main` takes changes only by pull request; release tags cannot be moved or deleted. |
| **Analysis** | CodeQL, Bandit, Ruff, mypy, pip-audit, ShellCheck, PSScriptAnalyzer; property-based fuzz tests of every parser. |
| **OpenSSF Scorecard** | Runs weekly and on every change to `main`; results are public at [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/ForrestLasiter/warden). |

Honest gaps: binaries are **not** Authenticode-signed or Apple-notarized (paid
certificates; verify with [VERIFY.md](VERIFY.md) instead). The Intel macOS
binary's crypto component is compiled against the build machine's OpenSSL. There
is one maintainer, so "code review" of the maintainer's own changes is not
independent. The project has not applied for the OpenSSF Best Practices badge.

### A.4 NIST Secure Software Development Framework (SP 800-218)

Selected practices and where they are met. This is a self-description, not an
attestation.

| SSDF practice | Evidence |
| --- | --- |
| PO.3 Toolchains | Pinned Actions, hash-locked build dependencies, reproducible lock generation ([RELEASING.md](RELEASING.md)) |
| PS.1 Protect code from tampering | Branch and tag rulesets, code-owner review on release-critical paths |
| PS.2 Verify release integrity | Checksums, Sigstore signature, provenance, fail-closed installers ([VERIFY.md](VERIFY.md)) |
| PS.3 Archive and protect releases | Immutable tags, SBOMs per release |
| PW.1 Design to meet security requirements | [THREAT_MODEL.md](THREAT_MODEL.md) |
| PW.4 Reuse well-secured components | Small dependency set, audited weekly (pip-audit), Dependabot alerts |
| PW.7 Review and analyze code | CodeQL, Bandit, Ruff, mypy on every change |
| PW.8 Test executable code | 440+ tests incl. fuzzing on 5 OS/architecture combinations, Python 3.10–3.14; release smoke tests |
| RV.1 Identify vulnerabilities | Private vulnerability reporting, advisories, weekly dependency audit |
| RV.2 / RV.3 Assess, remediate, analyse root cause | [SECURITY.md](../SECURITY.md); fixes land on the latest release with a changelog entry |

### A.5 Vulnerability disclosure

Private reporting through GitHub Security Advisories is enabled; the policy,
scope and out-of-scope list are in [SECURITY.md](../SECURITY.md). Fixed
vulnerabilities are published as advisories (GitHub is a CVE Numbering Authority
and can assign CVE IDs).

### A.6 EU Cyber Resilience Act

The CRA places obligations on products made available **in the course of a
commercial activity**. Warden is free, open-source software developed and
supplied outside any commercial activity, and is not CE-marked. If you integrate
or redistribute Warden commercially, CRA obligations for that product are yours;
the SBOMs, provenance, threat model and vulnerability-handling policy here are
the inputs you would need.

### A.7 Export controls (informational)

Warden contains and uses standard, published cryptography (AES-256-GCM, Ed25519,
SHA-2, HKDF, scrypt, TLS via OpenSSL) and its source is publicly available. Under
the U.S. Export Administration Regulations, publicly available encryption source
code implementing only standard cryptography is generally not subject to
notification or licensing. Check your own jurisdiction if you redistribute it.

---

## Section B — Using Warden inside your compliance programme

### B.1 The one thing to get right first

**Warden is an on-demand scanner. It is not real-time anti-malware.** Almost
every framework's malware control expects protection that acts as files are
opened or run. Warden's scheduled and on-demand scans can be *part* of that
control — a second engine, a periodic sweep, an investigation tool — but an
operating-system antivirus (Microsoft Defender, XProtect, or an EDR) must stay
enabled to satisfy it.

Warden also has **no vendor**: no company, no support contract, no SLA, no
SOC 2 report to hand your vendor-risk process. It is MIT-licensed software
provided "as is". What you can put in the file instead is at the end of this page.

### B.2 Control mapping

| Control area | Framework references | What Warden contributes | What you still need |
| --- | --- | --- | --- |
| **Malware protection** | SOC 2 CC6.8 · ISO 27001 A.8.7 · HIPAA §164.308(a)(5)(ii)(B) · PCI DSS 5.2, 5.3 · NIST 800-53 SI-3 · NIST 800-171 3.14.2, 3.14.5 · CIS 10 | On-demand and scheduled scans (YARA, heuristics, documents, archives, hashes, optional ClamAV); persistence sweep; quarantine | **Real-time protection** (PCI 5.3.2, 800-171 3.14.5, UK Cyber Essentials all require it). Central management and tamper-resistance (PCI 5.3.5): any user can stop Warden |
| **Signature currency** | PCI DSS 5.3.1 · CIS 10.2 · NIST 800-171 3.14.4 | ClamAV database age is reported and flagged when stale; signed, versioned rule packs with rollback | Schedule `freshclam`. **Warden never updates itself** — track releases and update it |
| **Periodic scanning with evidence** | PCI DSS 5.3.2 · ISO 27001 A.8.7 | `warden schedule add`; `schedule doctor` proves the schedule is alive; reports saved to history; exit codes for automation | Review the results; act on exit code `1` (threats) and `2` (incomplete) |
| **Audit logging** | SOC 2 CC7.2, CC7.3 · ISO 27001 A.8.15, A.8.16 · HIPAA §164.312(b), §164.308(a)(1)(ii)(D) · PCI DSS 5.3.4, 10.2 · NIST 800-53 AU-2, AU-3 | Hash-chained audit trail of scans, quarantine actions, setting changes, rule and schedule changes, with user, host and time (`warden audit`) | **Protect and retain it yourself** (PCI 10.3, 10.5.1; AU-9, AU-11): forward `~/.warden/audit/audit.jsonl` to a log collector. The local chain is tamper-evident, not tamper-proof |
| **Encryption at rest** | HIPAA §164.312(a)(2)(iv) · ISO 27001 A.8.24 · SOC 2 CC6.1 · NIST 800-53 SC-28 | Quarantined files can be sealed with AES-256-GCM (`quarantine_encryption`); keys in the OS secret store | History, audit log and settings are plain files — use full-disk encryption. Cryptography is **not FIPS 140-validated** |
| **Retention and disposal** | SOC 2 CC6.5, C1.2 · ISO 27001 A.8.10 · HIPAA §164.310(d)(2)(i) · GDPR Art. 5(1)(e) | `history_retention_days`, `quarantine_retention_days`, `history prune`, `quarantine purge`, `audit prune` | Deletion is ordinary file deletion, not secure erasure; choose the periods your policy requires |
| **Data leaving the system** | HIPAA §164.312(e)(1) · ISO 27001 A.8.12 · SOC 2 CC6.7 · GDPR Ch. V | Nothing leaves by default; `offline` mode is a hard guarantee; online lookups send only a hash, over HTTPS; their use is recorded in the audit trail | Decide whether hashes may leave; set `offline true` if not |
| **Access control** | SOC 2 CC6.1 · ISO 27001 A.5.15, A.8.3 · HIPAA §164.312(a)(1) | Data folder owner-only (0700); dashboard local-only with a session token | Warden has **no user accounts or roles**; it runs as, and is only as protected as, the OS account |
| **Integrity of installed software** | SOC 2 CC8.1 · ISO 27001 A.8.19, A.8.32 · NIST 800-53 SI-7, SR-4 | Signed, attested releases; fail-closed installers; rollback; rule packs re-verified on every scan | Verify what you deploy ([VERIFY.md](VERIFY.md)); control who may install |
| **Vulnerability management of the tool** | SOC 2 CC7.1 · ISO 27001 A.8.8 · PCI DSS 6.3 | Disclosure policy, advisories, weekly dependency audit, SBOM to match against your scanner | Subscribe to releases; patch |
| **Supplier assessment** | SOC 2 CC9.2 · ISO 27001 A.5.19–A.5.22 | Public source, threat model, SBOM, provenance, this page | Accept that there is no vendor attestation or contractual commitment |
| **Accessibility of tooling** | ADA · Section 508 · EN 301 549 | WCAG 2.1 AA dashboard ([ACCESSIBILITY.md](ACCESSIBILITY.md)) | — |

### B.3 A hardened configuration

For machines in scope of a compliance programme (or that handle sensitive data):

```bash
warden config set offline true                   # nothing can leave the machine
warden config set quarantine_encryption true     # seal quarantined files (AES-256-GCM)
warden config set history_retention_days 365     # or what your policy says
warden config set quarantine_retention_days 90   # then: warden quarantine purge --expired
warden schedule add nightly --kind sweep --frequency daily --at 03:00
warden schedule doctor                           # confirm it will really run
warden posture                                   # review what still needs attention
```

Leave `audit_log` on (the default), forward the audit file to your log
collector, keep full-disk encryption on, and keep your real-time antivirus on.

### B.4 Evidence you can collect

| Evidence | Command |
| --- | --- |
| Point-in-time security posture of an installation | `warden posture --json` |
| That scheduled scans exist and run | `warden schedule doctor --json` |
| What was scanned, when, and the outcome | `warden history list`, `warden scan … --json report.json --save` |
| Who did what (quarantine, restore, delete, setting changes) | `warden audit show`, `warden audit export audit.jsonl` |
| That the audit trail is unaltered | `warden audit verify` (record the head hash) |
| What data is stored and what can leave | `warden privacy --json` |
| Software composition and licenses | release SBOMs, `warden licenses --full` |
| Integrity of the installed binary | [VERIFY.md](VERIFY.md) |

`warden posture --strict` exits `1` when anything needs attention, so it can gate
a deployment or run under configuration management.

### B.5 HIPAA

Warden is not a covered entity or a business associate: the project never
receives your data, so there is nothing to sign a Business Associate Agreement
for, and none is offered. Running Warden on systems that hold PHI is your
decision under your own risk analysis. Where PHI can touch Warden:

- **File paths.** Scan history, the audit trail and quarantine records store
  absolute paths. If your file or folder names contain patient identifiers,
  those records contain PHI. Limit retention, and protect `~/.warden` like any
  other PHI store (full-disk encryption, OS access control).
- **Quarantined files.** A quarantined document may itself be PHI. Turn on
  `quarantine_encryption`; otherwise it is only obfuscated.
- **Online hash lookups.** Off by default. A hash is not the document, but for
  PHI systems set `offline true` and remove the question.
- **Exported reports and bundles.** `--json` reports and quarantine exports
  contain paths (and, for bundles, the file). Treat them as PHI when sharing.

Warden addresses none of HIPAA's administrative or physical safeguards and is
not a substitute for the "protection from malicious software" a real-time
product provides.

### B.6 GDPR / CCPA

The Warden project collects and processes **no personal data**: no telemetry, no
accounts, no update checks, no crash reports. There is no controller or
processor relationship with its users, and no data to request or erase.

On your side: the local records Warden writes include the OS user name, host
name and file paths, which can be personal data — you are the controller of
them, and the retention and purge commands exist for that. If you enable online
lookups, your IP address and a file hash reach Cloudflare (DNS-over-HTTPS) and
Team Cymru, or VirusTotal, under those services' own terms. Details in
[PRIVACY.md](PRIVACY.md).

### B.7 Cryptography and FIPS

| Use | Algorithm |
| --- | --- |
| Quarantine encryption | AES-256-GCM, chunked, per-item key via HKDF-SHA256 |
| Exported bundle password | scrypt (N=2^15) → AES-256-GCM |
| Rule-pack signatures | Ed25519 |
| File and audit hashing | SHA-256 |
| Hash-reputation lookup key | SHA-1 (an identifier for the lookup service, not a security function) |
| Default quarantine neutralization | XOR — **obfuscation, not encryption** |

Implementations come from the `cryptography` library (OpenSSL). They are **not
FIPS 140-2/140-3 validated modules** as shipped, and Warden has no FIPS mode. If
your requirement is validated cryptography for data at rest, rely on a validated
full-disk or volume encryption product rather than Warden's quarantine
encryption.

### B.8 What Warden is not

- Not certified, attested or audited under SOC 2, ISO 27001, HIPAA, PCI DSS,
  FedRAMP, CMMC or Common Criteria.
- Not tested by AV-TEST, AV-Comparatives, Virus Bulletin or under AMTSO
  standards; no detection rate is claimed or implied.
- Not real-time protection, not EDR, not centrally managed.
- Not a FIPS-validated cryptographic module.
- Not backed by a vendor, support contract or warranty.
