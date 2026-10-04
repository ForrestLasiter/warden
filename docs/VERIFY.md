# Verifying a Warden release

Every Warden release publishes, alongside the binaries:

| File | What it is |
| --- | --- |
| `SHA256SUMS` | SHA-256 of every binary |
| `SHA256SUMS.sig` | Sigstore (keyless) signature of `SHA256SUMS` |
| `SHA256SUMS.pem` | the signing certificate (ties the signature to this repo's release workflow) |
| `warden.spdx.json` / `warden.cdx.json` | Software Bill of Materials (SPDX / CycloneDX) |

Binaries also carry **SLSA build provenance** attestations recorded on GitHub.

Binaries: `warden-windows-x64.exe`, `warden-linux-x64`, `warden-linux-arm64`,
`warden-macos-arm64` (Apple Silicon), `warden-macos-x64` (Intel).

> Warden's binaries are **not** Authenticode-signed or Apple-notarized (that
> needs paid certificates). The checks below are how you establish that a
> download is genuine.

The one-line installers verify `SHA256SUMS` automatically and **fail closed** if
it can't be checked. The steps below are for verifying a manual download.

## 1. Checksum (always do this)

```bash
# with all files in the same directory
sha256sum --check --ignore-missing SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS  # macOS
```
PowerShell:
```powershell
(Get-FileHash .\warden-windows-x64.exe -Algorithm SHA256).Hash -eq `
  ((Get-Content .\SHA256SUMS | Select-String 'warden-windows-x64.exe') -split '\s+')[0]
```

## 2. Signature (proves the checksums came from this repo's release workflow)

Install [cosign](https://docs.sigstore.dev/cosign/installation/), then:

```bash
cosign verify-blob \
  --certificate SHA256SUMS.pem \
  --signature SHA256SUMS.sig \
  --certificate-identity-regexp '^https://github\.com/ForrestLasiter/warden/\.github/workflows/release\.yml@.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
```
A `Verified OK` means the checksums file was signed by Warden's release workflow.
Because it covers the checksums, verifying one binary's checksum then transitively
proves that binary.

## 3. Build provenance (SLSA)

With the GitHub CLI:

```bash
gh attestation verify warden-linux-x64 --repo ForrestLasiter/warden
```
This confirms the binary was produced by this repository's workflow on GitHub's
runners, not built or swapped elsewhere.

## Convenience script

`scripts/verify-release.sh <dir>` runs the checksum and (if cosign is present)
the signature check for you.

## What is *not* provided

Warden binaries are **not** Authenticode- or Apple-notarized-signed — that needs
paid certificates, which this project intentionally doesn't use. The Sigstore
signature + SLSA provenance + checksums give you cryptographic assurance of
origin and integrity for free; the trade-off is a first-run SmartScreen /
Gatekeeper prompt.
