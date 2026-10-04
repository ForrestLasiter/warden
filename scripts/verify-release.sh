#!/usr/bin/env sh
# Verify Warden release artifacts in a directory (checksums + Sigstore signature).
#
#   scripts/verify-release.sh <dir-with-downloads>
#
# Requires: sha256sum or shasum. Signature check also needs `cosign`.
set -eu

DIR="${1:-.}"
cd "$DIR"

if [ ! -f SHA256SUMS ]; then
  echo "SHA256SUMS not found in $DIR" >&2
  exit 1
fi

echo "== Checksums =="
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --check --ignore-missing SHA256SUMS
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 --check --ignore-missing SHA256SUMS
else
  echo "Need sha256sum or shasum to verify." >&2
  exit 1
fi

echo
echo "== Signature =="
if command -v cosign >/dev/null 2>&1 && [ -f SHA256SUMS.sig ] && [ -f SHA256SUMS.pem ]; then
  cosign verify-blob \
    --certificate SHA256SUMS.pem \
    --signature SHA256SUMS.sig \
    --certificate-identity-regexp '^https://github\.com/ForrestLasiter/warden/\.github/workflows/release\.yml@.*$' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    SHA256SUMS && echo "Signature: OK"
else
  echo "Skipped (cosign not installed or signature files missing)."
  echo "Install cosign and re-run, or see docs/VERIFY.md."
fi
