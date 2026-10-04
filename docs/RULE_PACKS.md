# Rule packs

A **rule pack** is a signed, versioned bundle of detection content (YARA rules
and/or a SHA-256 denylist) that can be installed, verified and rolled back as a
unit. Use packs when you want updates you can trust and undo; for a few rules of
your own, dropping `.yar` files into `~/.warden/rules/` still works.

Warden never downloads rules on its own and there is no hosted "official" feed.
The rules that ship with Warden travel inside the signed release binary. Packs
are for content *you* (or an organisation you trust) publish.

## Using a pack someone gave you

```bash
warden rules trust acme.pub --name "ACME security team"   # once: trust their key
warden rules verify acme-core-12.wrp                      # optional: check without installing
warden rules install acme-core-12.wrp                     # looks for acme-core-12.wrp.sig beside it
warden rules list
```

From a URL (HTTPS only; fetches `<url>.sig` too; refused in offline mode):

```bash
warden rules install https://example.org/packs/acme-core-12.wrp
```

If a new version causes false positives:

```bash
warden rules rollback acme-core        # back to the previously active version
```

Remove a pack, or stop trusting a key:

```bash
warden rules remove acme-core
warden rules keys                      # list trusted keys and their ids
warden rules untrust 3fa1c09d7b2e4a10
```

## Publishing your own

```bash
warden rules keygen acme                         # writes acme.key (SECRET) and acme.pub
warden rules build ./my-rules --name acme-core --version 12 \
       --description "ACME core detections" --key acme.key
# -> acme-core-12.wrp and acme-core-12.wrp.sig
```

Give users `acme.pub` once (through a channel they can trust) and then the
`.wrp` + `.wrp.sig` pair for each release. **Bump `--version` every time** —
Warden refuses a version that is not newer than the installed one.

Keep `acme.key` offline or in a secrets manager. Anyone who has it can sign
packs your users will accept. If it leaks, publish a new key and have users
`untrust` the old one.

## What Warden checks

| Check | When | On failure |
| --- | --- | --- |
| Ed25519 signature against your trust store | install, verify | refused (`--allow-unsigned` overrides for packs with **no** signature only; a *bad* signature is always refused) |
| Version is newer than the active one | install | refused (`--allow-downgrade` overrides) |
| Every file matches the SHA-256 in the manifest; no extra or missing files | install, verify | refused |
| File names stay inside the pack; only `.yar` `.yara` `.txt` `.md` `.json` | install, verify | refused |
| Size limits (64 MiB pack, 2,000 files) | install, verify | refused |
| All YARA compiles | install, build | refused — the previous version stays active |
| Installed files still match the manifest; nothing was added | **every scan** | the pack is not loaded and the scan is reported **incomplete** |

Installation is atomic: a pack is unpacked beside the current version and
activated by one state-file swap. The three previous versions are kept for
rollback.

## Format

A pack is a zip file (conventionally `<name>-<version>.wrp`):

```
manifest.json
rules/anything.yar
malware_hashes.txt        (optional: one SHA-256 per line, "hash  label")
```

```json
{
  "format": 1,
  "name": "acme-core",
  "version": 12,
  "created": "2026-10-04T12:00:00+00:00",
  "description": "ACME core detections",
  "files": { "rules/anything.yar": "<sha256>", "malware_hashes.txt": "<sha256>" }
}
```

`name` is 1–64 characters of `a-z 0-9 - _`; `version` is a positive integer.

The detached signature (`<pack>.sig`) is JSON:

```json
{ "algorithm": "ed25519", "key_id": "3fa1c09d7b2e4a10", "signature": "<base64>" }
```

computed over the bytes `"warden-rulepack-v1\n"` followed by the pack file. The
key id is the first 16 hex characters of the SHA-256 of the raw public key. Keys
are raw 32-byte Ed25519 keys, base64-encoded.

Rule severity comes from each rule's `severity` metadata (`"low"` … `"critical"`;
default medium).
