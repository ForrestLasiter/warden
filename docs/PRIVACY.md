# Privacy: what Warden stores and what it sends

Run `warden privacy` at any time for this information about *your* installation
(add `--json` for a machine-readable version).

## The short version

- **No telemetry.** Warden has no analytics, crash reporting, update checks,
  accounts or "phone home" of any kind. There is no code for it.
- **Nothing leaves your computer by default.** The only features that use the
  network are ones you turn on yourself.
- **Scan history and quarantine records contain file paths.** They stay on your
  computer, but be aware of it before you share a report or a screenshot.

## What is stored on your computer

Everything lives in one folder: `~/.warden` (`C:\Users\<you>\.warden` on
Windows). On Linux and macOS it is created readable only by you.

| Location | What it contains | Created when |
| --- | --- | --- |
| `config.json` | Your settings. No secrets. | You change a setting |
| `history/*.json` | One report per saved scan: **the absolute path of every file scanned**, its size and SHA-256, every finding, timings, and the folder you scanned | `--save`, every dashboard scan, every scheduled scan |
| `quarantine/` | A neutralized (or encrypted) copy of each quarantined file, plus its **original absolute path**, hash, verdict and findings | You quarantine a file |
| `cache/reputation.json` | Hashes you looked up online and the answers | You use online lookups |
| `schedules.json` | Scheduled scans you created (name, target path, time) | `warden schedule add` |
| `rules/`, `rulepacks/`, `trusted_keys/` | Detection rules you added and the signing keys you trust | You add rules |
| `secrets/` | Your VirusTotal API key and quarantine encryption key, protected by the OS (DPAPI on Windows; the Keychain on macOS and libsecret on Linux keep them outside this folder) | You store a key / enable encryption |

### Things worth knowing

- **Absolute paths reveal more than you might expect** — your user name, project
  and client names, folder structure. A history report or a `--json` report is a
  list of them. Review a report before attaching it to a bug report.
- **History grows.** Each saved scan lists every file it looked at. Prune with
  `warden history prune --keep 20`.
- **Quarantine keeps the file.** A quarantined file is still on your disk until
  you delete it. By default it is only *neutralized* (so it can't run by
  accident), not encrypted: anyone who can read your home folder can recover it.
  Turn on `warden config set quarantine_encryption true` to seal new items with
  AES-256-GCM.
- **An exported quarantine bundle contains the flagged file** (neutralized) and
  its original path. Use `--password` when sending one to someone.
- **Scheduled scans** run as you and write to history like any other scan.

## What can be sent over the network

Only these, and only when you ask:

| Feature | How you turn it on | What is sent | To whom |
| --- | --- | --- | --- |
| Online hash reputation (keyless) | `--online`, `online_hash_lookup`, `warden lookup`, or the dashboard checkbox | The file's **SHA-1** | A DNS-over-HTTPS query via `cloudflare-dns.com` to Team Cymru's Malware Hash Registry — so Cloudflare's resolver and Team Cymru see the hash |
| Online hash reputation (VirusTotal) | The above **and** a VirusTotal API key you stored | The file's **SHA-256**, with your API key | `www.virustotal.com` |
| Rule pack from a URL | `warden rules install https://…` | An HTTPS request for that URL (and `<url>.sig`) | The server you named |

Never sent: file contents, file names, paths, your user name, your settings.

A hash is a fingerprint, not the file — but it does tell the provider that
*someone at your IP address has this exact file*. For a common program that
reveals little; for a unique document it could confirm you hold it. Only
executables, scripts, Office documents, PDFs and archives are looked up, lookups
are capped per scan, cached, and files inside archives are never looked up.

Not network features: the installers download the release from GitHub once, when
you run them. Warden itself never checks for updates.

### Offline mode

To make it impossible for Warden to use the network, whatever else is set:

```bash
warden --offline scan ~/Downloads       # this run
export WARDEN_OFFLINE=1                 # this shell / service
warden config set offline true          # always
```

In offline mode every network call is refused before a connection is opened;
`warden lookup` and URL rule-pack installs report that they are unavailable.

## The dashboard

`warden gui` serves a page from your own computer on `127.0.0.1`. It is not
reachable from your network, loads no third-party scripts, fonts or images, and
sets no cookies (your theme choice is kept in the browser's local storage).

## Erasing your data

```bash
warden history prune --keep 0     # delete all saved reports
warden quarantine purge --all     # permanently delete quarantined files
warden config unset online_hash_lookup
```

To remove everything, delete the `~/.warden` folder. Uninstalling the program
(`install.sh --uninstall` / `install.ps1 -Uninstall`) leaves that folder in
place so quarantined files are not destroyed by accident; delete it yourself if
you want it gone. On macOS and Linux, keys kept in the Keychain / libsecret are
removed with your keychain tool (they are named `warden-…`).
