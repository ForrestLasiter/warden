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

Things we especially want to hear about:

- A crafted file that causes Warden to execute code, escape the scan sandbox, or
  crash in an exploitable way.
- Quarantine escapes — a way for a quarantined file to run or to overwrite an
  arbitrary path on restore.
- The local dashboard being reachable or driveable by another process or a
  web page (it binds to `127.0.0.1` and requires a per-session token by design).

## Supported versions

Warden is pre-1.0; security fixes land on the latest release. Please test against
the newest version before reporting.

## A note on detection

Warden is an **on-demand scanner**, not a real-time antivirus, and it is not a
replacement for your operating system's built-in protection (e.g. Microsoft
Defender). Missed detections and false positives are expected in any scanner and
are best filed as regular issues, not security reports.
