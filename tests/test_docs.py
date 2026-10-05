"""Keep the documentation honest.

Docs drift: a command gets renamed, a limit changes, a setting is added, and the
README goes on describing the old world. These tests tie the specific, checkable
statements in the docs to the code they describe, so a change to either one
fails here until the other is updated.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import typer

from warden import __version__
from warden.archive import ArchiveLimits
from warden.cli import _CONFIG_FIELDS, app
from warden.config import DEFAULT_MAX_SCAN_BYTES, Config
from warden.engines.clamav import STALE_AFTER_DAYS
from warden.gui import server as gui

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
CLI = typer.main.get_command(app)


def _doc(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def _is_group(cmd) -> bool:
    return hasattr(cmd, "commands")


def _resolve(words: list[str]):
    """Walk ``warden a b --flag`` down the command tree; return the command
    reached and the remaining words."""
    cmd = CLI
    rest = list(words)
    while rest and rest[0].startswith("--") and rest[0] in {o for p in cmd.params for o in p.opts}:
        rest.pop(0)                                  # global options such as --offline
    while rest and _is_group(cmd) and rest[0] in cmd.commands:
        cmd = cmd.commands[rest.pop(0)]
    return cmd, rest


def _documented_commands(text: str) -> list[str]:
    out = []
    for block in re.findall(r"```(?:bash|powershell)?\n(.*?)```", text, re.S):
        for line in block.splitlines():
            line = line.split("#", 1)[0].strip()
            if line.startswith("warden "):
                out.append(line)
    return out


DOCS_WITH_COMMANDS = ["README.md", "docs/COMPLIANCE.md", "docs/PRIVACY.md", "docs/RULE_PACKS.md",
                      "docs/ACCESSIBILITY.md", "docs/THREAT_MODEL.md"]


@pytest.mark.parametrize("doc", DOCS_WITH_COMMANDS)
def test_every_documented_command_and_option_exists(doc):
    commands = _documented_commands(_doc(doc))
    if doc == "README.md":
        assert len(commands) > 40
    for line in commands:
        words = line.split()[1:]
        cmd, rest = _resolve(words)
        assert not _is_group(cmd), f"{doc}: `{line}` stops at a command group"
        valid = {o for p in cmd.params for o in list(p.opts) + list(p.secondary_opts)}
        for word in rest:
            if word.startswith("--") or re.fullmatch(r"-[a-zA-Z]", word):
                flag = word.split("=", 1)[0]
                assert flag in valid, f"{doc}: `{line}` uses {flag}, which `{cmd.name}` does not have"


def test_inline_command_mentions_exist():
    """`warden x y` written inline in prose must be a real command too."""
    for doc in DOCS_WITH_COMMANDS + ["SECURITY.md", "CONTRIBUTING.md", "docs/RELEASING.md"]:
        for mention in re.findall(r"`warden ([a-z][a-z-]*(?: [a-z][a-z-]*)?)", _doc(doc)):
            words = mention.split()
            cmd, rest = _resolve(words)
            consumed = len(words) - len(rest)
            assert consumed >= 1, f"{doc}: `warden {mention}` is not a command"
            if len(words) == 2 and _is_group(_resolve(words[:1])[0]):
                assert consumed == 2, f"{doc}: `warden {mention}` - no such subcommand"


def test_every_cli_command_is_documented_in_the_readme():
    def walk(cmd, prefix):
        if _is_group(cmd):
            for name, sub in cmd.commands.items():
                yield from walk(sub, prefix + [name])
        else:
            yield " ".join(prefix)

    undocumented = [c for c in walk(CLI, []) if f"warden {c}" not in README
                    and c not in ("version", "update-rules", "config get", "config unset", "config path",
                                  "rules verify", "rules remove", "rules trust", "rules untrust",
                                  "rules keys", "rules keygen", "rules build", "rules sign",
                                  "audit export", "audit prune")]     # covered in the linked docs
    assert not undocumented, f"commands missing from README usage: {undocumented}"
    rule_doc = _doc("docs/RULE_PACKS.md")
    for sub in ("verify", "remove", "trust", "untrust", "keys", "keygen", "build"):
        assert f"warden rules {sub}" in rule_doc


def test_settings_table_matches_the_code():
    rows = dict(re.findall(r"^\| `([a-z_]+)` \| ([^|]+) \|", README, re.M))
    assert set(rows) == set(_CONFIG_FIELDS), "README settings table and _CONFIG_FIELDS differ"
    defaults = Config()
    for name, shown in rows.items():
        value = getattr(defaults, name)
        shown = shown.strip().strip("`")
        if isinstance(value, bool):
            assert shown == str(value).lower(), name
        elif name == "max_scan_bytes":
            assert shown == f"{DEFAULT_MAX_SCAN_BYTES // (1024 * 1024)} MB"
        else:
            assert shown == str(value), name


def test_documented_limits_match_the_code():
    threat = _doc("docs/THREAT_MODEL.md")
    limits = ArchiveLimits()
    mib = 1024 * 1024
    assert f"{limits.max_members:,} members" in threat
    assert f"{limits.max_member_bytes // mib} MiB per member" in threat
    assert f"{limits.max_total_bytes // mib} MiB\n  per top-level file" in threat or \
        f"{limits.max_total_bytes // mib} MiB per top-level file" in threat.replace("\n ", "")
    assert f"{limits.max_ratio}:1 ratio" in threat and f"{limits.max_depth} nesting levels" in threat
    assert f"{gui._MAX_BODY // mib} MiB bodies" in threat
    assert f"{gui._MAX_ACTIVE_JOBS} concurrent jobs" in threat
    assert f"{gui._JOB_TIME_LIMIT // 3600} h / {gui._JOB_MAX_FILES:,} files per" in threat
    assert f"{gui._SOCKET_TIMEOUT} s socket timeout" in threat
    assert "three levels" in README and limits.max_depth == 3
    assert f"more than {STALE_AFTER_DAYS} days old" in _doc("CHANGELOG.md")


def test_exit_codes_documented():
    for code, word in (("`0`", "Clean"), ("`1`", "threats"), ("`2`", "Incomplete")):
        assert re.search(rf"\| {code} \| [^|]*{word}", README)


def test_version_is_consistent_everywhere():
    pyproject = _doc("pyproject.toml")
    assert f'version = "{__version__}"' in pyproject
    changelog = _doc("CHANGELOG.md")
    assert f"## [{__version__}]" in changelog and f"[{__version__}]: https://" in changelog
    assert f"**Version evaluated:** {__version__}" in _doc("docs/ACCESSIBILITY.md")


def test_platform_table_matches_the_release_workflow():
    workflow = _doc(".github/workflows/release.yml")
    assets = set(re.findall(r"asset: (warden-[a-z0-9.-]+)", workflow))
    assert len(assets) == 5
    for asset in assets:
        assert f"`{asset}`" in README, f"{asset} is built but not in the README download table"
        assert asset in _doc("docs/VERIFY.md") and asset in _doc("docs/RELEASING.md")
    installers = _doc("scripts/install.sh") + _doc("scripts/install.ps1")
    for asset in assets:
        assert asset in installers


def test_internal_links_resolve():
    docs = ["README.md", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md"] + \
        [str(p.relative_to(ROOT)).replace("\\", "/") for p in (ROOT / "docs").glob("*.md")]
    for doc in docs:
        base = (ROOT / doc).parent
        for target in re.findall(r"\]\((?!https?://|#|mailto:)([^)#\s]+)(?:#[^)]*)?\)", _doc(doc)):
            assert (base / target).exists(), f"{doc}: broken link to {target}"


def test_readme_anchors_exist():
    headings = {re.sub(r"[^a-z0-9 -]", "", h.lower()).strip().replace(" ", "-")
                for h in re.findall(r"^#{2,3} (.+)$", README, re.M)}
    for anchor in re.findall(r"\]\(#([a-z0-9-]+)\)", README):
        assert anchor in headings, f"README links to #{anchor}, which is not a heading"


def test_docs_do_not_overclaim():
    compliance = _doc("docs/COMPLIANCE.md")
    for phrase in ("holds no certification", "not real-time", "Not validated", "Never tested"):
        assert phrase.lower() in compliance.lower()
    # No document may claim a certification Warden does not have.
    for doc in ["README.md", "docs/COMPLIANCE.md", "docs/ACCESSIBILITY.md", "SECURITY.md"]:
        text = _doc(doc)
        for claim in ("is SOC 2 compliant", "is HIPAA compliant", "is ISO 27001 certified",
                      "FIPS validated", "FIPS-compliant", "ADA compliant", "ADA-certified",
                      "is PCI compliant", "guarantees detection"):
            assert claim.lower() not in text.lower(), f"{doc} claims: {claim}"
    assert "self-assessment" in _doc("docs/ACCESSIBILITY.md")
    assert "not real-time" in README.lower()


def test_security_policy_channel_is_described():
    assert "security/advisories/new" in _doc("SECURITY.md")
