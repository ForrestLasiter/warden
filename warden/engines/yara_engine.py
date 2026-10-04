"""YARA engine, built on yara-x (VirusTotal's Rust rewrite of YARA).

Compiles every ``.yar``/``.yara`` file found in the bundled rules dir and the
user rules dir into one rule set, then scans file bytes against it. Rule
severity comes from a ``severity`` metadata field on the rule (defaults to
MEDIUM), so rule authors control how loud a match is.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import yara_x
    _YARA_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover - env-specific
    yara_x = None  # type: ignore
    _YARA_IMPORT_ERROR = str(exc)

from ..models import Finding, Severity
from .base import ScanContext

_RULE_GLOBS = ("*.yar", "*.yara")


class YaraEngine:
    name = "yara"

    def __init__(self, rule_dirs: list[Path]):
        self._rules: Any = None
        self._rule_count = 0
        self._load_error: str | None = _YARA_IMPORT_ERROR
        self._compile_warnings: list[str] = []
        if yara_x is not None:
            self._compile(rule_dirs)

    # -- setup ------------------------------------------------------------
    def _compile(self, rule_dirs: list[Path]) -> None:
        sources: list[tuple[str, str]] = []
        for d in rule_dirs:
            if not d or not d.exists():
                continue
            for pattern in _RULE_GLOBS:
                for f in sorted(d.rglob(pattern)):
                    try:
                        sources.append((str(f), f.read_text(encoding="utf-8", errors="replace")))
                    except OSError as exc:
                        self._compile_warnings.append(f"{f}: {exc}")
        if not sources:
            self._load_error = "no YARA rule files found"
            return
        try:
            compiler = yara_x.Compiler()
            # Don't let one broken rule file sink the whole set.
            try:
                compiler.ignore_invalid_rules(True)  # type: ignore[call-arg]
            except TypeError:
                compiler.ignore_invalid_rules()  # type: ignore[call-arg]
            for origin, text in sources:
                try:
                    compiler.add_source(text, origin=origin)
                except TypeError:
                    # older/newer binding without origin kwarg
                    compiler.add_source(text)
                except Exception as exc:  # noqa: BLE001 - report and continue
                    self._compile_warnings.append(f"{origin}: {exc}")
            self._rules = compiler.build()
            # Count compiled rules by scanning an empty buffer's rule table is
            # not exposed; track source files instead as a rough indicator.
            self._rule_count = len(sources)
        except Exception as exc:  # noqa: BLE001
            self._load_error = f"YARA compile failed: {exc}"
            self._rules = None

    def available(self) -> bool:
        return self._rules is not None

    @property
    def load_error(self) -> str | None:
        """A genuine failure to compile rules that were expected to load.

        Distinct from "no rules found" (harmless): a broken ruleset silently
        reducing coverage must not let files be reported clean.
        """
        if self._rules is None and self._load_error and "no YARA rule" not in self._load_error:
            return self._load_error
        return None

    @property
    def status(self) -> str:
        if self.available():
            return f"{self._rule_count} rule file(s) loaded"
        return self._load_error or "unavailable"

    @property
    def warnings(self) -> list[str]:
        return self._compile_warnings

    # -- scan -------------------------------------------------------------
    def scan(self, ctx: ScanContext) -> list[Finding]:
        if self._rules is None:
            return []
        data = ctx.data()
        if not data:
            return []
        try:
            scanner = yara_x.Scanner(self._rules)
            results = scanner.scan(data)
        except Exception as exc:  # noqa: BLE001
            return [Finding.engine_error(self.name, f"YARA scan error: {exc!r}")]

        findings: list[Finding] = []
        for rule in results.matching_rules:
            meta = _meta_to_dict(rule.metadata)
            severity = _severity_from_meta(meta)
            desc = str(meta.get("description") or meta.get("desc") or rule.identifier)
            matched_patterns = [p.identifier for p in rule.patterns if p.matches]
            findings.append(Finding(
                engine=self.name,
                name=rule.identifier,
                severity=severity,
                description=desc,
                meta={
                    "namespace": rule.namespace,
                    "tags": list(rule.tags),
                    "patterns": matched_patterns[:10],
                    "author": meta.get("author"),
                    "reference": meta.get("reference"),
                },
            ))
        return findings


def _meta_to_dict(metadata) -> dict:
    """yara-x metadata is a tuple of (key, value) pairs."""
    out: dict = {}
    try:
        for pair in metadata:
            if len(pair) == 2:
                out[str(pair[0])] = pair[1]
    except TypeError:
        pass
    return out


def _severity_from_meta(meta: dict) -> Severity:
    raw = meta.get("severity")
    if raw is None:
        return Severity.MEDIUM
    try:
        return Severity.parse(raw)
    except (KeyError, ValueError):
        return Severity.MEDIUM
