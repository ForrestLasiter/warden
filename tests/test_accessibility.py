"""Accessibility regression tests for the dashboard (WCAG 2.1 AA).

These run without a browser. They recompute colour-contrast ratios straight from
the design tokens in ``style.css`` for BOTH themes, and check the structural
rules of ``index.html`` / ``app.js`` that assistive technology depends on.

They exist because a theme change once left white text on a too-light fill in
dark mode while the light theme was fine - exactly the kind of regression a
person testing by eye in one theme will not see. The full audit (axe-core in a
real browser, keyboard, reflow, target size) is ``packaging/a11y_audit.py``; see
``docs/ACCESSIBILITY.md``.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parent.parent / "warden" / "gui" / "static"
CSS = (STATIC / "style.css").read_text(encoding="utf-8")
HTML = (STATIC / "index.html").read_text(encoding="utf-8")
JS = (STATIC / "app.js").read_text(encoding="utf-8")

TEXT = 4.5       # SC 1.4.3 normal-size text
NON_TEXT = 3.0   # SC 1.4.11 control boundaries, focus indicators, state fills


# -- colour maths --------------------------------------------------------
def _luminance(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    channels = [int(h[i:i + 2], 16) / 255 for i in (0, 2, 4)]
    lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = _luminance(a), _luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _tokens(block: str) -> dict[str, str]:
    return {m.group(1): m.group(2).lower()
            for m in re.finditer(r"--([a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,6})\b", block)}


def _block(selector_regex: str) -> str:
    m = re.search(selector_regex + r"\s*\{([^}]*)\}", CSS, re.S)
    assert m, f"CSS block not found: {selector_regex}"
    return m.group(1)


LIGHT = _tokens(_block(r"(?<![\w\[\]\"=-]):root"))
DARK_MEDIA = _tokens(_block(r':root:not\(\[data-theme="light"\]\)'))
DARK_FORCED = _tokens(_block(r':root\[data-theme="dark"\]'))
THEMES = {"light": LIGHT, "dark": {**LIGHT, **DARK_FORCED}}


def test_contrast_maths_matches_known_values():
    assert round(contrast("#000000", "#ffffff"), 1) == 21.0
    assert round(contrast("#767676", "#ffffff"), 2) == 4.54     # the classic AA boundary grey
    assert contrast("#ffffff", "#ffffff") == 1.0


def test_both_dark_definitions_are_identical():
    """Dark colours are declared twice (OS preference, and the explicit toggle).
    If they drift apart, one of the two routes into dark mode is untested."""
    assert DARK_MEDIA == DARK_FORCED
    assert set(DARK_FORCED) >= {"bg", "surface", "text", "muted", "accent", "accent-solid",
                                "accent-text", "control-border", "danger", "danger-solid"}


# (foreground token, background token, minimum ratio, where it is used)
TEXT_PAIRS = [
    ("text", "bg", TEXT, "body text"),
    ("text", "surface", TEXT, "card text"),
    ("text", "surface-2", TEXT, "buttons, hovered rows"),
    ("text", "sidebar", TEXT, "sidebar"),
    ("text", "btn-hover", TEXT, "hovered button label"),
    ("text", "info-bg", TEXT, "notice"),
    ("text", "warn-bg", TEXT, "coverage notes / warning notice"),
    ("text", "danger-bg", TEXT, "inline form error"),
    ("muted", "bg", TEXT, "secondary text"),
    ("muted", "surface", TEXT, "secondary text on cards"),
    ("muted", "surface-2", TEXT, "secondary text on hover"),
    ("muted", "sidebar", TEXT, "nav items, local-only note"),
    ("accent", "bg", TEXT, "footer links"),
    ("accent", "surface", TEXT, "links on cards"),
    ("accent-text", "accent-subtle", TEXT, "selected nav item"),
    ("accent-contrast", "accent-solid", TEXT, "primary button, pressed theme button, skip link"),
    ("#ffffff", "danger-solid", TEXT, "danger button, Critical badge"),
    ("success", "success-bg", TEXT, "Clean badge"),
    ("info", "info-bg", TEXT, "Info badge"),
    ("warn", "warn-bg", TEXT, "Low / Medium badge"),
    ("danger", "danger-bg", TEXT, "High badge, error label"),
    ("warn", "surface", TEXT, "offline note"),
]
NON_TEXT_PAIRS = [
    ("control-border", "bg", NON_TEXT, "input / select boundary"),
    ("control-border", "surface", NON_TEXT, "controls on cards"),
    ("control-border", "surface-2", NON_TEXT, "button boundary"),
    ("control-border", "sidebar", NON_TEXT, "theme switch boundary"),
    ("accent", "bg", NON_TEXT, "focus ring"),
    ("accent", "surface", NON_TEXT, "focus ring on cards"),
    ("accent", "surface-2", NON_TEXT, "focus ring on buttons"),
    ("accent", "sidebar", NON_TEXT, "focus ring in sidebar"),
    ("accent-solid", "surface", NON_TEXT, "primary button vs card; pressed vs unpressed theme button"),
    ("accent-solid", "sidebar", NON_TEXT, "pressed theme button vs sidebar"),
    ("danger-solid", "surface", NON_TEXT, "danger button vs card"),
    ("danger", "bg", NON_TEXT, "invalid-field border"),
]


def _color(theme: dict[str, str], token: str) -> str:
    return token if token.startswith("#") else theme[token]


@pytest.mark.parametrize("theme", ["light", "dark"])
@pytest.mark.parametrize("fg,bg,minimum,where", TEXT_PAIRS + NON_TEXT_PAIRS)
def test_color_contrast(theme, fg, bg, minimum, where):
    colors = THEMES[theme]
    ratio = contrast(_color(colors, fg), _color(colors, bg))
    assert ratio >= minimum, (
        f"{theme} theme: {fg} on {bg} is {ratio:.2f}:1, needs {minimum}:1 ({where})")


def test_filled_controls_use_the_solid_tokens():
    """White-on-fill controls must use the *-solid tokens (chosen for white
    text), never the lighter text-colour tokens."""
    for selector in (r"\.btn-primary, \.btn-primary:hover", r"\.btn-danger, \.btn-danger:hover",
                     r"\.badge-critical", r'\.theme-btn\[aria-pressed="true"\]', r"\.skip-link"):
        body = _block(selector)
        assert re.search(r"background:\s*var\(--(accent|danger)-solid\)", body), selector
    # Hover must not swap a filled button's background for the neutral hover fill.
    assert re.search(r"\.btn-primary:hover, \.btn-danger:hover\s*\{[^}]*filter", CSS)


def test_focus_is_always_visible():
    assert re.search(r":focus-visible\s*\{[^}]*outline:\s*2px solid var\(--accent\)", CSS)
    # Nothing may remove the outline except the :not(:focus-visible) mouse case.
    removed = re.findall(r"([^{}]+)\{[^}]*outline:\s*(?:none|0)\b", CSS)
    assert [s.strip() for s in removed] == [":focus:not(:focus-visible)"]


def test_motion_reflow_and_forced_colors_rules_exist():
    assert "prefers-reduced-motion: reduce" in CSS
    assert "forced-colors: active" in CSS
    assert "grid-template-columns: 248px minmax(0, 1fr)" in CSS      # content can shrink (1.4.10)
    assert re.search(r"\.table-wrap\s*\{[^}]*overflow-x:\s*auto", CSS)
    assert "scroll-padding-top" in CSS                                # focus not hidden by sticky bar
    assert re.search(r'input\[type="checkbox"\]\s*\{[^}]*width:\s*24px;\s*height:\s*24px', CSS)


# -- markup --------------------------------------------------------------
class _Doc(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.elements: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, {k: (v or "") for k, v in attrs}))


DOC = _Doc()
DOC.feed(HTML)
BY_ID = {a["id"]: (t, a) for t, a in DOC.elements if "id" in a}


def test_document_basics():
    html = next(a for t, a in DOC.elements if t == "html")
    assert html.get("lang") == "en"
    assert "<title>" in HTML
    viewport = next(a for t, a in DOC.elements if t == "meta" and a.get("name") == "viewport")
    assert "user-scalable=no" not in viewport["content"] and "maximum-scale" not in viewport["content"]
    assert any(t == "a" and a.get("class") == "skip-link" and a.get("href") == "#main" for t, a in DOC.elements)
    assert BY_ID["main"][0] == "main"


def test_no_positive_tabindex_and_ids_are_unique():
    ids = [a["id"] for _, a in DOC.elements if "id" in a]
    assert len(ids) == len(set(ids))
    for tag, attrs in DOC.elements:
        if "tabindex" in attrs:
            assert int(attrs["tabindex"]) <= 0, (tag, attrs)


def test_every_form_control_has_a_label():
    labelled = {a["for"] for t, a in DOC.elements if t == "label" and "for" in a}
    for tag, attrs in DOC.elements:
        if tag in ("input", "select", "textarea"):
            assert attrs.get("id") in labelled or attrs.get("aria-label"), (tag, attrs)


def test_aria_references_resolve():
    for tag, attrs in DOC.elements:
        for ref in ("aria-controls", "aria-labelledby", "aria-describedby"):
            for target in attrs.get(ref, "").split():
                assert target in BY_ID, f"<{tag}> {ref}={target!r} points nowhere"


def test_tabs_are_wired_to_panels():
    tabs = [a for t, a in DOC.elements if a.get("role") == "tab"]
    assert len(tabs) == 5
    assert [a["aria-selected"] for a in tabs].count("true") == 1
    for tab in tabs:
        panel = BY_ID[tab["aria-controls"]][1]
        assert panel.get("role") == "tabpanel" and panel.get("aria-labelledby") == tab["id"]
        assert tab["tabindex"] == ("0" if tab["aria-selected"] == "true" else "-1")   # roving tabindex
    tablist = next(a for _, a in DOC.elements if a.get("role") == "tablist")
    assert tablist.get("aria-label")


def test_dialog_and_live_regions():
    dialog = next(a for _, a in DOC.elements if a.get("role") == "dialog")
    assert dialog.get("aria-modal") == "true" and dialog.get("aria-labelledby") and dialog.get("aria-describedby")
    # Live regions are small and deliberate. A big results container must never
    # be one: a screen reader would read out every row that gets inserted.
    live = sorted(a.get("id", "?") for _, a in DOC.elements if "aria-live" in a or a.get("role") in ("status", "alert"))
    assert live == ["notices", "scanError", "srStatus", "sweepError", "toast"]


def test_decorative_svgs_are_hidden_and_buttons_have_names():
    for tag, attrs in DOC.elements:
        if tag == "svg":
            assert attrs.get("aria-hidden") == "true", attrs
    # Every <button> in the static markup contains visible text.
    for m in re.finditer(r"<button\b[^>]*>(.*?)</button>", HTML, re.S):
        text = re.sub(r"<svg.*?</svg>|<[^>]+>", "", m.group(1), flags=re.S).strip()
        assert text, m.group(0)[:80]


def test_new_tab_links_say_so():
    for m in re.finditer(r'<a\b[^>]*target="_blank"[^>]*>(.*?)</a>', HTML, re.S):
        assert "opens in a new tab" in m.group(1)
        assert 'rel="noopener"' in m.group(0)


# -- script behaviour (static) ------------------------------------------
def test_script_accessibility_contracts():
    # Untrusted text is inserted as text, never parsed as HTML.
    assert ".innerHTML = v" in JS and JS.count("innerHTML") == 1      # only the ICON-constant path
    # Errors are persistent, tied to the field, and focus goes back to it.
    assert 'setAttribute("aria-invalid", "true")' in JS and "aria-errormessage" in JS
    # Progress is announced on a throttle, not on every poll.
    assert "function srAnnounce" in JS and "6000" in JS
    # The dialog makes the page behind it inert and restores focus on close.
    assert '$(".app").inert = true' in JS and '$(".app").inert = false' in JS
    assert "modalOpener.focus()" in JS
    # Focus moves to the outcome when a scan finishes; the title tracks the view.
    assert "summary.focus()" in JS and "document.title =" in JS
    # Icon-only / repeated buttons get a name that says what they act on, and
    # that name still contains the visible label (SC 2.5.3).
    assert "`Quarantine this file: ${r.path}`" in JS
    assert "`Restore ${e.original_path}`" in JS
    # Wide tables are wrapped in a focusable, named scrolling region.
    assert 'role: "region"' in JS and 'tabindex: "0"' in JS
