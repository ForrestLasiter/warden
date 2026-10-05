# Accessibility conformance

Warden's dashboard is built to **WCAG 2.1 Level AA**, which is the technical
standard used for the ADA (U.S. Department of Justice Title II rule; widely
applied to Title III), **Section 508** (which incorporates WCAG 2.0 AA), and the
EU's **EN 301 549**. This page is an honest account of how that was checked,
what was found, and what has not been verified.

- **Product:** Warden dashboard (`warden gui`) and command-line interface
- **Version evaluated:** 0.6.0
- **Evaluated:** October 2026
- **Standard:** WCAG 2.1 A and AA (all 50 success criteria), plus the new A/AA
  criteria of WCAG 2.2
- **Result:** no known failures of WCAG 2.1 AA

## What kind of assessment this is

A **self-assessment by automated and scripted testing** — not an audit by an
independent accessibility firm, and **not** testing by people who use assistive
technology day to day. Specifically:

| Done | Not done |
| --- | --- |
| axe-core 4.13 in Chromium against **13 views/states × 2 themes × 2 viewport sizes** (52 runs): 0 violations | Manual testing with NVDA, JAWS, VoiceOver, TalkBack or Narrator by a person |
| Scripted keyboard walk: tab order, visible focus on every stop, tab-list arrow keys, dialog focus trap / Escape / focus return | Testing with speech input, switch access, or screen magnifiers |
| Scripted checks: reflow at 320 CSS px, target size, text-spacing overrides, control-boundary contrast | Usability testing with disabled users |
| Every colour pair recomputed from the stylesheet for both themes (in CI on every change) | Third-party audit or certification |
| Review of each success criterion against the code | Browsers other than Chromium for the automated run |

Automated tools find a minority of accessibility problems. If you use assistive
technology and something does not work, that is a bug we want:
[open an issue](https://github.com/ForrestLasiter/warden/issues).

### What the October 2026 audit found and fixed

The dashboard had previously been described as WCAG 2.1 AA on the strength of a
lighter self-check. A proper audit found real failures, all fixed in 0.6.0:

| Criterion | Problem | Now |
| --- | --- | --- |
| 1.4.3 Contrast | Dark theme: white text on the primary / pressed fill was 3.74:1, on the danger fill and "Critical" badge 2.52:1; selected navigation text 4.08:1 | ≥ 4.5:1 everywhere |
| 1.4.3 Contrast | Hovering a filled button replaced its fill with light grey under white text (1.35:1) | Filled buttons keep their fill |
| 1.4.10 Reflow | The page scrolled sideways at 320 CSS px (400 % zoom) | No horizontal scrolling; wide tables scroll inside their own focusable region |
| 1.4.11 Non-text contrast | Input and button boundaries were about 2:1 | ≥ 3:1 in both themes |
| 3.3.1 / 3.3.3 Errors | Errors appeared only in a message that vanished after a few seconds | Persistent, next to the form, tied to the field, with a suggestion; focus returns to the field |
| 4.1.3 Status messages | Results containers were live regions (a screen reader would read every row); the progress counter was announced on every update | One throttled progress announcement; focus moves to the result summary when a scan ends |
| 1.3.1 / 2.4.1 | The "Warden has stopped" screen had no main landmark | Fixed |

## WCAG 2.1 conformance table

"Supports" means the criterion is met in every view, in both themes.

### Perceivable

| Criterion | Level | Result | Notes |
| --- | --- | --- | --- |
| 1.1.1 Non-text Content | A | Supports | All icons are decorative and hidden from assistive technology; every control has a text name |
| 1.2.1 – 1.2.5 Time-based media | A/AA | Not applicable | No audio or video |
| 1.3.1 Info and Relationships | A | Supports | Landmarks, headings, labelled fields, table captions and header scopes, tab list / tab panels, definition lists |
| 1.3.2 Meaningful Sequence | A | Supports | DOM order matches visual order |
| 1.3.3 Sensory Characteristics | A | Supports | No instruction relies on shape, colour or position |
| 1.3.4 Orientation | AA | Supports | Works in portrait and landscape |
| 1.3.5 Identify Input Purpose | AA | Not applicable | No fields collect information about the user |
| 1.4.1 Use of Color | A | Supports | Severity badges carry a text label; the selected section also has a bar and bold weight; errors are text |
| 1.4.2 Audio Control | A | Not applicable | No audio |
| 1.4.3 Contrast (Minimum) | AA | Supports | Lowest text pair: 4.52:1 (light), 4.62:1 (dark). Checked in CI |
| 1.4.4 Resize Text | AA | Supports | Relative units throughout; usable at 200 % and 400 % |
| 1.4.5 Images of Text | AA | Supports | None used |
| 1.4.10 Reflow | AA | Supports | No two-dimensional scrolling at 320 CSS px; data tables use the permitted exception and scroll within a labelled, keyboard-focusable region |
| 1.4.11 Non-text Contrast | AA | Supports | Control boundaries, focus ring and state fills ≥ 3:1 (lowest 3.24:1). Checked in CI |
| 1.4.12 Text Spacing | AA | Supports | No clipping with the WCAG spacing overrides applied |
| 1.4.13 Content on Hover or Focus | AA | Supports | No custom hover or focus pop-ups |

### Operable

| Criterion | Level | Result | Notes |
| --- | --- | --- | --- |
| 2.1.1 Keyboard | A | Supports | Every function works from the keyboard |
| 2.1.2 No Keyboard Trap | A | Supports | The confirm dialog holds focus by design and releases it on Escape, Cancel or confirm |
| 2.1.4 Character Key Shortcuts | A | Not applicable | No single-key shortcuts |
| 2.2.1 Timing Adjustable | A | Supports | No time limits on the user. Brief status messages duplicate information that stays on the page |
| 2.2.2 Pause, Stop, Hide | A | Supports | The only motion is the progress spinner while a scan runs (essential; removed under `prefers-reduced-motion`; **Cancel scan** stops it) |
| 2.3.1 Three Flashes | A | Supports | Nothing flashes |
| 2.4.1 Bypass Blocks | A | Supports | "Skip to content" link; landmarks |
| 2.4.2 Page Titled | A | Supports | The title names the current section |
| 2.4.3 Focus Order | A | Supports | Logical order; focus moves to the result summary after a scan and back to the opener after a dialog |
| 2.4.4 Link Purpose (In Context) | A | Supports | Links that open a new tab say so |
| 2.4.5 Multiple Ways | AA | Supports | Every section is one step from the persistent navigation; Scan and Sweep are also reachable from Overview. (The dashboard is one page with five views.) |
| 2.4.6 Headings and Labels | AA | Supports | |
| 2.4.7 Focus Visible | AA | Supports | 2 px outline on every focus stop, never suppressed for keyboard users |
| 2.5.1 Pointer Gestures | A | Supports | Single clicks only |
| 2.5.2 Pointer Cancellation | A | Supports | Actions fire on release |
| 2.5.3 Label in Name | A | Supports | Accessible names contain the visible label |
| 2.5.4 Motion Actuation | A | Not applicable | |

### Understandable

| Criterion | Level | Result | Notes |
| --- | --- | --- | --- |
| 3.1.1 Language of Page | A | Supports | `lang="en"` |
| 3.1.2 Language of Parts | AA | Supports | Interface text is English only (file names are user data) |
| 3.2.1 On Focus | A | Supports | |
| 3.2.2 On Input | A | Supports | Changing a field never submits or navigates |
| 3.2.3 Consistent Navigation | AA | Supports | |
| 3.2.4 Consistent Identification | AA | Supports | |
| 3.3.1 Error Identification | A | Supports | Persistent text next to the form; the field is marked invalid and linked to the message |
| 3.3.2 Labels or Instructions | A | Supports | Visible labels; the path field has an example and a hint |
| 3.3.3 Error Suggestion | AA | Supports | Error messages say how to fix the problem |
| 3.3.4 Error Prevention (Legal, Financial, Data) | AA | Supports | Permanent deletion asks for confirmation; restoring a file that is still detected asks again |

### Robust

| Criterion | Level | Result | Notes |
| --- | --- | --- | --- |
| 4.1.1 Parsing | A | Supports | Unique IDs, valid nesting (criterion removed in WCAG 2.2) |
| 4.1.2 Name, Role, Value | A | Supports | Native controls or complete ARIA patterns (tabs, dialog) |
| 4.1.3 Status Messages | AA | Supports | Results, progress and errors are announced without moving focus unexpectedly |

### WCAG 2.2 additions (beyond the 2.1 AA target)

| Criterion | Level | Result | Notes |
| --- | --- | --- | --- |
| 2.4.11 Focus Not Obscured (Minimum) | AA | Supports | Scroll padding keeps focus clear of the sticky header |
| 2.5.7 Dragging Movements | AA | Not applicable | |
| 2.5.8 Target Size (Minimum) | AA | Supports | Every control is at least 24 × 24 CSS px |
| 3.2.6 Consistent Help | A | Supports | Help links are in the same place on every view |
| 3.3.7 Redundant Entry | A | Not applicable | |
| 3.3.8 Accessible Authentication (Minimum) | AA | Not applicable | There is no sign-in |

## Other accommodations

- **Themes:** light, dark, and follow-the-system. Both are tested to the same bar.
- **Reduced motion:** honoured (`prefers-reduced-motion`).
- **Windows High Contrast / forced colours:** selected and pressed states, badges
  and buttons are restated with system colours.
- **Zoom:** usable to 400 %.
- **No timeouts, no sign-in, no CAPTCHA.**

## Command line

The CLI is plain text and works with terminal screen readers.

- Severity is always written as a word (`High`, `Critical`), never colour alone.
- Set `NO_COLOR=1` to remove colour; `TERM=dumb` removes all styling.
- `--json` gives output with no tables or box drawing: on `inspect`, `privacy`,
  `posture`, `audit show`, `audit verify`, `schedule doctor` and `schedule test`
  it prints JSON; on `scan` and `sweep` it writes the full report to a file.
- `--quiet` on `scan` prints only the summary and threats.
- The progress spinner is shown only on an interactive terminal and is removed
  when the scan finishes; it is never written to redirected output.

## Documentation

The Markdown docs use headings in order, descriptive link text, real tables with
header rows, and alt text on images.

## Known limitations

- Not verified with real assistive technology by a human tester (see above).
- The installers and the console window that hosts the dashboard are ordinary
  terminal programs; their accessibility is that of your terminal.
- Third-party pages Warden links to (GitHub) are outside its control.

## Re-running the audit

```bash
pip install playwright && playwright install chromium
npm pack axe-core && tar -xzf axe-core-*.tgz
python packaging/a11y_audit.py package/axe.min.js
```

It starts its own dashboard on a throwaway data folder and exits non-zero on any
axe violation or failed scripted check. The colour and markup rules also run as
ordinary tests (`pytest tests/test_accessibility.py`) on every change.
