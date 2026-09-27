"""Generate Warden's app icon (shield + checkmark) as PNG and multi-size ICO.

Run once when the brand mark changes:
    python packaging/make_icon.py
Outputs into assets/: icon-256.png, icon-512.png, favicon-32.png, warden.ico
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

ASSETS = Path(__file__).resolve().parent.parent / "assets"
ASSETS.mkdir(exist_ok=True)

TOP = (59, 142, 234)      # #3b8eea
BOT = (26, 86, 179)       # #1a56b3
WHITE = (255, 255, 255)


def _cubic(p0, c1, c2, p3, n=18):
    out = []
    for i in range(n + 1):
        t = i / n
        mt = 1 - t
        x = mt**3 * p0[0] + 3 * mt**2 * t * c1[0] + 3 * mt * t**2 * c2[0] + t**3 * p3[0]
        y = mt**3 * p0[1] + 3 * mt**2 * t * c1[1] + 3 * mt * t**2 * c2[1] + t**3 * p3[1]
        out.append((x, y))
    return out


def _shield_points(s: float) -> list[tuple[float, float]]:
    # Trace the exact (symmetric) SVG shield path on a 64-unit grid.
    pts = [(32, 4), (56, 12), (56, 30)]
    pts += _cubic((56, 30), (56, 46), (46, 55), (32, 60))
    pts += _cubic((32, 60), (18, 55), (8, 46), (8, 30))
    pts += [(8, 12)]
    return [(x / 64 * s, y / 64 * s) for x, y in pts]


def _vgrad(size: int, top, bot) -> Image.Image:
    grad = Image.new("RGB", (1, size))
    for y in range(size):
        t = y / max(1, size - 1)
        grad.putpixel((0, y), tuple(round(top[i] + (bot[i] - top[i]) * t) for i in range(3)))
    return grad.resize((size, size))


def render(size: int) -> Image.Image:
    ss = size * 4  # supersample for smooth edges
    img = Image.new("RGBA", (ss, ss), (0, 0, 0, 0))
    mask = Image.new("L", (ss, ss), 0)
    ImageDraw.Draw(mask).polygon(_shield_points(ss), fill=255)
    grad = _vgrad(ss, TOP, BOT).convert("RGBA")
    img.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(img)
    # checkmark
    p = [(21, 32.5), (28.5, 40), (44, 23)]
    p = [(x / 64 * ss, y / 64 * ss) for x, y in p]
    draw.line(p, fill=WHITE, width=int(ss * 0.078), joint="curve")
    r = ss * 0.039
    for (x, y) in (p[0], p[2]):
        draw.ellipse([x - r, y - r, x + r, y + r], fill=WHITE)

    return img.resize((size, size), Image.LANCZOS)


def main() -> None:
    render(256).save(ASSETS / "icon-256.png")
    render(512).save(ASSETS / "icon-512.png")
    render(32).save(ASSETS / "favicon-32.png")
    ico = render(256)
    ico.save(ASSETS / "warden.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("wrote icon-256.png, icon-512.png, favicon-32.png, warden.ico to", ASSETS)


if __name__ == "__main__":
    main()
