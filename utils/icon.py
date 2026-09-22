"""PrimeProxy app icon rendering (shared across platforms).

Modern flat/glass design: deep diagonal gradient on a rounded "squircle"
tile, soft-lit lightning bolt with glow and shadow, diagonal glass sheen,
bottom vignette and a crisp light edge - all fully procedural (Pillow only).
"""
from __future__ import annotations

import math
from typing import TYPE_CHECKING, List, Sequence, Tuple

if TYPE_CHECKING:
    from PIL import Image

# Depth gradient (top-left light amber -> bottom-right deep orange).
_BASE_STOPS = [
    (0.00, (255, 216, 132)),
    (0.35, (255, 146, 26)),
    (0.72, (245, 96, 20)),
    (1.00, (212, 62, 12)),
]
# Warm "energy" glow behind the bolt.
_GLOW_STOPS = [
    (0.00, (255, 229, 170, 120)),
    (0.55, (255, 204, 128, 50)),
    (1.00, (255, 204, 128, 0)),
]
# Bolt body: near-white on top, warm cream at the bottom for a subtle 3D tilt.
_BOLT_STOPS = [
    (0.00, (255, 255, 255)),
    (1.00, (255, 238, 212)),
]
# Diagonal glass sheen over the tile.
_SHEEN_STOPS = [
    (0.00, (255, 255, 255, 160)),
    (0.45, (255, 255, 255, 80)),
    (0.72, (255, 255, 255, 0)),
]
# Grounding vignette (dark, centred near the bottom edge).
_VIGNETTE_STOPS = [
    (0.00, (80, 26, 8, 0)),
    (0.60, (80, 26, 8, 40)),
    (1.00, (80, 26, 8, 82)),
]

# Lightning bolt in normalized [0..100] coords (classic sharp bolt, kept narrow
# and tall so it reads well even at 16x16 tray sizes).
_BOLT = [(62, 8), (25, 56), (44, 56), (30, 92), (79, 44), (58, 44)]

_Color = Tuple[int, ...]


def _lerp(a: Sequence[float], b: Sequence[float], t: float) -> Tuple[int, ...]:
    return tuple(round(a[i] + (b[i] - a[i]) * t) for i in range(len(a)))


def _sample(stops: Sequence[Tuple[float, _Color]], t: float) -> Tuple[int, ...]:
    if t <= stops[0][0]:
        return tuple(stops[0][1])
    for i in range(1, len(stops)):
        t0, c0 = stops[i - 1]
        t1, c1 = stops[i]
        if t <= t1:
            span = max(t1 - t0, 1e-6)
            return _lerp(c0, c1, (t - t0) / span)
    return tuple(stops[-1][1])


def _diag(size: int, stops: Sequence[Tuple[float, _Color]]) -> "Image.Image":
    """Top-left -> bottom-right smooth gradient, built small then upscaled."""
    from PIL import Image

    w = h = 96
    im = Image.new("RGBA", (w, h))
    px = im.load()
    for y in range(h):
        for x in range(w):
            t = (x / max(w - 1, 1) + y / max(h - 1, 1)) / 2.0
            px[x, y] = _sample(stops, t)
    if size == w:
        return im
    return im.resize((size, size), Image.LANCZOS)


def _vertical(size: int, stops: Sequence[Tuple[float, _Color]]) -> "Image.Image":
    from PIL import Image

    w = 1
    h = 96
    im = Image.new("RGBA", (w, h))
    px = im.load()
    for y in range(h):
        t = y / max(h - 1, 1)
        px[0, y] = _sample(stops, t)
    if size == h:
        return im
    return im.resize((size, size), Image.LANCZOS)


def _radial(
    size: int,
    cx: float,
    cy: float,
    r: float,
    stops: Sequence[Tuple[float, _Color]],
) -> "Image.Image":
    from PIL import Image

    w = h = 96
    im = Image.new("RGBA", (w, h))
    px = im.load()
    for y in range(h):
        yy = y / max(h - 1, 1)
        for x in range(w):
            xx = x / max(w - 1, 1)
            d = math.hypot(xx - cx, yy - cy) / r
            px[x, y] = _sample(stops, min(d, 1.0))
    if size == w:
        return im
    return im.resize((size, size), Image.LANCZOS)


def render_icon(size: int) -> "Image.Image":
    """Render the modern PrimeProxy icon at the given size (anti-aliased)."""
    from PIL import Image, ImageChops, ImageDraw, ImageFilter

    scale = 8 if size <= 48 else 4
    big = size * scale

    img = Image.new("RGBA", (big, big), (0, 0, 0, 0))

    margin = max(1, round(big * 0.028))
    radius = max(1, round(big * 0.228))
    box = (margin, margin, big - margin - 1, big - margin - 1)

    # Squircle tile mask.
    tile_mask = Image.new("L", (big, big), 0)
    ImageDraw.Draw(tile_mask).rounded_rectangle(box, radius=radius, fill=255)

    # 1. Diagonal depth gradient.
    base = _diag(big, _BASE_STOPS)
    base.putalpha(tile_mask)
    img.alpha_composite(base)

    # 2. Warm energy glow behind the bolt.
    glow = _radial(big, 0.5, 0.56, 0.62, _GLOW_STOPS)
    glow.putalpha(ImageChops.multiply(glow.split()[3], tile_mask))
    img.alpha_composite(glow)

    # 3. Bolt.
    inner = big * 0.60
    cx, cy = big / 2, big * 0.545
    pts = [
        (cx + (x - 50) / 100 * inner, cy + (y - 50) / 100 * inner)
        for x, y in _BOLT
    ]
    bolt_raw = Image.new("L", (big, big), 0)
    ImageDraw.Draw(bolt_raw).polygon(pts, fill=255)
    # Round the corners and feather the edges (modern soft look).
    bolt = bolt_raw.filter(ImageFilter.GaussianBlur(max(2.0, big * 0.012)))
    bolt = bolt.point(lambda v: 255 if v > 118 else 0)

    # 3a. Soft drop shadow under the bolt.
    shadow_a = bolt.filter(ImageFilter.GaussianBlur(max(2.0, big * 0.03)))
    shadow_a = ImageChops.offset(shadow_a, 0, round(big * 0.035))
    shadow = Image.new("RGBA", (big, big), (132, 38, 4, 255))
    shadow.putalpha(shadow_a.point(lambda v: int(v * 0.48)))
    img.alpha_composite(shadow)

    # 3b. Faint white halo so the bolt "lights" the glass.
    halo_a = bolt.filter(ImageFilter.GaussianBlur(max(2.0, big * 0.04)))
    halo = Image.new("RGBA", (big, big), (255, 244, 214, 255))
    halo.putalpha(halo_a.point(lambda v: int(v * 0.40)))
    img.alpha_composite(halo)

    # 3c. Bolt body with a subtle vertical gradient.
    body = _vertical(big, _BOLT_STOPS).split()[:3]
    body = Image.merge("RGBA", body + (bolt,))
    img.alpha_composite(body)

    # 4. Diagonal glass sheen.
    sheen = _diag(big, _SHEEN_STOPS)
    sheen.putalpha(ImageChops.multiply(sheen.split()[3], tile_mask))
    img.alpha_composite(sheen)

    # 5. Bottom vignette for grounding.
    vignette = _radial(big, 0.5, 0.74, 0.58, _VIGNETTE_STOPS)
    vignette.putalpha(ImageChops.multiply(vignette.split()[3], tile_mask))
    img.alpha_composite(vignette)

    # 6. Crisp inner light edge.
    edge = Image.new("RGBA", (big, big), (0, 0, 0, 0))
    ImageDraw.Draw(edge).rounded_rectangle(
        box,
        radius=radius,
        outline=(255, 255, 255, 42),
        width=max(1, big // 220),
    )
    img.alpha_composite(edge)

    if (big, big) != (size, size):
        img = img.resize((size, size), Image.LANCZOS)
    return img


def generate_ico(output_path: str) -> None:
    """Write icon.ico with multiple sizes for Windows."""
    sizes = ((16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256))
    render_icon(256).save(output_path, format="ICO", sizes=sizes)