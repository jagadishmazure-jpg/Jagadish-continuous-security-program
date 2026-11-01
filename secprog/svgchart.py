"""Inline SVG charts for HTML email (no JavaScript, no external images, deterministic output)."""
from __future__ import annotations

from html import escape

COLORS = {"good": "#2e7d32", "warn": "#f9a825", "bad": "#c62828", "info": "#1565c0", "muted": "#90a4ae"}


def hbar(rows: list[tuple[str, float]], maximum: float | None = None, unit: str = "", color: str = "info",
         width: int = 520, title: str = "") -> str:
    """Horizontal bar chart. rows = [(label, value)]."""
    maximum = maximum or max([v for _, v in rows] + [1])
    h = 22 * len(rows) + (24 if title else 4)
    parts = [(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{h}" role="img" '
              f'aria-label="{escape(title or "bar chart")}">')]
    y = 4
    if title:
        parts.append(f'<text x="0" y="14" font-family="Arial" font-size="13" font-weight="bold">{escape(title)}</text>')
        y = 24
    for label, v in rows:
        w = 0 if maximum <= 0 else int(round(min(1, max(0, v / maximum)) * (width - 240)))
        parts.append(f'<text x="0" y="{y + 13}" font-family="Arial" font-size="11">{escape(str(label)[:30])}</text>')
        parts.append(f'<rect x="170" y="{y + 2}" width="{w}" height="14" fill="{COLORS.get(color, color)}"/>')
        parts.append(f'<text x="{176 + w}" y="{y + 13}" font-family="Arial" font-size="11">{v:g}{escape(unit)}</text>')
        y += 22
    parts.append("</svg>")
    return "".join(parts)


def stacked(rows: list[tuple[str, dict]], keys: list[tuple[str, str]], width: int = 520, title: str = "") -> str:
    """Stacked horizontal bars. keys = [(key, color)]. Each row value is {key: count}."""
    total = max([sum(d.values()) for _, d in rows] + [1])
    h = 22 * len(rows) + 44
    parts = [(f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{h}" role="img" '
              f'aria-label="{escape(title or "stacked chart")}">'),
             f'<text x="0" y="14" font-family="Arial" font-size="13" font-weight="bold">{escape(title)}</text>']
    y = 24
    for label, d in rows:
        parts.append(f'<text x="0" y="{y + 13}" font-family="Arial" font-size="11">{escape(str(label)[:30])}</text>')
        x = 170
        for k, c in keys:
            w = int(round(d.get(k, 0) / total * (width - 200)))
            if w:
                parts.append(f'<rect x="{x}" y="{y + 2}" width="{w}" height="14" fill="{COLORS.get(c, c)}"/>')
            x += w
        parts.append(f'<text x="{x + 6}" y="{y + 13}" font-family="Arial" font-size="11">{sum(d.values())}</text>')
        y += 22
    lx = 0
    for k, c in keys:
        parts.append(f'<rect x="{lx}" y="{y + 4}" width="10" height="10" fill="{COLORS.get(c, c)}"/>'
                     f'<text x="{lx + 14}" y="{y + 13}" font-family="Arial" font-size="10">{escape(k)}</text>')
        lx += 14 + 7 * len(k) + 16
    parts.append("</svg>")
    return "".join(parts)


def sparkline(values: list[float], width: int = 160, height: int = 30, color: str = "info") -> str:
    if not values:
        return ""
    lo, hi = min(values), max(values)
    span = (hi - lo) or 1
    step = width / max(1, len(values) - 1)
    pts = " ".join(f"{i * step:.1f},{height - 2 - (v - lo) / span * (height - 4):.1f}" for i, v in enumerate(values))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" role="img" aria-label="trend">'
            f'<polyline fill="none" stroke="{COLORS.get(color, color)}" stroke-width="2" points="{pts}"/></svg>')


def ring(pct: float, label: str, sub: str = "", size: int = 120) -> str:
    """Readiness ring (donut). pct 0-100. Color: >=80 good, >=50 warn, else bad."""
    import math
    pct = max(0.0, min(100.0, float(pct)))
    r = size * 0.36
    c = size / 2
    circ = 2 * math.pi * r
    color = COLORS["good"] if pct >= 80 else COLORS["warn"] if pct >= 50 else COLORS["bad"]
    dash = f"{circ * pct / 100:.2f} {circ:.2f}"
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size + 34}" role="img" '
            f'aria-label="{escape(label)} {pct:g} percent ready">'
            f'<circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="#e0e0e0" stroke-width="{size * 0.1:.1f}"/>'
            f'<circle cx="{c}" cy="{c}" r="{r:.2f}" fill="none" stroke="{color}" stroke-width="{size * 0.1:.1f}" '
            f'stroke-dasharray="{dash}" transform="rotate(-90 {c} {c})"/>'
            f'<text x="{c}" y="{c + 5}" text-anchor="middle" font-family="Arial" font-size="{int(size * 0.16)}" '
            f'font-weight="bold">{pct:g}%</text>'
            f'<text x="{c}" y="{size + 12}" text-anchor="middle" font-family="Arial" font-size="11">'
            f'{escape(label[:22])}</text>'
            f'<text x="{c}" y="{size + 27}" text-anchor="middle" font-family="Arial" font-size="10" fill="#555">'
            f'{escape(sub[:28])}</text></svg>')


def cards(rows: list[dict], per_row: int = 4, size: int = 110) -> str:
    """Framework readiness card grid as an HTML table of rings (email-safe: tables, no CSS grid).
    rows = [{"name", "ready", "controls", "ready_pct", "coverage"}]."""
    cells = []
    for r in rows:
        sub = f"{r['ready']} / {r['controls']} ready"
        cells.append(f'<td style="padding:6px;text-align:center;vertical-align:top">'
                     f'{ring(r["ready_pct"], r["name"], sub, size)}'
                     f'<div style="font:10px Arial;color:#777">{escape(r.get("coverage", "").split(" ")[0])}</div></td>')
    trs = ["<tr>" + "".join(cells[i:i + per_row]) + "</tr>" for i in range(0, len(cells), per_row)]
    return '<table role="presentation" style="border-collapse:collapse">' + "".join(trs) + "</table>"
