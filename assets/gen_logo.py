#!/usr/bin/env python3
"""
Generate pixel-art SVG logos for "AGENTJAIL" in Press-Start-2P style.

Each glyph is 7×7 cells, strokes 2px wide. Cell size: 18px.
Gap between characters: 1 cell.

Run:  python3 assets/gen_logo.py
Writes: assets/agentjail-logo-light.svg  (dark pixels, for light backgrounds)
        assets/agentjail-logo-dark.svg   (light pixels, for dark backgrounds)
"""

import os

CELL = 18     # pixels per grid cell
ROWS = 7      # rows per glyph
CHAR_W = 7    # columns per glyph
GAP = 1       # blank columns between glyphs

# 7×7 bitmaps in Press-Start-2P chunky style (2-pixel strokes).
# 1 = filled cell, 0 = empty.  Row 0 = top.
GLYPHS = {
    'A': [
        [0,0,1,1,1,0,0],
        [0,1,1,0,1,1,0],
        [1,1,0,0,0,1,1],
        [1,1,0,0,0,1,1],
        [1,1,1,1,1,1,1],
        [1,1,0,0,0,1,1],
        [1,1,0,0,0,1,1],
    ],
    'G': [
        [0,1,1,1,1,1,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,1,1,1],
        [1,1,0,0,0,1,1],
        [1,1,0,0,0,1,1],
        [0,1,1,1,1,1,0],
    ],
    'E': [
        [1,1,1,1,1,1,1],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,1,1,1,1,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,1,1,1,1,1],
    ],
    'N': [
        [1,1,0,0,0,1,1],
        [1,1,1,0,0,1,1],
        [1,1,0,1,0,1,1],
        [1,1,0,0,1,1,1],
        [1,1,0,0,0,1,1],
        [1,1,0,0,0,1,1],
        [1,1,0,0,0,1,1],
    ],
    'T': [
        [1,1,1,1,1,1,1],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
    ],
    'J': [
        [0,0,1,1,1,1,1],
        [0,0,0,0,1,1,0],
        [0,0,0,0,1,1,0],
        [0,0,0,0,1,1,0],
        [1,1,0,0,1,1,0],
        [1,1,0,0,1,1,0],
        [0,1,1,1,1,0,0],
    ],
    'I': [
        [1,1,1,1,1,1,1],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0],
        [1,1,1,1,1,1,1],
    ],
    'L': [
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,0,0,0,0,0],
        [1,1,1,1,1,1,1],
    ],
}

TEXT = "AGENTJAIL"

total_cols = len(TEXT) * CHAR_W + (len(TEXT) - 1) * GAP
total_w = total_cols * CELL
total_h = ROWS * CELL


def build_rects():
    rects = []
    for ci, ch in enumerate(TEXT):
        ox = ci * (CHAR_W + GAP) * CELL
        for ri, row in enumerate(GLYPHS[ch]):
            for pi, px in enumerate(row):
                if px:
                    x = ox + pi * CELL
                    y = ri * CELL
                    rects.append(f'<rect x="{x}" y="{y}" width="{CELL}" height="{CELL}"/>')
    return ''.join(rects)


rects = build_rects()

light = (
    f'<svg xmlns="http://www.w3.org/2000/svg" '
    f'viewBox="0 0 {total_w} {total_h}" fill="#0d1117">'
    f'{rects}</svg>\n'
)
dark = (
    f'<svg xmlns="http://www.w3.org/2000/svg" '
    f'viewBox="0 0 {total_w} {total_h}" fill="#ffffff">'
    f'{rects}</svg>\n'
)

out_dir = os.path.dirname(os.path.abspath(__file__))
light_path = os.path.join(out_dir, 'agentjail-logo-light.svg')
dark_path  = os.path.join(out_dir, 'agentjail-logo-dark.svg')

with open(light_path, 'w') as f:
    f.write(light)
with open(dark_path, 'w') as f:
    f.write(dark)

print(f"SVG size: {total_w} × {total_h} px  ({total_cols} cols × {ROWS} rows)")
print(f"Wrote {light_path}")
print(f"Wrote {dark_path}")
