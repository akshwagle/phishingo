"""
Generate minimal valid PNG icons for the PhishFilter Pro extension.
Requires only Python stdlib — no Pillow or other dependencies.

Run from the extension/assets directory:
    python generate-icons.py
"""
import struct
import zlib
import os

os.makedirs('icons', exist_ok=True)

INDIGO = (79, 70, 229)  # #4f46e5


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    raw = chunk_type + data
    crc = zlib.crc32(raw) & 0xFFFFFFFF
    return struct.pack('>I', len(data)) + raw + struct.pack('>I', crc)


def make_shield_png(size: int, bg: tuple, shield: tuple) -> bytes:
    """
    Create a simple PNG with a colored background and a white shield silhouette
    drawn with basic filled rectangles (no curves — pure pixel art).
    """
    # Build RGBA pixel grid
    pixels = []
    cx, cy = size // 2, size // 2
    radius = size // 2 - 2  # outer circle-ish radius

    for y in range(size):
        row = []
        for x in range(size):
            # Rounded rect background
            padding = max(1, size // 10)
            in_rect = (padding <= x < size - padding) and (padding <= y < size - padding)
            corner  = max(1, size // 6)
            in_tl   = x < padding + corner and y < padding + corner
            in_tr   = x >= size - padding - corner and y < padding + corner
            in_bl   = x < padding + corner and y >= size - padding - corner
            in_br   = x >= size - padding - corner and y >= size - padding - corner

            def corner_ok(cx2, cy2):
                return (x - cx2) ** 2 + (y - cy2) ** 2 <= corner ** 2

            if in_rect:
                if in_tl and not corner_ok(padding + corner, padding + corner):
                    row += [0, 0, 0, 0]
                elif in_tr and not corner_ok(size - padding - corner - 1, padding + corner):
                    row += [0, 0, 0, 0]
                elif in_bl and not corner_ok(padding + corner, size - padding - corner - 1):
                    row += [0, 0, 0, 0]
                elif in_br and not corner_ok(size - padding - corner - 1, size - padding - corner - 1):
                    row += [0, 0, 0, 0]
                else:
                    # Shield shape: simple polygon inside the rounded rect
                    # Top center tapers, sides go down, bottom narrows to a point
                    rel_x = (x - padding) / (size - 2 * padding)  # 0..1
                    rel_y = (y - padding) / (size - 2 * padding)  # 0..1
                    # Simple shield mask
                    if rel_y < 0.45:
                        # Top half: rectangle minus corners
                        shield_inner = 0.1 <= rel_x <= 0.9
                    elif rel_y < 0.75:
                        # Middle: tapered
                        taper = (rel_y - 0.45) / 0.30 * 0.15
                        shield_inner = (0.1 + taper) <= rel_x <= (0.9 - taper)
                    else:
                        # Bottom: narrows to point
                        taper = (rel_y - 0.75) / 0.25 * 0.35
                        shield_inner = (0.25 + taper) <= rel_x <= (0.75 - taper)

                    if shield_inner:
                        row += list(shield) + [255]
                    else:
                        row += list(bg) + [255]
            else:
                row += [0, 0, 0, 0]  # transparent
        pixels.append(row)

    # Build raw image data (RGBA, filter byte 0 per scanline)
    raw = b''.join(b'\x00' + bytes(row) for row in pixels)
    compressed = zlib.compress(raw, 9)

    signature = b'\x89PNG\r\n\x1a\n'
    ihdr = png_chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))  # 8-bit RGBA
    idat = png_chunk(b'IDAT', compressed)
    iend = png_chunk(b'IEND', b'')
    return signature + ihdr + idat + iend


for sz in [16, 48, 128]:
    data = make_shield_png(sz, INDIGO, (255, 255, 255))
    path = f'icons/{sz}.png'
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  Created {path}  ({sz}x{sz}, {len(data)} bytes)')

print('Done. Icons written to assets/icons/')
