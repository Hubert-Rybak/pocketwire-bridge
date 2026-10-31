#!/usr/bin/env python3
"""Converts an 8-bit RGBA PNG to raw RGBA bytes (the tray icons are embedded this way, so the
Bridge needs no image decoder). Standard library only.

    python3 tools/png2rgba.py assets/icon.png assets/icon.rgba
"""
import struct
import sys
import zlib


def decode(data):
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
    pos, idat, w = 8, b"", None
    while pos < len(data):
        n, typ = struct.unpack(">I4s", data[pos:pos + 8])
        chunk = data[pos + 8:pos + 8 + n]
        pos += 12 + n
        if typ == b"IHDR":
            w, h, depth, color, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
            assert depth == 8 and color == 6 and interlace == 0, "need 8-bit RGBA, not interlaced"
        elif typ == b"IDAT":
            idat += chunk
    raw, bpp, stride = zlib.decompress(idat), 4, w * 4
    out, prev = bytearray(), bytearray(stride)
    for y in range(h):
        f, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        out += line
        prev = line
    return w, h, bytes(out)


if __name__ == "__main__":
    w, h, rgba = decode(open(sys.argv[1], "rb").read())
    open(sys.argv[2], "wb").write(rgba)
    print(f"{sys.argv[2]}: {w}x{h}")
