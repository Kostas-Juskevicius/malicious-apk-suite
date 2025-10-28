#!/usr/bin/env python3
"""Minimal resource tamper/steganography checker."""

from __future__ import annotations
import os
import sys
import math

TAIL_SCAN = 1024 * 1024
HEADER_READ = 4096
SAMPLE_CHUNK = 131072

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"RIFF", "RIFF/WEBP"),
    (b"PK\x03\x04", "ZIP/APK/JAR"),
    (b"dex\n035", "DEX"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
]

EMBED_SIGNATURES = [
    (b"PK\x03\x04", "ZIP"),
    (b"dex\n035", "DEX"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
]

try:
    from PIL import Image
except Exception:
    Image = None


def read_initial(path: str, n: int = HEADER_READ) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def read_tail(path: str, n: int = TAIL_SCAN) -> bytes:
    size = os.path.getsize(path)
    if size == 0:
        return b""
    with open(path, "rb") as f:
        toread = min(n, size)
        f.seek(size - toread)
        return f.read(toread)


def detect_magic(header_bytes: bytes) -> str | None:
    for sig, name in MAGICS:
        if header_bytes.startswith(sig):
            return name
    return None


def try_image_dimensions(path: str) -> tuple[int|None, int|None]:
    if Image is None:
        return None, None
    try:
        with Image.open(path) as im:
            return im.width, im.height
    except Exception:
        return None, None


def bytes_per_pixel(filesize: int, w: int | None, h: int | None) -> float | None:
    if not w or not h:
        return None
    pixels = w * h
    if pixels == 0:
        return None
    return filesize / pixels


def scan_for_embedded(path: str, signatures=EMBED_SIGNATURES, max_scan=TAIL_SCAN):
    found = []
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        if size <= max_scan * 2:
            data = f.read()
            base = 0
        else:
            head = f.read(HEADER_READ)
            f.seek(max(0, size - max_scan))
            tail = f.read(max_scan)
            data = head + tail
            base = max(0, size - max_scan)
        for sig, name in signatures:
            idx = data.find(sig)
            if idx != -1:
                found.append((name, base + idx))
    return found


def pretty_bytes(n: int) -> str:
    for unit in ("B","KB","MB","GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def analyze_file(path: str) -> dict:
    entry = {
        "path": path,
        "filesize": os.path.getsize(path) if os.path.exists(path) else 0,
        "magic": None,
        "extension": os.path.splitext(path)[1].lower(),
        "w": None,
        "h": None,
        "bpp": None,
        "embedded": [],
        "reasons": [],
    }

    if entry["filesize"] == 0:
        entry["reasons"].append("empty file")
        return entry

    header = read_initial(path)
    entry["magic"] = detect_magic(header) or "UNKNOWN"

    w, h = try_image_dimensions(path)
    entry["w"], entry["h"] = w, h
    if w and h:
        entry["bpp"] = bytes_per_pixel(entry["filesize"], w, h)

    embedded = scan_for_embedded(path)
    entry["embedded"] = embedded
    for name, offset in embedded:
        entry["reasons"].append(f"found {name} at offset 0x{offset:x}")

    if any(e[0] == "ZIP" for e in embedded):
        tail = read_tail(path, TAIL_SCAN)
        if b"META-INF/" in tail or b"MANIFEST.MF" in tail or b".RSA" in tail or b".SF" in tail:
            entry["reasons"].append("embedded ZIP/JAR with META-INF / signature files")

    ext_map = {".png": "PNG", ".jpg": "JPEG", ".jpeg": "JPEG", ".gif": "GIF", ".webp": "RIFF/WEBP"}
    expected = ext_map.get(entry["extension"]) if entry["extension"] else None
    if expected and entry["magic"] != expected:
        entry["reasons"].append(f"extension {entry['extension']} but magic {entry['magic']}")

    if entry["bpp"] is not None and entry["bpp"] > 5.0:
        entry["reasons"].append(f"bytes_per_pixel {entry['bpp']:.2f} > 5.0 (way too big for pixel dimensions)")

    if any(e[0] in ("DEX", "ELF", "PE/MZ") for e in embedded):
        entry["reasons"].append("embedded executable (DEX/ELF/PE)")

    return entry


def print_report(results: list[dict]):
    for r in results:
        print(f"[*] FOUND: {r['path']} ({r['magic']})")
        if r["reasons"]:
            for reason in r["reasons"]:
                print(f"    -> reason: {reason}")
    print()


def walk_and_analyze(root: str):
    files = [root] if os.path.isfile(root) else [os.path.join(dp, f) for dp, _, fs in os.walk(root) for f in fs]
    return [analyze_file(f) for f in files]


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    results = walk_and_analyze(root)
    print_report(results)

if __name__ == "__main__":
    main()
