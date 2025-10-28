#!/usr/bin/env python3
"""Minimal resource tamper/steganography checker."""
from __future__ import annotations
import os
import math
import argparse
from pathlib import Path

# Constants
BPP_THRESHOLD = 5.0  # bytes per pixel considered too high
ENTROPY_SUSPICIOUS = 7.5
ENTROPY_UNMISTAKABLE = 7.9
HEADER_READ = 4096
TAIL_SCAN = 1024 * 1024
SAMPLE_CHUNK = 131072

# Magic bytes using hex constants
MAGICS = [
    (bytes.fromhex("89504E470D0A1A0A"), "PNG"),
    (bytes.fromhex("FFD8FF"), "JPEG"),
    (bytes.fromhex("47494638"), "GIF"),
    (bytes.fromhex("52494646"), "RIFF/WEBP"),
    (bytes.fromhex("504B0304"), "ZIP/APK/JAR"),
    (bytes.fromhex("6465780A303335"), "DEX"),
    (bytes.fromhex("7F454C46"), "ELF"),
    (bytes.fromhex("4D5A"), "PE/MZ"),
]

def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    data_len = len(data)
    for count in counts:
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    return entropy

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

def try_image_dimensions(path: str) -> tuple[int | None, int | None]:
    try:
        from PIL import Image
    except Exception:
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

def scan_for_embedded(path: str) -> list[tuple[str, int]]:
    """Scan file for embedded signatures in head and tail."""
    size = os.path.getsize(path)
    if size == 0:
        return []
    embedded = []
    with open(path, "rb") as f:
        head = f.read(HEADER_READ)
        # Scan head
        for sig, name in MAGICS:
            if head.startswith(sig) and len(sig) > 2: # Avoid short signatures like MZ
                embedded.append((name, 0))
        # Scan tail
        if size > HEADER_READ:
            f.seek(max(0, size - TAIL_SCAN))
            tail = f.read()
            for sig, name in MAGICS:
                pos = tail.find(sig)
                if pos != -1:
                    offset = size - len(tail) + pos
                    if offset != 0: # Avoid double-counting head hits
                        embedded.append((name, offset))
    return embedded

def analyze_file(path: str) -> dict:
    entry = {
        "path": path,
        "filesize": os.path.getsize(path) if os.path.exists(path) else 0,
        "magic": None,
        "extension": os.path.splitext(path)[1].lower(),
        "entropy": None,
        "w": None,
        "h": None,
        "bpp": None,
        "embedded": [],
        "reasons": [],
        "score": 0,
    }

    if entry["filesize"] == 0:
        entry["reasons"].append("empty file")
        return entry

    header = read_initial(path)
    entry["magic"] = detect_magic(header) or "UNKNOWN"
    size = entry["filesize"]

    # Entropy check: full for small files, sampled for large ones
    try:
        if size <= 5 * 1024 * 1024:
            with open(path, "rb") as f:
                data_all = f.read()
            ent = shannon_entropy_bytes(data_all)
        else:
            with open(path, "rb") as f:
                head = f.read(SAMPLE_CHUNK)
                f.seek(size // 2)
                mid = f.read(SAMPLE_CHUNK)
                f.seek(max(0, size - SAMPLE_CHUNK))
                tail = f.read(SAMPLE_CHUNK)
            ent = shannon_entropy_bytes(head + mid + tail)
        entry["entropy"] = ent
        if ent >= ENTROPY_UNMISTAKABLE:
            entry["reasons"].append(f"high entropy {ent:.3f} >= {ENTROPY_UNMISTAKABLE} (strong indicator of packed/encrypted data)")
            entry["score"] += 3
        elif ent >= ENTROPY_SUSPICIOUS:
            entry["reasons"].append(f"elevated entropy {ent:.3f} >= {ENTROPY_SUSPICIOUS}")
            entry["score"] += 1
    except Exception:
        entry["reasons"].append("entropy: error computing")

    # Image-specific checks
    w, h = try_image_dimensions(path)
    entry["w"], entry["h"] = w, h
    if w and h:
        bpp = bytes_per_pixel(size, w, h)
        entry["bpp"] = bpp
        if bpp and bpp > BPP_THRESHOLD:
            entry["reasons"].append(f"bytes_per_pixel {bpp:.2f} > {BPP_THRESHOLD} (way too big for pixel dimensions)")
            entry["score"] += 2

    # Embedded signatures/executables check
    embedded = scan_for_embedded(path)
    entry["embedded"] = embedded
    if embedded:
        for name, offset in embedded:
            entry["reasons"].append(f"found {name} at offset 0x{offset:x}")
            if name in ("DEX", "ELF", "PE/MZ"):
                entry["score"] += 5
            else:
                entry["score"] += 3

    # Magic vs extension check
    ext_map = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".webp": "RIFF/WEBP",
        ".xml": None,  # Explicitly allow XML, will be skipped anyway
        ".arsc": None,
        ".txt": None,
        ".ttf": None,
        ".otf": None,
        ".wav": None,
        ".mp3": None,
        ".so": "ELF", # Usually ELF for native libs
    }
    expected = ext_map.get(entry["extension"])
    if expected and entry["magic"] != expected:
        entry["reasons"].append(f"magic '{entry['magic']}' does not match extension '{entry['extension']}'")
        entry["score"] += 2

    return entry

def should_scan_file(file_path: Path) -> bool:
    ext = file_path.suffix.lower()
    # Include images
    if ext in {'.png', '.jpg', '.jpeg', '.gif', '.webp'}:
        return True
    # Include .so files (native libraries)
    if ext == '.so':
        return True
    # Include all files under assets/
    if 'assets' in file_path.parts:
        return True
    # Explicitly skip XML files
    if ext == '.xml':
        return False
    # You requested to scan specific types, so only those.
    return False

def main():
    parser = argparse.ArgumentParser(description="Minimal tamper/stego checker.")
    parser.add_argument("root", nargs="?", default=".", help="Directory to scan")
    args = parser.parse_args()

    root_path = Path(args.root)
    if not root_path.exists():
        print(f"[!] Path does not exist: {args.root}", file=sys.stderr)
        return

    results = []
    total_files = 0

    if root_path.is_file():
        if should_scan_file(root_path):
            total_files = 1
            res = analyze_file(str(root_path))
            results.append(res)
    else:
        for file_path in root_path.rglob('*'):
            if file_path.is_file() and should_scan_file(file_path):
                total_files += 1
                res = analyze_file(str(file_path))
                results.append(res)

    # Print only files with warnings (score > 0 or reasons)
    found_count = 0
    for res in results:
        if res["score"] > 0 or len(res["reasons"]) > 0:
            print(f"[*] FOUND: {res['path']} ({res['magic']})")
            for reason in res["reasons"]:
                print(f"    [*] WARNING: {reason}")
            found_count += 1
            print()

    # Print summary line if any files were found
    if found_count > 0:
        print(f"[*] TOTAL: {found_count} suspicious files found out of {total_files} scanned.")

if __name__ == "__main__":
    main()