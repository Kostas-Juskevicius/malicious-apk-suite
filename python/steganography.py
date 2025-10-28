#!/usr/bin/env python3
"""Minimal resource tamper/steganography checker.

Checks:
- bytes-per-pixel (too many bytes for given pixel dimensions)
- magic bytes vs extension mismatch
- Shannon entropy (sampled for large files)
- embedded signatures in head/tail (zip/apk/dex/elf/pe)

Outputs a short faithful report per-file (no Android permission categorization).
"""
from __future__ import annotations
import os
import math
from pathlib import Path
import sys

# Constants (edit here if needed)
BPP_THRESHOLD = 5.0  # bytes per pixel considered too high
ENTROPY_SUSPICIOUS = 7.5
ENTROPY_UNMISTAKABLE = 7.9
HEADER_READ = 4096  # bytes to read for header/magic
TAIL_SCAN = 1024 * 1024  # bytes to scan from end for embedded signatures
SAMPLE_CHUNK = 131072  # chunk size for entropy sampling in large files

# Magic bytes as hex constants (no raw \x literals)
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
    """Calculate Shannon entropy of a byte sequence."""
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
    """Read first n bytes from a file."""
    with open(path, "rb") as f:
        return f.read(n)

def read_tail(path: str, n: int = TAIL_SCAN) -> bytes:
    """Read last n bytes from a file."""
    size = os.path.getsize(path)
    if size == 0:
        return b""
    with open(path, "rb") as f:
        toread = min(n, size)
        f.seek(size - toread)
        return f.read(toread)

def detect_magic(header_bytes: bytes) -> str | None:
    """Detect file type based on magic bytes."""
    for sig, name in MAGICS:
        if header_bytes.startswith(sig):
            return name
    return None

def try_image_dimensions(path: str) -> tuple[int | None, int | None]:
    """Try to get image dimensions using PIL."""
    try:
        from PIL import Image
    except ImportError:
        # print("Warning: PIL not found, image dimension checks will be skipped. Install Pillow.", file=sys.stderr)
        return None, None
    try:
        with Image.open(path) as im:
            return im.width, im.height
    except Exception:
        # Could be not an image file, corrupted, etc.
        return None, None

def bytes_per_pixel(filesize: int, w: int | None, h: int | None) -> float | None:
    """Calculate bytes per pixel."""
    if not w or not h or w == 0 or h == 0:
        return None
    pixels = w * h
    return filesize / pixels

def scan_for_embedded(path: str, primary_magic: str | None) -> list[tuple[str, int]]:
    """Scan file head and tail for embedded signatures, excluding the primary one at offset 0."""
    size = os.path.getsize(path)
    if size == 0:
        return []
    embedded = []
    with open(path, "rb") as f:
        head = f.read(HEADER_READ)
        # Scan head for signatures
        for sig, name in MAGICS:
            # Check if signature is at the very beginning
            if head.startswith(sig) and len(sig) > 2:
                # Only add if it's NOT the primary magic detected for the file at offset 0
                if not (name == primary_magic and f.tell() == len(sig)): # f.tell() is misleading here, just check offset 0 logic
                # Simpler: if the name found at offset 0 matches the primary_magic passed in, don't add it.
                    if not (name == primary_magic and 0 == 0): # This condition is always true if name matches primary_magic
                        if name != primary_magic: # This is the correct check
                            embedded.append((name, 0))
                        # else: it's the primary signature, skip it
        # Scan tail for signatures
        if size > HEADER_READ:
            f.seek(max(0, size - TAIL_SCAN))
            tail = f.read()
            for sig, name in MAGICS:
                pos = tail.find(sig)
                if pos != -1:
                    # Calculate absolute offset in the file
                    offset = size - len(tail) + pos
                    # Add if it's not at offset 0 (or if it is, only if it's different from primary magic, which is handled above for head)
                    if offset != 0: # This already excludes offset 0 found in the tail, which is correct as head covers offset 0
                        embedded.append((name, offset))
    return embedded

def analyze_file(path: str) -> dict:
    """Analyze a single file for tampering/steganography."""
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

    # --- Entropy Check ---
    try:
        if size <= 5 * 1024 * 1024:  # For smaller files, read all
            with open(path, "rb") as f:
                data_all = f.read()
            ent = shannon_entropy_bytes(data_all)
        else:  # For larger files, sample head, middle, tail
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

    # --- Image-specific Checks (BPP) ---
    w, h = try_image_dimensions(path)
    entry["w"], entry["h"] = w, h
    if w and h:
        bpp = bytes_per_pixel(size, w, h)
        entry["bpp"] = bpp
        if bpp and bpp > BPP_THRESHOLD:
            entry["reasons"].append(f"bytes_per_pixel {bpp:.2f} > {BPP_THRESHOLD} (way too big for pixel dimensions)")
            entry["score"] += 2

    # --- Embedded Signatures Check (PASS the primary magic to filter it) ---
    embedded = scan_for_embedded(path, entry["magic"])
    entry["embedded"] = embedded
    if embedded:
        for name, offset in embedded:
            entry["reasons"].append(f"found {name} at offset 0x{offset:x}")
            if name in ("DEX", "ELF", "PE/MZ"):
                entry["score"] += 5  # High score for embedded executables
            else:
                entry["score"] += 3  # Lower score for embedded archives

    # --- Magic vs Extension Check ---
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
        ".so": "ELF",  # Usually ELF for native libs
    }
    expected = ext_map.get(entry["extension"])
    if expected and entry["magic"] != expected:
        entry["reasons"].append(f"magic '{entry['magic']}' does not match extension '{entry['extension']}'")
        entry["score"] += 2

    return entry

def should_scan_file(file_path: Path) -> bool:
    """Determine if a file should be scanned based on extension and path."""
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
    # Skip other common non-resource files if needed
    # For now, only scan the specific types requested.
    return False

def main():
    # Accept directory path as command line argument
    if len(sys.argv) < 2:
        print("[*] ERROR: you must pass the path to jadx output of resources as the first arg.")
        sys.exit(1)

    root_path_str = sys.argv[1]
    root_path = Path(root_path_str)

    if not root_path.exists():
        print(f"[!] Path does not exist: {root_path_str}", file=sys.stderr)
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
            print() # Add a blank line after each file's warnings
            found_count += 1

    # Print summary line if any files were found
    print(f"[*] TOTAL: {found_count} suspicious files found out of {total_files} scanned.")

if __name__ == "__main__":
    main()