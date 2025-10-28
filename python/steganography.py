#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
import math

"""Minimal resource tamper checker."""

ENTROPY_UNMISTAKABLE = 7.9   # >= -> high-confidence dangerous
ENTROPY_SUSPICIOUS = 7.5     # >= -> suspicious if other flags present
BPP_SUSPICIOUS = 10.0        # bytes per pixel suspicious threshold
TAIL_SCAN = 1024 * 1024      # how many bytes from end to scan for embedded archives
HEADER_READ = 4096

MAGICS = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"RIFF", "RIFF/WEBP"),
    (b"PK\x03\x04", "ZIP/APK/JAR"),
    (b"dex\n035", "DEX"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
    (b"Rar!\x1a\x07", "RAR"),
]

EMBED_SIGNATURES = [
    (b"PK\x03\x04", "ZIP"),
    (b"dex\n035", "DEX"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/MZ"),
]


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for f in freq:
        if f == 0:
            continue
        p = f / length
        ent -= p * math.log2(p)
    return ent

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

def detect_magic(header_bytes: bytes) -> str | None:
    for sig, name in MAGICS:
        if header_bytes.startswith(sig):
            return name
    return None

def try_image_dimensions(path: str):
    try:
        from PIL import Image
    except Exception:
        return None, None
    try:
        with Image.open(path) as im:
            return im.width, im.height
    except Exception:
        return None, None

def bytes_per_pixel(filesize: int, w: int | None, h: int | None):
    if not w or not h:
        return None
    pixels = w * h
    if pixels == 0:
        return None
    return filesize / pixels

def pretty_bytes(n: int) -> str:
    for unit in ("B","KB","MB","GB"):
        if abs(n) < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}TB"


def analyze_file(path: str) -> dict:
    entry = {
        "path": path,
        "filesize": os.path.getsize(path),
        "magic": None,
        "extension": os.path.splitext(path)[1].lower(),
        "entropy": None,
        "w": None,
        "h": None,
        "bpp": None,
        "embedded": [],
        "reasons": [],
        "score": 0,
        "category": "normal",
    }

    if entry["filesize"] == 0:
        entry["reasons"].append("empty file")
        return entry

    header = read_initial(path)
    entry["magic"] = detect_magic(header) or "UNKNOWN"

    size = entry["filesize"]
    # entropy: sample for large files to avoid huge memory use
    if size <= 5 * 1024 * 1024:
        with open(path, "rb") as f:
            data_all = f.read()
        ent = shannon_entropy_bytes(data_all)
    else:
        with open(path, "rb") as f:
            head = f.read(131072)
            f.seek(size // 2)
            mid = f.read(131072)
            f.seek(max(0, size - 131072))
            tail = f.read(131072)
        ent = shannon_entropy_bytes(head + mid + tail)
        entry["reasons"].append("entropy sampled (large file)")
    entry["entropy"] = ent

    w, h = try_image_dimensions(path)
    entry["w"], entry["h"] = w, h
    if w and h:
        entry["bpp"] = bytes_per_pixel(size, w, h)

    embedded = scan_for_embedded(path)
    entry["embedded"] = embedded
    if embedded:
        for name, offset in embedded:
            entry["reasons"].append(f"found {name} at offset 0x{offset:x}")
            if name in ("DEX", "ELF", "PE/MZ"):
                entry["score"] += 5
            else:
                entry["score"] += 3

    # basic ext -> magic expectation
    ext_map = {
        ".png": "PNG",
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".gif": "GIF",
        ".webp": "RIFF/WEBP",
        ".xml": None,
        ".arsc": None,
        ".txt": None,
        ".ttf": None,
        ".otf": None,
        ".wav": None,
        ".mp3": None,
    }
    expected = ext_map.get(entry["extension"])
    if expected and entry["magic"] != expected:
        entry["reasons"].append(f"extension {entry['extension']} but magic {entry['magic']}")
        entry["score"] += 2

    # entropy rules
    if ent >= ENTROPY_UNMISTAKABLE:
        entry["reasons"].append(f"entropy {ent:.3f} >= {ENTROPY_UNMISTAKABLE} (unmistakable)")
        entry["score"] += 4
    elif ent >= ENTROPY_SUSPICIOUS:
        entry["reasons"].append(f"entropy {ent:.3f} >= {ENTROPY_SUSPICIOUS}")
        entry["score"] += 1

    # bpp rule
    if entry["bpp"] is not None and entry["bpp"] >= BPP_SUSPICIOUS:
        entry["reasons"].append(f"bytes_per_pixel {entry['bpp']:.2f} >= {BPP_SUSPICIOUS}")
        entry["score"] += 2

    # check for signature files in tail if ZIP found
    if any(e[0] == "ZIP" for e in embedded):
        tail = read_tail(path, TAIL_SCAN)
        if b"META-INF/" in tail or b"MANIFEST.MF" in tail or b".RSA" in tail or b".SF" in tail:
            entry["reasons"].append("embedded ZIP/JAR with META-INF / signature files")
            entry["score"] += 1
            entry["category"] = "signature"

    # final classification if not already signature
    if entry["category"] != "signature":
        if entry["score"] >= 6:
            entry["category"] = "dangerous"
        elif entry["score"] >= 3:
            entry["category"] = "suspicious"
        else:
            entry["category"] = "normal"

    return entry

def walk_and_analyze(root: str):
    files = []
    if os.path.isfile(root):
        files = [root]
    else:
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                files.append(os.path.join(dirpath, fn))
    results = []
    for f in files:
        try:
            results.append(analyze_file(f))
        except Exception as e:
            # treat analysis errors as dangerous so they get inspected
            results.append({
                "path": f,
                "filesize": os.path.getsize(f) if os.path.exists(f) else 0,
                "magic": None,
                "extension": os.path.splitext(f)[1].lower(),
                "entropy": None,
                "w": None, "h": None, "bpp": None,
                "embedded": [], "reasons": [f"error:{e}"], "score": 999, "category": "dangerous"
            })
    return results

def print_report(results: list[dict]):
    dangerous = [r for r in results if r["category"] == "dangerous"]
    signature = [r for r in results if r["category"] == "signature"]
    normal = [r for r in results if r["category"] == "normal"]
    suspicious = [r for r in results if r["category"] == "suspicious"]

    total_d = len(dangerous)
    total_sg = len(signature)
    total_n = len(normal) + len(suspicious)

    print(f"TOTAL: {total_d} dangerous, {total_sg} signature, {total_n} normal\n")
    sys.stdout.flush()

    print("[*] NORMAL (including suspicious)")
    for r in normal + suspicious:
        size = pretty_bytes(r["filesize"])
        print(f"\t[*] {r['path']} ({r['magic']}) — {size}")
    print()
    sys.stdout.flush()

    print("[*] SIGNATURE FILES (require signature match - likely system/repackaged)")
    for r in signature:
        size = pretty_bytes(r["filesize"])
        reasons = "; ".join(r["reasons"]) if r["reasons"] else ""
        print(f"\t[*] {r['path']} ({r['magic']}) — {size}")
        if reasons:
            print(f"\t\t-> reason: {reasons}")
    print()
    sys.stdout.flush()

    print("[*] DANGEROUS FILES")
    for r in dangerous:
        size = pretty_bytes(r["filesize"])
        reasons = "; ".join(r["reasons"]) if r["reasons"] else ""
        extra = ""
        if r["w"] and r["h"]:
            extra = f" w{r['w']}x{r['h']} bpp={r['bpp']:.2f}" if r["bpp"] else f" w{r['w']}x{r['h']}"
        print(f"\t[*] {r['path']} ({r['magic']}) — {size}{extra}")
        if reasons:
            print(f"\t\t-> reason: {reasons}")
    print()
    sys.stdout.flush()

if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    results = walk_and_analyze(root)
    print_report(results)