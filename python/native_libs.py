#!/usr/bin/env python3
import re
import subprocess
import sys
from pathlib import Path

"""Reports quick, potentially useful information about the native libraries present"""


def run_readelf(path, *args):
    """Run readelf"""
    try:
        out = subprocess.check_output(["readelf", *args, path], text=True, stderr=subprocess.DEVNULL)
        return out
    except FileNotFoundError:
        sys.exit("readelf not found — install binutils (e.g. apt install binutils).")
    except subprocess.CalledProcessError:
        return ""


def get_architecture(path):
    """Parse architecture info from readelf -h"""
    header = run_readelf(path, "-h")
    arch = re.search(r"Machine:\s+(.+)", header)
    cls = re.search(r"Class:\s+(.+)", header)
    return f"{cls.group(1) if cls else '?'} / {arch.group(1) if arch else '?'}"


def get_exported_symbols(path):
    """Return list of exported symbols from readelf -s"""
    syms = []
    out = run_readelf(path, "-s")
    for line in out.splitlines():
        cols = line.split()
        if len(cols) >= 8:
            name = cols[-1]
            if name and not name.startswith("_FINI_") and not name.startswith("_INIT_"):
                syms.append(name)
    return syms


def get_linked_libs(path):
    """Return list of shared library dependencies from readelf -d"""
    out = run_readelf(path, "-d")
    return re.findall(r'\(NEEDED\)\s+Shared library:\s+\[(.*?)\]', out)


def pick_target_so(resources_dir: Path):
    """Return a single .so path to analyze, preferring arm64-v8a"""
    lib_dir = resources_dir / "lib"
    if not lib_dir.exists():
        print("[*] NO LIBRARY FOLDER FOUND — SKIPPING NATIVE ANALYSIS\n")
        sys.stdout.flush()
        return None

    arm64_dir = lib_dir / "arm64-v8a"
    if arm64_dir.exists():
        so_files = sorted(arm64_dir.glob("*.so"))
        if so_files:
            return so_files[0]

    # fallback: any .so under lib/
    all_sos = sorted(lib_dir.rglob("*.so"))
    if all_sos:
        return all_sos[0]

    print("[*] NO .SO FILES FOUND IN LIB FOLDER — NOTHING TO ANALYZE\n")
    sys.stdout.flush()
    return None


def analyze_lib(path: Path):
    print(f"[*] ANALYZING NATIVE LIBRARY: {path}\n")

    arch = get_architecture(str(path))
    syms = get_exported_symbols(str(path))
    libs = get_linked_libs(str(path))
    jni_syms = [s for s in syms if s.startswith("Java_")]
    has_jni_onload = any(s == "JNI_OnLoad" for s in syms)

    print(f"[*] TOTAL EXPORTED SYMBOLS: {len(syms)}\n")

    print(f"[*] Architecture: {arch}\n")

    if has_jni_onload:
        print("[*] FOUND JNI_OnLoad\n")

    print("[*] JNI FUNCTIONS (Java_*)")
    if not jni_syms:
        print("\t[*] (none)\n")
    else:
        for s in jni_syms:
            print(f"\t[*] {s}")
        print()

    print("[*] EXPORTED SYMBOLS")
    if not syms:
        print("\t[*] (none)\n")
    else:
        for s in syms:
            print(f"\t[*] {s}")
        print()

    print("[*] LINKED LIBRARIES")
    if not libs:
        print("\t[*] (none)\n")
    else:
        for l in libs:
            print(f"\t[*] {l}")
        print()


def main():
    if len(sys.argv) < 2:
        print("Usage: native_info.py <resources folder>")
        sys.exit(1)

    resources_dir = Path(sys.argv[1])
    if not resources_dir.exists():
        sys.exit("Provided path does not exist")

    target_so = pick_target_so(resources_dir)
    if not target_so:
        sys.stdout.flush()
        return

    analyze_lib(target_so)


if __name__ == "__main__":
    main()