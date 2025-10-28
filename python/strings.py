#!/usr/bin/env python3
import subprocess
import sys
import os
import multiprocessing as mp
from pathlib import Path

"""Finds interesting strings in APK resource files using ripgrep directly on binaries for speed."""

RESOURCE_STRINGS_PATTERNS = [
    # --- C&C Communication (more specific) ---
    # URLs containing specific paths often used by malware (e.g., /api/login, /upload, /cmd)
    r"https?://[a-zA-Z0-9\.-]+\.(com|net|org|io|ru|tk|ml|ga|cf|top|xyz|onion)/(api|upload|cmd|login|control|bot)/[a-zA-Z0-9\./\-_%\?=&]*",
    # SOCKS proxy (relatively specific)
    r"socks[45]://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}",
    # --- Identifiers / Secrets (more specific) ---
    # Long base64 strings *likely* containing keys or significant data (length > 50, avoids short base64 fragments)
    r"[a-zA-Z0-9+/]{50,}={0,2}",
    # RSA/EC/DSA private keys (specific start/end markers)
    r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
    # --- Commands / Actions (specific to Android control) ---
    # Direct system execution from resources (less common in legitimate resources)
    r"Runtime\.getRuntime\(\)\.exec\(",
    r"ProcessBuilder\(",
    # Specific Android commands for persistence/modification
    r"pm install -r ", # Install with replace flag
    r"pm install -t ", # Install with test flag
    r"am start -n [a-zA-Z0-9_\.]+/\.?[^/\s]+ --ei", # am start with extra intent data
    r"am broadcast -n [a-zA-Z0-9_\.]+/\.?[^/\s]+ --es", # am broadcast with extra string data
    # --- Crypto / Persistence (more specific) ---
    # Specific crypto mode combinations often used for encryption
    r"(?:AES|RSA|ChaCha20|Salsa20|Curve25519|Ed25519)\s*(?:\+|/|-)\s*(?:GCM|CTR)",
    # Accessing specific sensitive system directories from resources
    r"/data/data/[a-zA-Z0-9_\.]+/(shared_prefs|databases|cache)/", # Specific sensitive subdirs
    # --- Other Highly Suspicious ---
    # Common malware command strings (often found in config/resource files)
    r"(?:exec_cmd|run_shell|execute_now|send_data_to_server)",
    # Potential hardcoded credentials in URLs (less common in resource XML, more in code, but possible)
    # r"https?://[a-zA-Z0-9\.-]+:[a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+\.(com|net|org|io|ru|tk|ml|ga|cf|top|xyz|onion)/", # Still quite generic
    # Specific malware-related filenames or paths
    r"/dev/(?:shm|pts/[0-9]+)", # Shared memory, pseudo-terminals
    r"(?:/system/bin/|/system/xbin/)(?:su|busybox|lib\S*\.so)", # Specific tools/binaries
]

# Extensions to scan - focusing on likely places for hidden data
# Adding .xml back, but patterns should be specific enough to avoid normal XML strings
RESOURCE_EXTENSIONS = ['.dex', '.so', '.png', '.jpg', '.gif', '.ttf', '.otf', '.bin', '.dat', '.xml', '.txt', '.properties', '.json', '.db', '.sqlite']

def should_scan_file(file_path: Path) -> bool:
    ext = file_path.suffix.lower()
    return ext in RESOURCE_EXTENSIONS

def find_resource_files(root_path: Path) -> list[str]:
    files = []
    for file_path in root_path.rglob('*'):
        if file_path.is_file() and should_scan_file(file_path):
            files.append(str(file_path))
    return files

def search_strings_in_file(args):
    res_file, patterns = args
    results = []
    for pattern in patterns:
        # Use ripgrep directly on the binary file
        # -a treats binary as text for matching
        # -o outputs only the matching part
        # -P enables PCRE2 regex
        # --color=never avoids ANSI codes in output
        cmd = ['rg', '-a', '-o', '-P', '--color=never', pattern, res_file]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=False) # check=False handles non-zero exit codes gracefully
        except FileNotFoundError:
            print("[*] ERROR: 'rg' (ripgrep) not found. Please install ripgrep.", file=sys.stderr)
            sys.exit(1)

        if result.returncode == 0: # Matches found
            matches = list(filter(None, result.stdout.strip().split('\n')))
            if matches:
                # Group matches by pattern for this file
                results.append((pattern, matches))
    return res_file, results

def main():
    if len(sys.argv) < 2:
        print("[*] ERROR: you must pass the path to jadx output of resources as the first arg.")
        sys.exit(1)

    root_dir = sys.argv[1]
    root_path = Path(root_dir)

    if not root_path.exists():
        print(f"[!] Path does not exist: {root_dir}", file=sys.stderr)
        return

    # Find files to scan
    resource_files = find_resource_files(root_path)
    if not resource_files:
        print(f"[*] No resource files found in {root_dir} matching extensions {RESOURCE_EXTENSIONS}")
        return

    # Prepare arguments for multiprocessing
    args_list = [(f, RESOURCE_STRINGS_PATTERNS) for f in resource_files]

    # Search strings in parallel
    with mp.Pool() as pool:
        results = pool.map(search_strings_in_file, args_list)

    # Print results
    found_count = 0
    for res_file, file_results in results:
        if file_results: # If any patterns matched in this file
            print(f"[*] FOUND STRINGS IN {res_file}:")
            for pattern, matches in file_results:
                for match in matches:
                    if match: # Filter out empty strings if any
                        print(f"\t[*] FOUND STRING:")
                        print(f"\t\t[*] STRING: '{match}'")
                        print(f"\t\t[*] OF PATTERN: '{pattern}'")
            print()
            found_count += 1

    if found_count == 0:
        print(f"[*] TOTAL: {found_count} suspicious string matches found across {len(resource_files)} scanned files.")
    else:
        print(f"[*] TOTAL: {found_count} files with suspicious string matches found out of {len(resource_files)} scanned.")

if __name__ == "__main__":
    main()