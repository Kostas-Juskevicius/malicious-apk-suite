#!/usr/bin/env python3
import subprocess
import sys
import os
import multiprocessing as mp
from pathlib import Path

"""Finds interesting strings in APK resource files using ripgrep directly on binaries for speed."""


RESOURCE_STRINGS_PATTERNS = [
    # --- C&C Communication ---
    r"https?://[a-zA-Z0-9\.-]+\.(com|net|org|io|ru|tk|ml|ga|cf|top|xyz|onion)/[a-zA-Z0-9\./\-_%\?=&]*", # URL patterns
    r"socks[45]://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}", # SOCKS proxy
    r"ftp://[a-zA-Z0-9\.-]+:[a-zA-Z0-9\.-]+@[a-zA-Z0-9\.-]+\.(com|net|org|io|ru|tk|ml|ga|cf|top|xyz|onion)/", # FTP credentials
    # --- Identifiers / Secrets ---
    r"[a-zA-Z0-9]{20,}", # Long random-looking strings (API keys, device IDs)
    r"[A-Z]{2,3}_[A-Z0-9_]{10,}", # API key patterns (e.g., AWS, Google)
    r"-----BEGIN [A-Z ]+-----", # RSA/EC/DSA keys
    r"[a-zA-Z0-9+/]{32,}={0,2}", # Base64 potentially containing keys/secrets
    # --- Commands / Actions ---
    r"(?:exec|shell|system|Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(", # Execution commands (if somehow in resources)
    r"am broadcast -a", # Android broadcast commands
    r"am start -a", # Android activity start commands
    r"pm install", # Package manager install commands
    r"su ", # Root command
    r"chmod\s+\d{3,4}", # Permission change command
    # --- Crypto / Persistence ---
    r"(?:AES|RSA|DES|ChaCha20|Salsa20|Curve25519|Ed25519|SHA(?:256|512)|MD5)\s*(?:\+|/|-)\s*(?:CBC|ECB|GCM|CTR|OFB)", # Crypto algorithm names/modes
    r"keystore://", # Android keystore references
    r"/data/data/[a-zA-Z0-9_\.]+/", # App data directories (potential persistence)
    r"/system/bin/", # System directories (potential persistence/modification)
    # --- Other Suspicious ---
    r"(?:imei|imsi|serial|mac|android_id)", # Device identifiers
    r"(?:access_token|refresh_token|oauth_token)", # Token names
    r"(\.onion|\.i2p)", # Dark web domains
    r"(?:hook|hooked|hooking|frida|substrate|xposed)", # Hooking framework names (if hidden)
]

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
        if file_results:
            print(f"[*] FOUND STRINGS IN {res_file}:")
            for pattern, matches in file_results:
                for match in matches:
                    if match:
                        print(f"\t[*] FOUND STRING:")
                        print(f"\t\t[*] STRING: '{match}'")
                        print(f"\t\t[*] OF PATTERN: '{pattern}'")
            print()
            found_count += 1

    if found_count == 0:
        print(f"TOTAL: {found_count} suspicious string matches found across {len(resource_files)} scanned files.")

if __name__ == "__main__":
    main()