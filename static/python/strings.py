#!/usr/bin/env python3
import subprocess
import sys
import os


# TODO: maybe should look at all files rather than at a whitelist of them?
# TODO: maybe some of this should synergize with the steganography.py script, maybe that one finds hidden bins in non-bin files and passes them here?


RES_DIR = sys.argv[1] if len(sys.argv) > 1 else sys.exit("[*] ERROR: you must pass the path to jadx output of resources as the first arg.")
MIN_MEANINGFUL_STRING_LENGTH = 8


STRINGS_PATTERNS = [
    r"http://",
    r"https://",
    r"ws://",
    r"wss://",
    r"ftp://",
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # IP addresses
    r"[a-zA-Z0-9-]+\.(com|net|org|io|xyz|ru|cn|onion)",  # domains
    r"aHR0cDovL2",  # base64 http://
    r"aHR0cHM6Ly9",  # base64 https://
]


print("[*] EXTRACTING STRINGS FROM RESOURCES...\n")

RESOURCE_EXTENSIONS = ['.dex', '.so', '.png', '.jpg', '.gif', '.ttf', '.otf', '.bin', '.dat']
resource_files = []

for root, dirs, files in os.walk(RES_DIR):
    for file in files:
        filepath = os.path.join(root, file)
        if any(filepath.endswith(ext) for ext in RESOURCE_EXTENSIONS):
            resource_files.append(filepath)

for res_file in resource_files:
    result = subprocess.run(['strings', '-n', str(MIN_MEANINGFUL_STRING_LENGTH), res_file], capture_output=True, text=True)
    
    if result.returncode != 0:
        continue
    
    all_strings = result.stdout.strip().split('\n')
    
    for pattern in STRINGS_PATTERNS:
        cmd = ['rg', '-o', pattern]
        grep_result = subprocess.run(cmd, input=result.stdout, capture_output=True, text=True)
        
        for match in grep_result.stdout.strip().split('\n'):
            if match:
                print(f"[*] FOUND STRING: {match} in {res_file}")
    print()

print("[*] EXTRACTION COMPLETE")