#!/bin/bash

### This script expects you to be in the root directory of your analysis project.
### The APK file should be in your current directory.

APK_FILE="$(ls *.apk | head -n 1)"

# TODO: look into --deobf and --no-imports
echo -e "[*] DECOMPILING...\n"
if [ ! -d jadx ]; then
	jadx "$PWD/$APK_FILE" -d $PWD/jadx
else
	echo -e "[*] ERROR: jadx/ already exists. Have you already decompiled with 'jadx'?\n"
fi

# echo "[*] DISASSEMBLING..."
# if [ ! -d disassembled ]; then
# 	apktool d $APK_FILE -o disassembled || {
# 		echo "[*] ERROR: couldn't disassemble with 'apktool'. Perhaps the APK's ZIP headers are malformed / obfuscated."
# 	}
# else
# 	echo "[*] ERROR: disassembled/ already exists. Have you already disassembled with 'apktool'?"
# fi

# echo "[*] UNZIPPING..."
# if [ ! -d unzipped ]; then
# 	mkdir unzipped
# 	unzip $APK_FILE -d unzipped 2>/dev/null
# else
# 	echo "[*] ERROR: unzipped/ already exists. Have you already unzipped?"
# fi

echo -e "[*] ANALYZING MANIFEST...\n"
./static/python/manifest_analysis.py > manifest_analysis.txt

echo -e "[*] GREPPING PATTERNS IN SOURCE...\n"
./static/python/ripgrep.py "$PWD/jadx/sources" > ripgrep.txt

echo -e "[*] SEARCHING FOR STRINGS IN RESOURCES...\n"
./static/python/strings.py "$PWD/jadx/resources" > strings.txt

echo -e "[*] SEARCHING FOR PAYLOADS IN RESOURCES...\n"
# ./static/python/steganography.py "$PWD/jadx/resources" > steganography.txt