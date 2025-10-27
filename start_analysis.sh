#!/bin/bash

### This script expects you to be in the root directory of your analysis project.
### The APK

# chmod scripts
chmod +x ./python/*.py file should be in your current directory.

# remove carriage returns \r so python shebangs dont freak out when written on windows
find "$PWD" -name "*.py" -exec sed -i 's/\r$//' {} \;

APK_FILE="$(ls *.apk | head -n 1)"

# decompilation
# TODO: look into --deobf and --no-imports
echo -e "[*] DECOMPILING...\n"
if [ ! -d jadx ]; then
	jadx "$PWD/$APK_FILE" -d $PWD/jadx
else
	echo -e "[*] ERROR: jadx/ already exists. Have you already decompiled with 'jadx'?\n"
fi

# results
mkdir -p "$PWD/results"

echo -e "[*] ANALYZING MANIFEST...\n"
./python/manifest_analysis.py > results/manifest_analysis.txt

echo -e "[*] GREPPING PATTERNS IN SOURCE...\n"
./python/ripgrep.py "$PWD/jadx/sources" > results/ripgrep.txt

echo -e "[*] SEARCHING FOR STRINGS IN RESOURCES...\n"
./python/strings.py "$PWD/jadx/resources" > results/strings.txt

# echo -e "[*] SEARCHING FOR PAYLOADS IN RESOURCES...\n"
# ./static/python/steganography.py "$PWD/jadx/resources" > steganography.txt

# echo -e "[*] ANALYZING NATIVE LIBRARIES...\n"
# ./static/python/steganography.py "$PWD/jadx/resources" > steganography.txt