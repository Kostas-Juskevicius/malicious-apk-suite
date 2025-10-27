#!/usr/bin/env python3

"""Checks whether resource files have potentially been tampered with"""

# 1) if image is way too big in bytes relative to its pixel dimensions
# 2) magic bytes dont correspond. e. g. file extension says png but magic bytes of zip or dex. or elf headers in files. or apk / jar signatures in image files
# 3) file entropy. images have like 6-7, encypted data - 7.5-8
# 4) maybe pass results of this into strings.py to further analyze. but ofc main
# benefit of this script is explicit warnings e. g. "intentionally tampered image file - look into it"
