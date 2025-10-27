#!/usr/bin/env python3

# 1) if image is way too big in bytes relative to its pixel dimensions
# 2) magic bytes dont correspond. e. g. file extension says png but magic bytes of zip or dex. or elf headers in files. or apk / jar signatures in image files
# 3) file entropy. images have like 6-7, encypted data - 7.5-8
