#!/usr/bin/env python3

"""Reports quick, potentially useful information about the native libraries present"""

# 1) maybe readelf -s to get globally exported symbols. ignore _FINI_<number 0+>
# 2) JNI_ONLOAD present?