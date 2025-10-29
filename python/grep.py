#!/usr/bin/env python3
from collections import defaultdict
import os
import subprocess
import sys
import json

"""Greps malicious code patterns in jadx decompilation output"""

SOURCES_DIR = sys.argv[1] if len(sys.argv) > 1 else sys.exit("[*] ERROR: you must pass the path to jadx output of sources as the first arg.")

SKIP_PACKAGES = [
    'kotlin/',
    'kotlinx/',
    'androidx/',
    'android/support/',
    'com/google/android/gms/',
    'com/google/firebase/',
    'com/google/android/datatransport/',
    'org/jetbrains/',
    'java/',
    'javax/',
    'sun/',
    'org/apache/',
    'okhttp3/',
    'retrofit2/',
    'com/squareup/',
]

SMS_PATTERNS = [
    r"\bSmsManager\b",
    r"\bsendTextMessage\s*\(",
    r"\bsendMultipartTextMessage\s*\(",
    r"\bsendDataMessage\s*\(",
    r"\bSMS_RECEIVED\b",
    r"\bSMS_DELIVER\b",
    r"android\.provider\.Telephony",
    r"\bgetDefault\s*\(\)\s*\.\s*sendTextMessage",
    r"content://sms",
    r"\bSmsMessage\b",
    r"\bcreateSmsMessage\s*\(",
    r"\bgetMessagesFromIntent\s*\(",
    r"\bgetOriginatingAddress\s*\(",
    r"\bgetMessageBody\s*\(",
    r"\bgetDisplayOriginatingAddress\s*\(",
    r"android\.provider\.Telephony\.Sms",
    r"android\.provider\.Telephony\.Mms",
    r"getSimOperator",
    r"Context\.TELEPHONY_SERVICE",
    r"TelephonyManager",
    r"WifiManager", # need to turn off wifi for toll fraud. this class can turn off wifi
    r"Context\.CONNECTIVITY_SERVICE", # this can check for wifi
    r"Telephpony\.Sms\.getDefaultSmsPackage\(this\)", # note: may be used to read sms in notifications
]

CRYPTO_PATTERNS = [
    # Weak / problematic algorithms or modes (explicit, string-literal)
    r"\"AES/ECB(?:/PKCS5Padding|/PKCS7Padding)?\"",
    r"\"DES/ECB(?:/PKCS5Padding)?\"",
    r"\"RSA/ECB(?:/PKCS1Padding)?\"",
    r"MessageDigest\.getInstance\s*\(\s*\"(?:MD5|SHA-1|SHA1)\"\s*\)",

    # Hardcoded keys or key material (Base64 of AES key length — 16 bytes -> 24 base64 chars)
    r"['\"][A-Za-z0-9+/]{24}={0,2}['\"]",   # likely hardcoded 16-byte key (base64)
    r"['\"][A-Za-z0-9+/]{32,44}={0,2}['\"]",# longer base64 (24/32-byte keys)

    # SecretKeySpec constructed directly from literal bytes/strings (very suspicious)
    r"new\s+SecretKeySpec\s*\(\s*(?:\"[^\"]+\"|'[^']+'|new\s+byte\s*\[.*\])\s*,",
    r"\bSecretKeySpec\s*\b",                # kept so we know class is used (but deprioritize alone)

    # Static / hardcoded IVs (byte arrays or literal strings next to IvParameterSpec)
    r"new\s+IvParameterSpec\s*\(\s*(?:new\s+byte\s*\[.*\]|\s*\"[^\"]+\"|'[^']+')\s*\)",
    r"\bIvParameterSpec\b",

    # Exposing raw key material or exported keys
    r"\bgetEncoded\s*\(",

    # Custom/trusting crypto implementations that indicate bypassing standard protections
    r"(?:implements|new)\s+X509TrustManager",
    r"HostnameVerifier\s*\{[^}]*\bverify\s*\([^)]*\)\s*\{[^}]*\breturn\s+true\s*;[^}]*\}",

    # Dynamic crypto APIs that are suspicious when combined with hardcoded keys or dynamic loading
    r"\bCipher\.getInstance\s*\(",
]

BASE64_PATTERNS = [
    r"Base64\.decode",
    r"Base64\.encode",
    r"getDecoder\(\)",
    r"getEncoder\(\)",
    r'aHR0cDovL2',  # http:// in base64
    r'aHR0cHM6Ly9',  # https:// in base64
    r"'[a-zA-Z0-9+/]{8,}={1,2}'",
]

HARDCODED_KEYS = [
    r'"[A-Za-z0-9+/]{40,}={0,2}"',  # long base64 strings
]

DROPPER_PATTERNS = [
    r"\bACTION_INSTALL_PACKAGE\b",
    r"\bPackageInstaller\b",
    r"\binstallPackage\s*\(",
    r"\bINSTALL_PACKAGES\b",
    r"\bREQUEST_INSTALL_PACKAGES\b",
    r"\bSessionParams\b",
    r"\bcreateSession\s*\(",
    r"\bopenSession\s*\(",
    r"\bcommit\s*\(",
    r"\bwriteSession\s*\(",
    r"\bInstallReceiver\b",
    r"\bsetInstallLocation\s*\(",
    r"\binstallExistingPackage\s*\(",
    r"\binstallPackageWithVerification\s*\(",
    r"\bDELETE_PACKAGE\b",
    r"\bdeletePackage\s*\(",
    r"\buninstallPackage\s*\(",
    r"application/vnd\.android\.package-archive",
    r"\.apk[\"']",
    r"\bgetPackageInstaller\s*\(",
]

TELEPHONY_PATTERNS = [
    r"\bSmsManager\b",
    r"\bsendTextMessage\s*\(",
    r"\bsendMultipartTextMessage\s*\(",
    r"\bsendDataMessage\s*\(",
    r"\bSMS_RECEIVED\b",
    r"\bSMS_DELIVER\b",
    r"android\.provider\.Telephony",
    r"\bgetDefault\s*\(\)\s*\.\s*sendTextMessage",
    r"content://sms",
    r"\bSmsMessage\b",
    r"\bcreateSmsMessage\s*\(",
    r"\bgetMessagesFromIntent\s*\(",
    r"\bgetOriginatingAddress\s*\(",
    r"\bgetMessageBody\s*\(",
    r"\bgetDisplayOriginatingAddress\s*\(",
    r"android\.provider\.Telephony\.Sms",
    r"android\.provider\.Telephony\.Mms",
    r"SMS_RECEIVED_ACTION",
    r"\.get\(\"pdus\"\)",
    r"SmsMessage",
    r"\.getMessageBody",
    r"\.createFromPdu",
]

ACCESSIBILITY_PATTERNS = [
    r"\bAccessibilityService\b",
    r"\bAccessibilityEvent\b",
    r"\bAccessibilityNodeInfo\b",
    r"\bTYPE_ACCESSIBILITY_OVERLAY\b",
    r"\bTYPE_APPLICATION_OVERLAY\b",
    r"\bSYSTEM_ALERT_WINDOW\b",
    r"\bperformGlobalAction\s*\(",
    r"\bperformAction\s*\(",
    r"\bfindAccessibilityNodeInfosByText\s*\(",
    r"\bfindAccessibilityNodeInfosByViewId\s*\(",
    r"\bgetRootInActiveWindow\s*\(",
    r"\bgetSource\s*\(",
    r"\bACTION_CLICK\b",
    r"\bACTION_LONG_CLICK\b",
    r"\bACTION_SCROLL_FORWARD\b",
    r"\bACTION_SCROLL_BACKWARD\b",
    r"\bACTION_PASTE\b",
    r"\bACTION_SET_TEXT\b",
    r"\bGLOBAL_ACTION_BACK\b",
    r"\bGLOBAL_ACTION_HOME\b",
    r"\bGLOBAL_ACTION_RECENTS\b",
    r"\bGLOBAL_ACTION_NOTIFICATIONS\b",
    r"\bonAccessibilityEvent\s*\(",
    r"\bonInterrupt\s*\(",
    r"\bgetPackageName\s*\(",
    r"\bgetClassName\s*\(",
    r"\bgetEventType\s*\(",
    r"TYPE_WINDOW_STATE_CHANGED\b",
    r"TYPE_VIEW_CLICKED\b",
    r"TYPE_VIEW_FOCUSED\b",
    r"TYPE_VIEW_TEXT_CHANGED\b",
]

STRING_CONCATENATION_PATTERNS = [
    r'"."\s*\+\s*"."',
]

WEBVIEW_PATTERNS = [
    r"\baddJavascriptInterface\s*\(",
    r"@JavascriptInterface",
    r"\bevaluateJavascript\s*\(",
    r"\bsetAllowFileAccessFromFileURLs\s*\(",
    r"\bsetAllowUniversalAccessFromFileURLs\s*\(",
    r"\bonReceivedSslError\s*\(",
]

DATA_EXFILTRATION_PATTERNS = [
    # Device identifiers
    r"\bgetDeviceId\s*\(",
    r"\bgetSubscriberId\s*\(",
    r"\bgetSimSerialNumber\s*\(",
    r"\bgetLine1Number\s*\(",
    r"\bgetImei\s*\(",
    r"\bgetMeid\s*\(",
    r"\bgetSimCountryIso\s*\(",
    r"\bgetNetworkOperator\s*\(",

    # Accounts
    r"\bgetAccounts\s*\(",
    r"\bgetAccountsByType\s*\(",

    # Sensitive content URIs
    r"content://sms",
    r"content://contacts",
    r"content://call_log",
    r"content://browser",
]

REFLECTION_PATTERNS = [
    r"\bClass\.forName\s*\(",
    r"\bgetClass\s*\(\)",
    r"\bgetMethod\s*\(",
    r"\bgetDeclaredMethod\s*\(",
    r"\bgetMethods\s*\(\)",
    r"\bgetDeclaredMethods\s*\(\)",
    r"\bgetField\s*\(",
    r"\bgetDeclaredField\s*\(",
    r"\bgetFields\s*\(\)",
    r"\bgetDeclaredFields\s*\(\)",
    r"\bgetConstructor\s*\(",
    r"\bgetDeclaredConstructor\s*\(",
    r"\binvoke\s*\(",
    r"\bnewInstance\s*\(",
    r"\bsetAccessible\s*\(",
    r"\bgetClassLoader\s*\(\)",
    r"\bgetSystemClassLoader\s*\(\)",
    r"\bgetPackage\s*\(\)",
    r"\bgetAnnotation\s*\(",
    r"\bgetModifiers\s*\(\)",
]

DYNAMIC_LOADING_PATTERNS = [
    r"\bDexClassLoader\b",
    r"\bPathClassLoader\b",
    r"\bInMemoryDexClassLoader\b",
    r"\.loadClass\s*\(",
    r"\bDexFile\b",
    r"\.loadDex\s*\(",
    r"\bClass\.forName\s*\(",
    r"\.getDeclaredMethod\s*\(",
    r"\.invoke\s*\(",
    r"\bdalvik\.system\.",
    r"System\.load\s*\(",
    r"System\.loadLibrary\s*\(",
]

NETWORK_PATTERNS = [
    # Remote targets embedded as string literals (hardcoded URLs / IPs) — high signal
    r"\"https?://[^\"]+\"",                       # any hardcoded http(s) URL string
    r"\"(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\"",      # hardcoded IPv4 (optionally with port)

    # Native execution + process spawn (often used for persistence, tunneling, obfuscation)
    r"Runtime\.getRuntime\s*\(\s*\)\.exec\b",
    r"\bProcessBuilder\b",

    # Insecure SSL handling / certificate pinning bypasses
    r"\bX509TrustManager\b",
    r"\bHostnameVerifier\b",
    r"(?:implements|new)\s+X509TrustManager",
    r"HostnameVerifier\s*\{[^}]*\bverify\s*\([^)]*\)\s*\{[^}]*\breturn\s+true\s*;[^}]*\}",

    # Dynamic code loading combined with networking (dex loading is very suspicious if paired with remote fetch)
    r"\bDexClassLoader\b",
    r"\bClass\.forName\s*\(",

    # WebSocket usage (commonly used for C2)
    r"\bWebSocket\b",
    r"wss?://",
]

FILE_OPS_PATTERNS = [
    r"\"java.io.tmpdir\"",
    r"new\s+FileWriter",
    r"Files\.(?:exists|readAllLines|readAllBytes|write|delete|copy|move)",
    r"FileChannel",
    r"new Scanner\(new File\(",
    r"AsynchronousFileChannel",
    r"File.(?:delete|deleteOnExit)",
    r"File.(?:exists|canRead|canWrite|list|listFiles|newDirectoryStream)",
]

COMMAND_EXECUTION_PATTERNS = [
    # Explicit Java/Android process execution APIs
    r"\bRuntime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
    r"\bnew\s+ProcessBuilder\s*\(",

    # Process control methods (only match when file also hits exec/ProcessBuilder)
    r"\bwaitFor\s*\(",
    r"\bdestroyForcibly\s*\(",

    # Hardcoded absolute shells or binaries (string-literal form)
    r"['\"](?:/system/bin/sh|/system/xbin/su|/system/bin/su|/sbin/su)['\"]",
    r"['\"](?:/system/bin/busybox|/system/xbin/busybox|busybox)['\"]",

    # Explicit package manager or activity manager commands (string-literal)
    r"['\"]pm\s+install(?:\s+-r)?\s+[^\"]+['\"]",
    r"['\"]pm\s+uninstall\s+[^\"]+['\"]",
    r"['\"]am\s+start\b[^\"]*['\"]",

    # chmod / chown when used as literal commands (likely for persistence / privilege change)
    r"['\"](?:chmod|chown)\s+[^\"]+['\"]",
]

NATIVE_PATTERNS = [
    r"System\.loadLibrary\(\"(?!.*(?:firebase|gms)).*\"\)",  # exclude firebase/gms
    r"System\.load\(\"(?!.*(?:firebase|gms)).*\"\)",  # exclude firebase/gms
    r"(?:static\s+)?native\s+\w+\s+\w",
]

LOGGING_PATTERNS = [
    r"Log\.[a-z]\(",  # Log.d(, Log.e(, etc
]

PERSISTENT_SERVICE_PATTERNS = [
    r"\bSTART_STICKY\b",
    r"\bSTART_NOT_STICKY\b",
    r"\bSTART_REDELIVER_INTENT\b",
    r"\bstartService\s*\(",
    r"\bstartForegroundService\s*\(",
    r"\bstartForeground\s*\(",
    r"\bJobScheduler\b",
    r"\bschedule\s*\(",
    r"\bJobService\b",
    r"\bonStartJob\s*\(",
    r"\bWorkManager\b",
    r"\bPeriodicWorkRequest\b",
    r"\bAlarmManager\b",
    r"\bsetRepeating\s*\(",
    r"\bsetInexactRepeating\s*\(",
    r"\bsetExact\s*\(",
    r"\bsetAlarmClock\s*\(",
    r"\bBOOT_COMPLETED\b",
    r"\bUSER_PRESENT\b",
    r"\bACTION_BOOT_COMPLETED\b",
    r"\bRECEIVE_BOOT_COMPLETED\b",
    r"\brestartService\s*\(",
]

IMAGE_PAYLOAD_PATTERNS = [
    r"\bgetPixel\s*\(",
    r"\bgetPixels\s*\(",
    r"\bsetPixel\s*\(",
    r"\bsetPixels\s*\(",
    r"\bBitmapFactory\.decodeByteArray\s*\(",
    r"\bBitmapFactory\.decodeStream\s*\(",
    r"\bBitmap\.createBitmap\s*\(",
    r"\bgetByteCount\s*\(",
    r"\bcopyPixelsToBuffer\s*\(",
    r"\bcopyPixelsFromBuffer\s*\(",
    r"\.png[\"']",
    r"\.jpg[\"']",
    r"\.jpeg[\"']",
    r"\.bmp[\"']",
    r"\brecycle\s*\(",
]

# not necessarily malicious
MISCELANEOUS_PATTERNS = [
    r"\.setPriority\()",
    r"\.query\(Uri\.parse", # content resolver query
    r"registerContentObserver",
    r"onNotificationPosted",
    r"NotificationListenerService",
    r"notification\.extras",
]

def grep_and_print(label, patterns, exclude_patterns):
    cmd = ["rg", "--json", "--type", "java", "-P"]
    for p in patterns:
        cmd.extend(["-e", p])
    cmd.append(SOURCES_DIR)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    # pattern_header_printed = False
    matches_by_file = defaultdict(list)

def grep_and_print(label, patterns, exclude_patterns):
    cmd = ["rg", "--json", "--type", "java", "-P"]
    for p in patterns:
        cmd.extend(["-e", p])
    cmd.append(SOURCES_DIR)
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    matches_by_file = defaultdict(list)
    
    for line in filter(None, lines):
        data = json.loads(line)
        if data.get('type') != 'match':
            continue

        m = data['data']
        filepath = m['path']['text']
        line_text = m['lines']['text'].strip() # misleading key. its a single line, not 'lines'
        line_number = m['line_number']

        # skip grepping from packages e. g. legit packages                
        skip = False
        for pkg in SKIP_PACKAGES:
            if pkg in filepath:
                skip = True
                break
        if skip:
            continue

        # skip words e. g. if method is /* synthetic */ - generated by jadx decompiler, not written by malware dev
        for exclude in exclude_patterns:
            if exclude in line_text:
                skip = True
                break
        if skip:
            continue
        
        matches_by_file[filepath].append((line_number, line_text))
    
    if matches_by_file:
        print(f"[*] GREPPING FOR {label}...")
        for filepath, matches in matches_by_file.items():
            print(f"\t[*] FOUND IN: {os.path.basename(filepath)}")
            for line_number, line_text in matches:
                print(f"\t\t[*] CODE: {line_text}")
                print(f"\t\t[*] AT LINE: {line_number}")
                print(f"\t\t[*]")
        print()


LABELS = [
    ("CRYPTO", CRYPTO_PATTERNS, []),
    ("BASE64", BASE64_PATTERNS, []),
    ("KEY", HARDCODED_KEYS, []),
    ("DROPPER", DROPPER_PATTERNS, []),
    ("TELEPHONY", TELEPHONY_PATTERNS, []),
    ("ACCESSIBILITY", ACCESSIBILITY_PATTERNS, []),
    ("STRING CONCATENATION", STRING_CONCATENATION_PATTERNS, []),
    ("WEBVIEW", WEBVIEW_PATTERNS, []), 
    ("DATA EXFILTRATION PATTERNS", DATA_EXFILTRATION_PATTERNS, []),
    ("REFLECTION", REFLECTION_PATTERNS, ["/* synthetic */", "/* bridge */"]),
    ("DYNAMIC LOADING", DYNAMIC_LOADING_PATTERNS, []),
    ("NETWORK", NETWORK_PATTERNS, []),
    ("COMMAND EXECUTION_PATTERNS", COMMAND_EXECUTION_PATTERNS, []),
    ("FILE OPS", FILE_OPS_PATTERNS, []),
    ("NATIVE", NATIVE_PATTERNS, ["/* synthetic */"]),
    ("LOG", LOGGING_PATTERNS, []),
    ("SERVICE PERSISTENCE", PERSISTENT_SERVICE_PATTERNS, []),
    ("MISCELANEOUS", MISCELANEOUS_PATTERNS, []),
]
 
for label, patterns, exclude in LABELS:
    grep_and_print(label, patterns, exclude)