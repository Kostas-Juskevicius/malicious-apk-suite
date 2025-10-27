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
]

CRYPTO_PATTERNS = [
    r"\bdecrypt\s*\(",
    r"\bencrypt\s*\(",
    r"\bCipher\.getInstance\s*\(",
    r"javax\.crypto",
    r"java\.security",
    r"\bSecretKeySpec\b",
    r"\bIvParameterSpec\b",
    r"\bKeyGenerator\b",
    r"\bKeyPairGenerator\b",
    r"\bSecretKeyFactory\b",
    r"\bMessageDigest\b",
    r"\bMac\.getInstance\s*\(",
    r"\bdoFinal\s*\(",
    r"\binit\s*\(",
    r"\bupdate\s*\(",
    r"\bPBEKeySpec\b",
    r"\bSecureRandom\b",
    r"\bKeyStore\b",
    r"AES/CBC",
    r"AES/ECB",
    r"DES/CBC",
    r"RSA/ECB",
    r"\bgetInstance\s*\(",
    r"\bgenerateKey\s*\(",
    r"\bgenerateKeyPair\s*\(",
    r"\bgetEncoded\s*\(",
]

BASE64_PATTERNS = [
    r"Base64\.decode",
    r"Base64\.encode",
    r"getDecoder\(\)",
    r"getEncoder\(\)",
    r'aHR0cDovL2',  # http:// in base64
    r'aHR0cHM6Ly9',  # https:// in base64
    r'"[a-zA-Z0-9+/]{5,}={1,2}"',
    r"'[a-zA-Z0-9+/]{5,}={1,2}'",
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
    r"\bgetText\s*\(",
    r"\bsetText\s*\(",
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
    r'"\s*\+\s*"',
]

WEBVIEW_PATTERNS = [
    r"\bWebView\b",
    r"\bWebViewClient\b",
    r"\bWebChromeClient\b",
    r"\bloadUrl\s*\(",
    r"\bloadData\s*\(",
    r"\bloadDataWithBaseURL\s*\(",
    r"\baddJavascriptInterface\s*\(",
    r"\bsetJavaScriptEnabled\s*\(",
    r"\bevaluateJavascript\s*\(",
    r"\bsetWebContentsDebuggingEnabled\s*\(",
    r"\bsetAllowFileAccess\s*\(",
    r"\bsetAllowFileAccessFromFileURLs\s*\(",
    r"\bsetAllowUniversalAccessFromFileURLs\s*\(",
    r"\bsetAllowContentAccess\s*\(",
    r"\bsetMixedContentMode\s*\(",
    r"\bsetDomStorageEnabled\s*\(",
    r"\bsetDatabaseEnabled\s*\(",
    r"\bsetGeolocationEnabled\s*\(",
    r"\bsetAppCacheEnabled\s*\(",
    r"\bonReceivedSslError\s*\(",
    r"\bshouldOverrideUrlLoading\s*\(",
    r"\bonJsAlert\s*\(",
    r"\bonJsConfirm\s*\(",
    r"\bonJsPrompt\s*\(",
]

DATA_EXFILTRATION_PATTERNS = [
    r"\bgetDeviceId\s*\(",
    r"\bgetSubscriberId\s*\(",
    r"\bgetSimSerialNumber\s*\(",
    r"\bgetLine1Number\s*\(",
    r"\bgetImei\s*\(",
    r"\bgetMeid\s*\(",
    r"\bgetSimCountryIso\s*\(",
    r"\bgetNetworkOperator\s*\(",
    r"\bgetAccounts\s*\(",
    r"\bgetAccountsByType\s*\(",
    r"\bContentResolver\b",
    r"\bquery\s*\(",
    r"content://sms",
    r"content://contacts",
    r"content://call_log",
    r"content://browser",
    r"\bgetInstalledPackages\s*\(",
    r"\bgetInstalledApplications\s*\(",
    r"\bgetRunningAppProcesses\s*\(",
    r"\bgetRunningTasks\s*\(",
    r"\bgetRecentTasks\s*\(",
    r"\bgetLastKnownLocation\s*\(",
    r"\bgetBestProvider\s*\(",
    r"\brequestLocationUpdates\s*\(",
    r"\bgetActiveNetworkInfo\s*\(",
    r"\bgetAllNetworkInfo\s*\(",
    r"\bWifiManager\b",
    r"\bgetConnectionInfo\s*\(",
    r"\bgetScanResults\s*\(",
    r"\bBluetoothAdapter\b",
    r"\bgetBondedDevices\s*\(",
    r"\bstartDiscovery\s*\(",
    r"\bgetSystemService\s*\(",
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
    # Standard Java HTTP
    r"\bHttpURLConnection\b",
    r"\bHttpsURLConnection\b",
    r"\.openConnection\s*\(",
    r"\.getInputStream\s*\(",
    r"\.getOutputStream\s*\(",
    
    # Raw sockets
    r"\bSocket\s*\(",
    r"\bServerSocket\s*\(",
    r"\bDatagramSocket\s*\(",
    r"\bDatagramPacket\s*\(",
    
    # OkHttp (very common in malware)
    r"\bOkHttpClient\b",
    r"\.newCall\s*\(",
    r"\bRequest\.Builder\b",
    
    # Apache HTTP (legacy but still used)
    r"\bDefaultHttpClient\b",
    r"\bHttpPost\b",
    r"\bHttpGet\b",
    r"\.execute\s*\(",
    
    # WebSockets
    r"\bWebSocket\b",
    r"wss?://",
    
    # URLs and IPs
    r"https?://[^\s'\"<>]+",
    r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    
    # SSL/TLS manipulation (common in malware)
    r"\bTrustManager\b",
    r"\bX509TrustManager\b",
    r"\bHostnameVerifier\b",
    r"\.setSSLSocketFactory\s*\(",
    
    # Dynamic loading (often used to hide networking)
    r"\bDexClassLoader\b",
    r"\bClass\.forName\s*\(",
    
    # Native execution
    r"Runtime\.getRuntime\s*\(\s*\)\.exec",
    r"\bProcessBuilder\b",
]

FILE_OPS_PATTERNS = [
    r"\"java.io.tmpdir\"",
    r"new\s+FileWriter",
    r"Files\.(?:exists|readAllLines|readAllBytes|write|delete|copy|move)",
    r"FileOutputStream",
    r"FileInputStream",
    r"FileChannel",
    r"new Scanner\(new File\(",
    r"AsynchronousFileChannel",
    r"File.(?:delete|deleteOnExit)",
    r"File.(?:exists|canRead|canWrite|list|listFiles|newDirectoryStream)",
]

COMMAND_EXECUTION_PATTERNS = [
    r"\bRuntime\.getRuntime\s*\(\)\s*\.\s*exec\s*\(",
    r"\bProcessBuilder\b",
    r"\bstart\s*\(",
    r"\bexec\s*\(",
    r"\bgetInputStream\s*\(",
    r"\bgetOutputStream\s*\(",
    r"\bgetErrorStream\s*\(",
    r"\bwaitFor\s*\(",
    r"\bdestroy\s*\(",
    r"\bdestroyForcibly\s*\(",
    r"[\"']/system/bin/sh[\"']",
    r"[\"']sh[\"']",
    r"[\"']su[\"']",
    r"[\"']busybox[\"']",
    r"[\"']chmod[\"']",
    r"[\"']chown[\"']",
    r"[\"']pm\s+install[\"']",
    r"[\"']pm\s+uninstall[\"']",
    r"[\"']am\s+start[\"']",
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
            print(f"[*] FOUND IN: {os.path.basename(filepath)}")
            for line_number, line_text in matches:
                print(f"\t[*] CODE: {line_text}")
                print(f"\t[*] AT LINE: {line_number}")
                print(f"\t[*]")
        print()


LABELS = [
    ("CRYPTO", CRYPTO_PATTERNS, []),
    ("BASE64", BASE64_PATTERNS, []),
    ("KEY", HARDCODED_KEYS, []),
    ("DROPPER", DROPPER_PATTERNS, []),
    ("SMS", SMS_PATTERNS, []),
    ("ACCESSIBILITY", ACCESSIBILITY_PATTERNS, []),
    ("STRING CONCATENATION", STRING_CONCATENATION_PATTERNS, []),
    ("WEBVIEW", WEBVIEW_PATTERNS, []), 
    ("REFLECTION PATTERNS", DATA_EXFILTRATION_PATTERNS, []),
    ("REFLECTION", REFLECTION_PATTERNS, []),
    ("DYNAMIC LOADING", DYNAMIC_LOADING_PATTERNS, []),
    ("NETWORK", NETWORK_PATTERNS, []),
    ("COMMAND EXECUTION_PATTERNS", COMMAND_EXECUTION_PATTERNS, []),
    ("FILE OPS", FILE_OPS_PATTERNS, []),
    ("NATIVE", NATIVE_PATTERNS, ["synthetic"]),
    ("LOG", LOGGING_PATTERNS, []),
    ("SERVICE PERSISTENCE", PERSISTENT_SERVICE_PATTERNS, []),
]
 
for label, patterns, exclude in LABELS:
    grep_and_print(label, patterns, exclude)
print("\n[*] GREPPING COMPLETE\n")