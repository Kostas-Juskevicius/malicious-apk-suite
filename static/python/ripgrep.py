#!/usr/bin/env python3
import subprocess
import sys


"""
    Key note: this script skips packages that I've encountered
    in the wild to be legit. Nothing prevents a malware author
    from naming their package kotlin.something and hiding
    malicious code there too, but we have to make a decision and
    I decided to make this sacrifice for the sake of a handy tool.
    The effort/time proportion to gain isn't good enough for me
    not to skip these packages. Too much noise would be grepped.

    Script prerequisites: ripgrep installed
"""
# TODO: some obfuscation does repeating patterns e. g. d1111e1111c1111r1111y1111p1111t111(...), so we can try to sed the "1111" with ""
# the difficulty is in determining that its in fact "1111" - maybe long substrings repeating 3+ times in a line?


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


CRYPTO_PATTERNS = [
    r"\.decrypt\(",
    r"\.encrypt\(",
    r"Cipher\.getInstance",
    r"javax\.crypto",
    r"java\.security",
    r"SecretKeySpec",
    r"IvParameterSpec",
    r"KeyGenerator",
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
    r"ACTION_INSTALL_PACKAGE",
    r"PackageInstaller",
    r"\.installPackage\(",
    r"INSTALL_PACKAGES",
    r"REQUEST_INSTALL_PACKAGES",
]

SMS_PATTERNS = [
    r"SmsManager",
    r"\.sendTextMessage\(",
    r"SMS_RECEIVED",
    r"android\.provider\.Telephony",
    r"getDefault\(\)\.sendTextMessage",
]

ACCESSIBILITY_PATTERNS = [
    r"AccessibilityService\b",
    r"TYPE_ACCESSIBILITY_OVERLAY",
    r"TYPE_APPLICATION_OVERLAY",
    r"SYSTEM_ALERT_WINDOW",
    r"AccessibilityEvent",
    r"performGlobalAction",
]

OBFUSCATION_PATTERNS = [
    r"String\s+\w+\s*=\s*\"[^\"]*\"\s*\+\s*\"[^\"]*\"\s*\+", # string concatenation
    r'"\s*\+\s*"',  # string concatenation
]

WEBVIEW_PATTERNS = [
    r"WebView",
    r"loadUrl\(",
    r"addJavascriptInterface",
    r"setJavaScriptEnabled",
    r"evaluateJavascript",
]

REFLECTION_PATTERNS = [
    r"Class\.forName\(",
    r"\.getMethod\(",
    r"\.invoke\(",
    r"getDeclaredMethod",
    r"\.newInstance\(",
]

DYNAMIC_LOADING_PATTERNS = [
    r"DexClassLoader",
    r"PathClassLoader",
    r"\.loadClass\(",
    r"DexFile",
    r"loadDex",
]

NETWORK_PATTERNS = [
    r"HttpURLConnection",
    r"OkHttpClient",
    r"\.openConnection\(",
    r"HttpClient",
    r"\.execute\(",
    r"Socket\(",
]

FILE_OPS_PATTERNS = [
    r"\.delete\(",
    r"\.deleteOnExit\(",
    r"FileOutputStream",
    r"\.write\(",
    r"Runtime\.getRuntime\(\)\.exec",
]

NATIVE_PATTERNS = [
    r"System\.loadLibrary\(['\"](?!.*(?:firebase|gms))[^'\"]+['\"]\)",  # exclude firebase/gms
    r"public\s+(?:static\s+)?native\s+",
    r"native\s+\w+\s+\w+\(",
]

LOGGING_PATTERNS = [
    r"Log\.[a-z]\(",  # Log.d(, Log.e(, etc
]

PERSISTENCE_PATTERNS = [
    r"AlarmManager\.setRepeating",
    r"START_STICKY",
    r"BOOT_COMPLETED",
    r"onStartCommand",
    r"AlarmManager",
    r"setRepeating",
]

IMAGE_PAYLOAD_PATTERNS = [
    r"getPixel",
]


def grep_and_print(label, patterns):
    print(f"[*] GREPPING FOR {label}...")
    cmd = ["rg", "--json", "--type", "java", "-P"]
    for p in patterns:
        cmd.extend(["-e", p])
    cmd.append(SOURCES_DIR)
    
    result = subprocess.run(cmd, capture_output=True, text=True)

    for line in result.stdout.strip().split('\n'):
        if not line:
            continue
        try:
            data = json.loads(line)
            if data.get('type') == 'match':
                m = data['data']
                filepath = m['path']['text']
                
                skip = False
                for pkg in SKIP_PACKAGES:
                    if pkg in filepath:
                        skip = True
                        break
                
                if skip:
                    continue
                
                print(f"[*] FOUND {label}: {m['lines']['text'].strip()} in {filepath} at line {m['line_number']}")
        except:
            continue
    print()


LABELS = [
    ("CRYPTO", CRYPTO_PATTERNS),
    ("BASE64", BASE64_PATTERNS),
    ("KEY", HARDCODED_KEYS),
    ("DROPPER", DROPPER_PATTERNS),
    ("SMS", SMS_PATTERNS),
    ("ACCESSIBILITY", ACCESSIBILITY_PATTERNS),
    ("OBFUSCATION", OBFUSCATION_PATTERNS),
    ("WEBVIEW", WEBVIEW_PATTERNS),
    ("REFLECTION", REFLECTION_PATTERNS),
    ("DYNAMIC_LOAD", DYNAMIC_LOADING_PATTERNS),
    ("NETWORK", NETWORK_PATTERNS),
    ("FILE_OPS", FILE_OPS_PATTERNS),
    ("NATIVE", NATIVE_PATTERNS),
    ("LOG", LOGGING_PATTERNS),
    ("PERSISTENCE", PERSISTENCE_PATTERNS),
]

for label, patterns in LABELS:
    grep_and_print(label, patterns)
print("\n[*] GREPPING COMPLETE\n")