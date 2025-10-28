#!/usr/bin/env python3
from lxml import etree

"""Parses the manifest and reports permission information grouped by protection level"""


DANGEROUS_PERMISSIONS = [
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.CALL_PHONE",
    "android.permission.CAMERA",
    "android.permission.GET_ACCOUNTS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_VISUAL_USER_SELECTED",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECORD_AUDIO",
    "android.permission.SEND_SMS",
    "android.permission.USE_SIP",
    "android.permission.UWB_RANGING",
    "android.permission.WRITE_CALENDAR",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.WRITE_CONTACTS",
    "android.permission.WRITE_EXTERNAL_STORAGE",
]

SIGNATURE_PERMISSIONS = [
    "android.permission.ACCOUNT_MANAGER",
    "android.permission.BATTERY_STATS",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_APPWIDGET",
    "android.permission.BIND_CARRIER_SERVICES",
    "android.permission.BIND_CHOOSER_TARGET_SERVICE",
    "android.permission.BIND_CONDITION_PROVIDER_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.BIND_DREAM_SERVICE",
    "android.permission.BIND_INPUT_METHOD",
    "android.permission.BIND_MIDI_DEVICE_SERVICE",
    "android.permission.BIND_NFC_SERVICE",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
    "android.permission.BIND_PRINT_SERVICE",
    "android.permission.BIND_QUICK_SETTINGS_TILE",
    "android.permission.BIND_REMOTEVIEWS",
    "android.permission.BIND_SCREENING_SERVICE",
    "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
    "android.permission.BIND_TEXT_SERVICE",
    "android.permission.BIND_TV_INPUT",
    "android.permission.BIND_VISUAL_VOICEMAIL_SERVICE",
    "android.permission.BIND_VOICE_INTERACTION",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.BIND_VR_LISTENER_SERVICE",
    "android.permission.BIND_WALLPAPER",
    "android.permission.BRICK",
    "android.permission.BROADCAST_PACKAGE_REMOVED",
    "android.permission.BROADCAST_SMS",
    "android.permission.BROADCAST_WAP_PUSH",
    "android.permission.CALL_PRIVILEGED",
    "android.permission.CAPTURE_AUDIO_OUTPUT",
    "android.permission.CHANGE_COMPONENT_ENABLED_STATE",
    "android.permission.CLEAR_APP_CACHE",
    "android.permission.CONTROL_LOCATION_UPDATES",
    "android.permission.DELETE_CACHE_FILES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.DIAGNOSTIC",
    "android.permission.DUMP",
    "android.permission.FACTORY_TEST",
    "android.permission.FORCE_STOP_PACKAGES",
    "android.permission.GET_PACKAGE_SIZE",
    "android.permission.GLOBAL_SEARCH",
    "android.permission.INSTALL_LOCATION_PROVIDER",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.INSTALL_SHORTCUT",
    "android.permission.INTERACT_ACROSS_USERS",
    "android.permission.INTERACT_ACROSS_USERS_FULL",
    "android.permission.INTERNAL_SYSTEM_WINDOW",
    "android.permission.MANAGE_DOCUMENTS",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_USB",
    "android.permission.MASTER_CLEAR",
    "android.permission.MEDIA_CONTENT_CONTROL",
    "android.permission.MODIFY_PHONE_STATE",
    "android.permission.MOUNT_FORMAT_FILESYSTEMS",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.READ_FRAME_BUFFER",
    "android.permission.READ_LOGS",
    "android.permission.READ_PRIVILEGED_PHONE_STATE",
    "android.permission.REBOOT",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SEND_RESPOND_VIA_MESSAGE",
    "android.permission.SET_ALWAYS_FINISH",
    "android.permission.SET_ANIMATION_SCALE",
    "android.permission.SET_DEBUG_APP",
    "android.permission.SET_PREFERRED_APPLICATIONS",
    "android.permission.SET_PROCESS_LIMIT",
    "android.permission.SET_TIME",
    "android.permission.SET_TIME_ZONE",
    "android.permission.SIGNAL_PERSISTENT_PROCESSES",
    "android.permission.STATUS_BAR",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.UPDATE_DEVICE_STATS",
    "android.permission.WRITE_APN_SETTINGS",
    "android.permission.WRITE_GSERVICES",
    "android.permission.WRITE_SECURE_SETTINGS",
    "android.permission.WRITE_SETTINGS",
]


tree = etree.parse("jadx/resources/AndroidManifest.xml")
root = tree.getroot()
package = root.get("package")
ns = {"android": "http://schemas.android.com/apk/res/android"}


# All permissions
all_permissions = root.xpath("//uses-permission/@android:name", namespaces=ns)

# Categorization
dangerous_permissions = []
signature_permissions = []
normal_permissions = []

for perm in all_permissions:
    if perm in DANGEROUS_PERMISSIONS:
        dangerous_permissions.append(perm)
    elif perm in SIGNATURE_PERMISSIONS:
        signature_permissions.append(perm)
    else:
        normal_permissions.append(perm)


# Results
print(f"TOTAL: {len(normal_permissions)} normal, {len(dangerous_permissions)} dangerous, {len(signature_permissions)} signature")

if normal_permissions:
    print("[*] NORMAL PERMISSIONS (granted automatically)")
    for perm in normal_permissions:
        print(f"[*] {perm}")
    print()

if dangerous_permissions:
    print("[*] DANGEROUS PERMISSIONS (require user approval)")
    for perm in dangerous_permissions:
        print(f"[*] {perm}")
    print()

if signature_permissions:
    print("[*] SIGNATURE PERMISSIONS (require signature match - so usually needs to be system app)")
    for perm in signature_permissions:
        print(f"[*] {perm}")
    print()