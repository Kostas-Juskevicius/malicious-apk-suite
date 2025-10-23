#!/usr/bin/env python3
from lxml import etree


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
    "android.permission.RANGING",
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


tree = etree.parse("jadx/resources/AndroidManifest.xml")
root = tree.getroot()
package = root.get("package") # for this "." case: https://developer.android.com/guide/topics/manifest/manifest-intro#components
ns = {"android": "http://schemas.android.com/apk/res/android"}


# Log package
print(f"[*] FOUND: main package {package}\n")


# Log permissions
for permission in DANGEROUS_PERMISSIONS:
    found = root.xpath(f"//uses-permission[@android:name='{permission}']", namespaces=ns)
    if found:
        print(f"[*] FOUND: found a dangerous permission: {permission}")
print()


# Log components
def qualify_name(name: str) -> str:
    """
    If name starts with '.', qualify it with package.
    """
    if name.startswith("."):
        return f"{package}{name}"
    return name

application = root.xpath("//application/@android:name", namespaces=ns)
print(f"[*] FOUND: application: {qualify_name(application[0])}\n")

main_activity = root.xpath(
    "//activity[intent-filter/action[@android:name='android.intent.action.MAIN'] and intent-filter/category[@android:name='android.intent.category.LAUNCHER']]/@android:name",
    namespaces=ns
)
if main_activity:
    print(f"[*] FOUND: main activity that's a launcher (appears on home screen): {qualify_name(main_activity)}\n")

for activity in root.xpath("//activity/@android:name", namespaces=ns):
    print(f"[*] FOUND: activity: {qualify_name(activity)}")
print()

for service in root.xpath("//service/@android:name", namespaces=ns):
    print(f"[*] FOUND: service: {qualify_name(service)}")
print()

for receiver in root.xpath("//receiver"):
    receiver_name = receiver.xpath("@android:name", namespaces=ns)
    r_name = receiver_name[0] if receiver_name else "Unknown"
    print(f"[*] FOUND: receiver: {qualify_name(r_name)}")
    actions = receiver.xpath("intent-filter/action/@android:name", namespaces=ns)
    for action in actions:
        print(f"\t[*] FOUND: receiver action: {action}")
print()

for provider in root.xpath("//provider/@android:name", namespaces=ns):
    print(f"[*] FOUND: provider: {qualify_name(provider)}")