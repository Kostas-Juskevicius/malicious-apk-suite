#!/usr/bin/env python3
from lxml import etree

"""Parses the manifest and reports component information"""


IGNORABLE_COMPONENTS = [
    "com.google.android.gms",
    "com.google.firebase",
    "com.google.android.datatransport",
    "androidx.profileinstaller",
    "androidx.startup",
]


tree = etree.parse("jadx/resources/AndroidManifest.xml")
root = tree.getroot()
package = root.get("package")
ns = {"android": "http://schemas.android.com/apk/res/android"}


def qualify_name(name: str) -> str:
    """
    If name starts with '.', qualify it with package.
    """
    if name.startswith("."):
        return f"{package}{name}"
    return name

def is_ignorable(component_name: str) -> bool:
    return any(component_name.startswith(prefix) for prefix in IGNORABLE_COMPONENTS)


print(f"[*] FOUND: main package {package}\n")

application = root.xpath("//application/@android:name", namespaces=ns)
if application and not is_ignorable(qualify_name(application[0])):
    print(f"[*] FOUND: application: {qualify_name(application[0])}\n")

main_activity = root.xpath(
    "//activity[intent-filter/action[@android:name='android.intent.action.MAIN'] and intent-filter/category[@android:name='android.intent.category.LAUNCHER']]/@android:name",
    namespaces=ns
)
if main_activity and not is_ignorable(qualify_name(main_activity[0])):
    print(f"[*] FOUND: main activity that's a launcher (appears on home screen): {qualify_name(main_activity[0])}\n")

for activity in root.xpath("//activity/@android:name", namespaces=ns):
    if not is_ignorable(qualify_name(activity)):
        print(f"[*] FOUND: activity: {qualify_name(activity)}")
print()

for service in root.xpath("//service/@android:name", namespaces=ns):
    if not is_ignorable(qualify_name(service)):
        print(f"[*] FOUND: service: {qualify_name(service)}")
print()

for receiver in root.xpath("//receiver"):
    receiver_name = receiver.xpath("@android:name", namespaces=ns)[0]
    if not is_ignorable(qualify_name(receiver_name)):
        print(f"[*] FOUND: receiver: {qualify_name(receiver_name)}")
        actions = receiver.xpath("intent-filter/action/@android:name", namespaces=ns)
        for action in actions:
            print(f"\t[*] FOUND: receiver action: {action}")
print()

for provider in root.xpath("//provider/@android:name", namespaces=ns):
    if not is_ignorable(qualify_name(provider)):
        print(f"[*] FOUND: provider: {qualify_name(provider)}")