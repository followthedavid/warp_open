#!/usr/bin/env python3
"""List all ChatGPT windows to find the main one"""

from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID

window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)

print("All ChatGPT windows:")
print("=" * 80)

chatgpt_windows = []
for i, window in enumerate(window_list):
    owner_name = window.get('kCGWindowOwnerName', '')
    if owner_name == 'ChatGPT':
        bounds = window.get('kCGWindowBounds', {})
        layer = window.get('kCGWindowLayer', 'N/A')
        window_id = window.get('kCGWindowNumber', 'N/A')
        name = window.get('kCGWindowName', 'Unnamed')

        info = {
            'id': window_id,
            'name': name,
            'x': bounds.get('X', 0),
            'y': bounds.get('Y', 0),
            'width': bounds.get('Width', 0),
            'height': bounds.get('Height', 0),
            'layer': layer
        }

        chatgpt_windows.append(info)

        print(f"\nWindow #{len(chatgpt_windows)}:")
        print(f"  ID: {info['id']}")
        print(f"  Name: {info['name']}")
        print(f"  Position: ({info['x']}, {info['y']})")
        print(f"  Size: {info['width']}x{info['height']}")
        print(f"  Layer: {info['layer']}")

print("\n" + "=" * 80)
print(f"Total ChatGPT windows found: {len(chatgpt_windows)}")

# Find the largest window (likely the main chat window)
if chatgpt_windows:
    largest = max(chatgpt_windows, key=lambda w: w['width'] * w['height'])
    print(f"\nLargest window (likely main chat):")
    print(f"  Size: {largest['width']}x{largest['height']}")
    print(f"  Position: ({largest['x']}, {largest['y']})")
    print(f"  Name: {largest['name']}")
