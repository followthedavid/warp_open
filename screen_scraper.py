#!/usr/bin/env python3
"""
ML-Based Screen Text Extraction for ChatGPT Desktop
Uses EasyOCR to extract text from screen capture
"""

import sys
import time
import json
from pathlib import Path

try:
    import easyocr
    from PIL import Image
    import numpy as np
    from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID
    from Quartz.CoreGraphics import CGWindowListCreateImage, CGRectMake, kCGWindowImageDefault
except ImportError as e:
    print(f"Missing dependencies. Install with:")
    print(f"  pip3 install easyocr pillow pyobjc-framework-Quartz")
    print(f"Error: {e}")
    sys.exit(1)

class ChatGPTScreenScraper:
    def __init__(self):
        print("[*] Initializing EasyOCR (this may take a moment)...")
        self.reader = easyocr.Reader(['en'], gpu=False)  # CPU mode for compatibility
        print("[+] EasyOCR initialized")

    def find_chatgpt_window(self):
        """Find ChatGPT window bounds"""
        window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)

        for window in window_list:
            owner_name = window.get('kCGWindowOwnerName', '')
            if owner_name == 'ChatGPT':
                bounds = window.get('kCGWindowBounds', {})
                return {
                    'x': bounds['X'],
                    'y': bounds['Y'],
                    'width': bounds['Width'],
                    'height': bounds['Height']
                }
        return None

    def capture_window_region(self, bounds):
        """Capture specific region of screen"""
        rect = CGRectMake(
            bounds['x'],
            bounds['y'],
            bounds['width'],
            bounds['height']
        )

        # Capture the window
        image_ref = CGWindowListCreateImage(
            rect,
            kCGWindowListOptionAll,
            kCGNullWindowID,
            kCGWindowImageDefault
        )

        if not image_ref:
            return None

        # Convert to PIL Image
        width = bounds['width']
        height = bounds['height']

        # Create temporary file
        temp_path = '/tmp/chatgpt_screenshot.png'
        from Quartz.CoreGraphics import CGImageDestinationCreateWithURL, CGImageDestinationAddImage, CGImageDestinationFinalize
        from Quartz import kUTTypePNG
        from Foundation import NSURL

        url = NSURL.fileURLWithPath_(temp_path)
        dest = CGImageDestinationCreateWithURL(url, kUTTypePNG, 1, None)
        CGImageDestinationAddImage(dest, image_ref, None)
        CGImageDestinationFinalize(dest)

        return temp_path

    def extract_text(self, image_path):
        """Extract text from image using EasyOCR"""
        results = self.reader.readtext(image_path)

        # Sort by vertical position (top to bottom)
        results.sort(key=lambda x: x[0][0][1])

        # Extract just the text
        text_lines = [text for (bbox, text, conf) in results if conf > 0.3]

        return '\n'.join(text_lines)

    def capture_response(self, wait_time=2):
        """Main function to capture ChatGPT response"""
        print("[*] Finding ChatGPT window...")
        bounds = self.find_chatgpt_window()

        if not bounds:
            print("[-] ChatGPT window not found!")
            return None

        print(f"[+] Found window at ({bounds['x']}, {bounds['y']}) - {bounds['width']}x{bounds['height']}")

        print(f"[*] Waiting {wait_time}s for response to complete...")
        time.sleep(wait_time)

        print("[*] Capturing screen...")
        image_path = self.capture_window_region(bounds)

        if not image_path:
            print("[-] Failed to capture screenshot")
            return None

        print(f"[+] Screenshot saved to {image_path}")

        print("[*] Extracting text with ML OCR...")
        text = self.extract_text(image_path)

        print(f"[+] Extracted {len(text)} characters")

        return text

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 screen_scraper.py <wait_time>")
        print("Example: python3 screen_scraper.py 3  # Wait 3 seconds before capture")
        sys.exit(1)

    wait_time = int(sys.argv[1])

    scraper = ChatGPTScreenScraper()
    text = scraper.capture_response(wait_time)

    if text:
        # Save to file
        output_file = '/tmp/chatgpt_screen_response.txt'
        with open(output_file, 'w') as f:
            f.write(text)

        print(f"\n{'='*80}")
        print("EXTRACTED TEXT:")
        print('='*80)
        print(text)
        print('='*80)
        print(f"\nSaved to: {output_file}")

        # Also output as JSON for programmatic use
        result = {
            'success': True,
            'text': text,
            'length': len(text),
            'timestamp': time.time()
        }
        print('\nJSON:', json.dumps(result))
    else:
        result = {
            'success': False,
            'error': 'Failed to extract text'
        }
        print('JSON:', json.dumps(result))
        sys.exit(1)

if __name__ == '__main__':
    main()
