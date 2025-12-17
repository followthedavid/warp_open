#!/usr/bin/env python3
"""
macOS Vision Framework Screen Text Extraction for ChatGPT Desktop
Uses built-in macOS Vision API - no external dependencies needed
"""

import sys
import time
import json
from pathlib import Path

try:
    from Quartz import CGWindowListCopyWindowInfo, kCGWindowListOptionAll, kCGNullWindowID
    from Quartz import CGWindowListCreateImage, CGRectMake, kCGWindowImageDefault
    from Quartz import CGImageDestinationCreateWithURL, CGImageDestinationAddImage, CGImageDestinationFinalize
    from Foundation import NSURL, NSData
    import Vision
except ImportError as e:
    print(f"Missing dependencies. Install with:")
    print(f"  pip3 install --break-system-packages pyobjc-framework-Vision")
    print(f"Error: {e}")
    sys.exit(1)

# UTI type constant for PNG
kUTTypePNG = 'public.png'

class ChatGPTScreenScraper:
    def __init__(self):
        print("[*] Using macOS Vision framework for OCR")

    def find_chatgpt_window(self):
        """Find ChatGPT window bounds - returns the LARGEST window (main chat)"""
        window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionAll, kCGNullWindowID)

        chatgpt_windows = []
        for window in window_list:
            owner_name = window.get('kCGWindowOwnerName', '')
            if owner_name == 'ChatGPT':
                bounds = window.get('kCGWindowBounds', {})
                chatgpt_windows.append({
                    'x': bounds['X'],
                    'y': bounds['Y'],
                    'width': bounds['Width'],
                    'height': bounds['Height']
                })

        if not chatgpt_windows:
            return None

        # Return the largest window (main chat window)
        largest = max(chatgpt_windows, key=lambda w: w['width'] * w['height'])
        return largest

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
            return None, None

        # Save to temporary file
        temp_path = '/tmp/chatgpt_screenshot.png'
        url = NSURL.fileURLWithPath_(temp_path)
        dest = CGImageDestinationCreateWithURL(url, kUTTypePNG, 1, None)
        CGImageDestinationAddImage(dest, image_ref, None)
        CGImageDestinationFinalize(dest)

        return temp_path, image_ref

    def extract_text_vision(self, image_ref):
        """Extract text using macOS Vision framework"""
        # Create a text recognition request
        request = Vision.VNRecognizeTextRequest.alloc().init()
        request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
        request.setUsesLanguageCorrection_(True)

        # Create request handler
        handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(image_ref, None)

        # Perform the request
        error = handler.performRequests_error_([request], None)

        if error[0] is None and error[1]:
            print(f"[-] Vision error: {error[1]}")
            return None

        # Get results
        results = request.results()
        if not results:
            print("[-] No text detected")
            return None

        # Extract text sorted by vertical position
        observations = []
        for observation in results:
            text = observation.topCandidates_(1)[0].string()
            bbox = observation.boundingBox()
            # bbox.origin.y is from bottom, convert to top-down
            y_pos = 1.0 - bbox.origin.y
            observations.append((y_pos, text))

        # Sort by vertical position (top to bottom)
        observations.sort(key=lambda x: x[0])

        # Join all text
        text_lines = [text for (_, text) in observations]
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
        image_path, image_ref = self.capture_window_region(bounds)

        if not image_path or not image_ref:
            print("[-] Failed to capture screenshot")
            return None

        print(f"[+] Screenshot saved to {image_path}")

        print("[*] Extracting text with Vision framework...")
        text = self.extract_text_vision(image_ref)

        if text:
            print(f"[+] Extracted {len(text)} characters")
        else:
            print("[-] No text extracted")

        return text

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 screen_scraper_vision.py <wait_time>")
        print("Example: python3 screen_scraper_vision.py 3  # Wait 3 seconds before capture")
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
