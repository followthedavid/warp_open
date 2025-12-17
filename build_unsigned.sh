#!/bin/bash
#
# Build Unsigned macOS DMG
#
# Creates an unsigned DMG for testing/beta distribution.
# Users will need to bypass Gatekeeper to run it.
#
# Usage: ./build_unsigned.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Warp_Open Unsigned Build ==="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Step 1: Clean previous builds
echo -e "${BLUE}[1/4]${NC} Cleaning previous builds..."
rm -rf src-tauri/target/release/bundle 2>/dev/null || true

# Step 2: Build frontend
echo -e "${BLUE}[2/4]${NC} Building frontend..."
npm run build

# Step 3: Build Tauri app (release mode)
echo -e "${BLUE}[3/4]${NC} Building Tauri application..."
cd src-tauri
cargo build --release
cd ..

# Step 4: Create DMG bundle
echo -e "${BLUE}[4/4]${NC} Creating DMG bundle..."
npm run tauri build -- --target universal-apple-darwin 2>/dev/null || npm run tauri build

# Find the output
DMG_PATH=$(find src-tauri/target -name "*.dmg" -type f 2>/dev/null | head -1)

if [ -n "$DMG_PATH" ]; then
    echo ""
    echo -e "${GREEN}=== Build Complete ===${NC}"
    echo ""
    echo "DMG Location: $DMG_PATH"
    echo "Size: $(du -h "$DMG_PATH" | cut -f1)"
    echo ""
    echo -e "${YELLOW}IMPORTANT: This is an unsigned build.${NC}"
    echo ""
    echo "To install on macOS:"
    echo "  1. Download the DMG"
    echo "  2. Open the DMG and drag Warp_Open to Applications"
    echo "  3. On first launch, macOS will block the app"
    echo "  4. Go to System Preferences → Security & Privacy"
    echo "  5. Click 'Open Anyway' next to the Warp_Open message"
    echo ""
    echo "Alternative: Right-click the app → Open → Open"
    echo ""

    # Copy to a more accessible location
    cp "$DMG_PATH" "./Warp_Open-unsigned.dmg"
    echo "Copied to: ./Warp_Open-unsigned.dmg"
else
    echo -e "${YELLOW}Warning: DMG not found. Checking for .app bundle...${NC}"
    APP_PATH=$(find src-tauri/target -name "*.app" -type d 2>/dev/null | head -1)
    if [ -n "$APP_PATH" ]; then
        echo "App bundle found: $APP_PATH"
        echo ""
        echo "To create DMG manually:"
        echo "  hdiutil create -volname 'Warp_Open' -srcfolder '$APP_PATH' -ov -format UDZO Warp_Open-unsigned.dmg"
    fi
fi
