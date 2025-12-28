#!/bin/bash
# Generate PWA icons from SVG source
# Requires: ImageMagick (brew install imagemagick)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ICONS_DIR="$PROJECT_ROOT/public/icons"
SPLASH_DIR="$PROJECT_ROOT/public/splash"

# Create SVG source if it doesn't exist
if [ ! -f "$ICONS_DIR/icon.svg" ]; then
  cat > "$ICONS_DIR/icon.svg" << 'EOF'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
  <defs>
    <linearGradient id="grad" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#0a84ff"/>
      <stop offset="100%" style="stop-color:#5856d6"/>
    </linearGradient>
  </defs>
  <rect width="512" height="512" rx="100" fill="#000"/>
  <rect x="20" y="20" width="472" height="472" rx="80" fill="url(#grad)" opacity="0.15"/>
  <path d="M128 160 L256 288 L128 416" stroke="#0a84ff" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <line x1="280" y1="416" x2="384" y2="416" stroke="#0a84ff" stroke-width="40" stroke-linecap="round"/>
</svg>
EOF
  echo "Created source icon.svg"
fi

# Generate PNG icons
echo "Generating PNG icons..."

SIZES=(16 32 72 96 128 144 152 167 180 192 384 512)
for size in "${SIZES[@]}"; do
  convert -background none -resize "${size}x${size}" "$ICONS_DIR/icon.svg" "$ICONS_DIR/icon-${size}.png"
  echo "  icon-${size}.png"
done

# Generate badge icon (monochrome for notifications)
convert -background none -resize 72x72 "$ICONS_DIR/icon.svg" \
  -colorspace Gray -modulate 100,0 "$ICONS_DIR/badge-72.png"
echo "  badge-72.png"

# Generate splash screens
echo "Generating splash screens..."

generate_splash() {
  local width=$1
  local height=$2
  local output="$SPLASH_DIR/splash-${width}x${height}.png"

  convert -size "${width}x${height}" xc:black \
    \( "$ICONS_DIR/icon.svg" -background none -resize 200x200 \) \
    -gravity center -composite "$output"
  echo "  splash-${width}x${height}.png"
}

# iPhone splash screens
generate_splash 1170 2532  # iPhone 12/13/14 Pro
generate_splash 1284 2778  # iPhone 12/13/14 Pro Max
generate_splash 1179 2556  # iPhone 14 Pro
generate_splash 1290 2796  # iPhone 14 Pro Max

# iPad splash screens
generate_splash 2048 2732  # iPad Pro 12.9"
generate_splash 1668 2388  # iPad Pro 11"
generate_splash 1620 2160  # iPad 10.2"

echo ""
echo "Icon generation complete!"
echo "Icons saved to: $ICONS_DIR"
echo "Splash screens saved to: $SPLASH_DIR"
