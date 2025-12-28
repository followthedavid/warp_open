#!/usr/bin/env node
/**
 * PWA Icon Generator
 * Generates all required iOS/PWA icons from the base SVG
 *
 * Run: node scripts/generate-icons.cjs
 *
 * Requirements: sharp (npm install sharp)
 * If sharp isn't available, creates placeholder files with instructions
 */

const fs = require('fs');
const path = require('path');

const ICON_SIZES = [16, 32, 72, 96, 120, 128, 144, 152, 167, 180, 192, 384, 512];
const SPLASH_CONFIGS = [
  { name: 'splash-1170x2532.png', width: 1170, height: 2532 }, // iPhone 12/13/14
  { name: 'splash-1284x2778.png', width: 1284, height: 2778 }, // iPhone 12/13/14 Pro Max
  { name: 'splash-1179x2556.png', width: 1179, height: 2556 }, // iPhone 14 Pro
  { name: 'splash-2048x2732.png', width: 2048, height: 2732 }, // iPad Pro 12.9"
];

const iconsDir = path.join(__dirname, '../public/icons');
const splashDir = path.join(__dirname, '../public/splash');
const svgPath = path.join(iconsDir, 'icon.svg');

async function generateWithSharp() {
  try {
    const sharp = require('sharp');
    const svgBuffer = fs.readFileSync(svgPath);

    console.log('Generating icons with sharp...');

    // Generate icons
    for (const size of ICON_SIZES) {
      const outputPath = path.join(iconsDir, `icon-${size}.png`);
      await sharp(svgBuffer)
        .resize(size, size)
        .png()
        .toFile(outputPath);
      console.log(`  Created: icon-${size}.png`);
    }

    // Generate splash screens (icon centered on dark background)
    console.log('\nGenerating splash screens...');
    for (const config of SPLASH_CONFIGS) {
      const iconSize = Math.min(config.width, config.height) * 0.3;
      const outputPath = path.join(splashDir, config.name);

      // Create dark background with centered icon
      const background = sharp({
        create: {
          width: config.width,
          height: config.height,
          channels: 4,
          background: { r: 26, g: 26, b: 46, alpha: 1 } // #1a1a2e
        }
      });

      const resizedIcon = await sharp(svgBuffer)
        .resize(Math.round(iconSize), Math.round(iconSize))
        .toBuffer();

      await background
        .composite([{
          input: resizedIcon,
          gravity: 'center'
        }])
        .png()
        .toFile(outputPath);

      console.log(`  Created: ${config.name}`);
    }

    console.log('\n✅ All icons and splash screens generated!');
    return true;
  } catch (error) {
    if (error.code === 'MODULE_NOT_FOUND') {
      return false;
    }
    throw error;
  }
}

function createPlaceholders() {
  console.log('Creating placeholder files...');
  console.log('(Install sharp for actual icon generation: npm install sharp)\n');

  // Create simple 1x1 placeholder PNGs (minimal valid PNG)
  const minimalPng = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41, // IDAT chunk
    0x54, 0x08, 0xD7, 0x63, 0x18, 0x05, 0x83, 0x01,
    0x00, 0x00, 0x05, 0x00, 0x01, 0x5A, 0x60, 0x47,
    0x4A, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, // IEND chunk
    0x44, 0xAE, 0x42, 0x60, 0x82
  ]);

  for (const size of ICON_SIZES) {
    const outputPath = path.join(iconsDir, `icon-${size}.png`);
    fs.writeFileSync(outputPath, minimalPng);
    console.log(`  Placeholder: icon-${size}.png`);
  }

  for (const config of SPLASH_CONFIGS) {
    const outputPath = path.join(splashDir, config.name);
    fs.writeFileSync(outputPath, minimalPng);
    console.log(`  Placeholder: ${config.name}`);
  }

  console.log('\n⚠️  Placeholder files created.');
  console.log('For proper icons, either:');
  console.log('  1. Run: npm install sharp && node scripts/generate-icons.cjs');
  console.log('  2. Use an online tool to convert public/icons/icon.svg');
  console.log('  3. Replace placeholders with your own icons');
}

async function main() {
  // Ensure directories exist
  fs.mkdirSync(iconsDir, { recursive: true });
  fs.mkdirSync(splashDir, { recursive: true });

  // Check if SVG exists
  if (!fs.existsSync(svgPath)) {
    console.error('Error: icon.svg not found at', svgPath);
    process.exit(1);
  }

  // Try sharp first, fall back to placeholders
  const sharpWorked = await generateWithSharp();
  if (!sharpWorked) {
    createPlaceholders();
  }
}

main().catch(console.error);
