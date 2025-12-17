# Warp_Open Release Guide

This document covers building, signing, and distributing Warp_Open.

## Quick Start (Unsigned Build)

For testing and beta distribution without Apple Developer credentials:

```bash
./build_unsigned.sh
```

This creates `Warp_Open-unsigned.dmg` that users can install after bypassing Gatekeeper.

### Installing Unsigned Builds

Users installing unsigned builds will see "app cannot be opened because it is from an unidentified developer". To bypass:

**Option 1: System Preferences**
1. Open the DMG and drag Warp_Open to Applications
2. Try to open the app (it will be blocked)
3. Go to **System Preferences → Security & Privacy → General**
4. Click **"Open Anyway"** next to the Warp_Open message
5. Click **Open** in the confirmation dialog

**Option 2: Right-Click**
1. Right-click (or Control+click) on Warp_Open.app
2. Select **Open** from the context menu
3. Click **Open** in the dialog

**Option 3: Terminal (removes quarantine)**
```bash
xattr -cr /Applications/Warp_Open.app
```

---

## Signed Release Build

For official distribution through the App Store or direct download.

### Prerequisites

1. **Apple Developer Account** ($99/year)
   - Enroll at [developer.apple.com](https://developer.apple.com)

2. **Certificates** (create in Apple Developer Portal)
   - Developer ID Application certificate
   - Developer ID Installer certificate (for PKG)

3. **App-Specific Password** (for notarization)
   - Create at [appleid.apple.com](https://appleid.apple.com) → Security → App-Specific Passwords

### Environment Setup

```bash
# Export credentials (add to ~/.zshrc or ~/.bashrc)
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAM_ID)"
export APPLE_CERTIFICATE_PASSWORD="your-cert-password"
export APPLE_ID="your-apple-id@email.com"
export APPLE_PASSWORD="your-app-specific-password"
export APPLE_TEAM_ID="YOUR_TEAM_ID"
```

### Build Signed DMG

```bash
# Build with signing
npm run tauri build -- \
  --target universal-apple-darwin \
  -- -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
```

### Manual Code Signing

If automatic signing fails:

```bash
# Sign the app
codesign --force --options runtime --deep \
  --sign "$APPLE_SIGNING_IDENTITY" \
  --entitlements entitlements.plist \
  src-tauri/target/release/bundle/macos/Warp_Open.app

# Verify signature
codesign --verify --deep --strict --verbose=2 \
  src-tauri/target/release/bundle/macos/Warp_Open.app
```

### Notarization

Apple requires notarization for apps distributed outside the App Store:

```bash
# Create ZIP for notarization
ditto -c -k --keepParent \
  src-tauri/target/release/bundle/macos/Warp_Open.app \
  Warp_Open.zip

# Submit for notarization
xcrun notarytool submit Warp_Open.zip \
  --apple-id "$APPLE_ID" \
  --password "$APPLE_PASSWORD" \
  --team-id "$APPLE_TEAM_ID" \
  --wait

# Staple the notarization ticket
xcrun stapler staple src-tauri/target/release/bundle/macos/Warp_Open.app
```

### Create Final DMG

```bash
# Create DMG with the notarized app
hdiutil create -volname "Warp_Open" \
  -srcfolder src-tauri/target/release/bundle/macos/Warp_Open.app \
  -ov -format UDZO \
  Warp_Open-v0.1.0.dmg

# Sign the DMG itself
codesign --sign "$APPLE_SIGNING_IDENTITY" Warp_Open-v0.1.0.dmg
```

---

## Tauri Configuration for Signing

Update `src-tauri/tauri.conf.json`:

```json
{
  "tauri": {
    "bundle": {
      "active": true,
      "targets": ["dmg", "app"],
      "identifier": "com.warp.open",
      "icon": ["icons/icon.icns"],
      "macOS": {
        "entitlements": "entitlements.plist",
        "signingIdentity": "-",
        "minimumSystemVersion": "10.15"
      }
    }
  }
}
```

### Entitlements File

Create `src-tauri/entitlements.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
    <key>com.apple.security.automation.apple-events</key>
    <true/>
</dict>
</plist>
```

---

## CI/CD Pipeline (GitHub Actions)

For automated releases, create `.github/workflows/release.yml`:

```yaml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Setup Rust
        uses: dtolnay/rust-toolchain@stable

      - name: Install dependencies
        run: npm ci

      - name: Import certificates
        env:
          APPLE_CERTIFICATE: ${{ secrets.APPLE_CERTIFICATE }}
          APPLE_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
        run: |
          echo $APPLE_CERTIFICATE | base64 --decode > certificate.p12
          security create-keychain -p actions temp.keychain
          security import certificate.p12 -k temp.keychain -P $APPLE_CERTIFICATE_PASSWORD -T /usr/bin/codesign
          security list-keychains -s temp.keychain
          security set-keychain-settings temp.keychain
          security unlock-keychain -p actions temp.keychain

      - name: Build and sign
        env:
          APPLE_SIGNING_IDENTITY: ${{ secrets.APPLE_SIGNING_IDENTITY }}
          APPLE_ID: ${{ secrets.APPLE_ID }}
          APPLE_PASSWORD: ${{ secrets.APPLE_PASSWORD }}
          APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
        run: npm run tauri build

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: Warp_Open-macos
          path: src-tauri/target/release/bundle/dmg/*.dmg
```

---

## Version Bumping

Before release, update versions in:

1. `package.json` - `version` field
2. `src-tauri/Cargo.toml` - `version` field
3. `src-tauri/tauri.conf.json` - `package.version` field

```bash
# Bump all versions (example: 0.1.0 → 0.2.0)
npm version minor
cd src-tauri && cargo bump minor
```

---

## Release Checklist

- [ ] Update version numbers
- [ ] Update CHANGELOG.md
- [ ] Run full test suite
- [ ] Build unsigned for testing
- [ ] Test on clean macOS install
- [ ] Build signed release
- [ ] Notarize with Apple
- [ ] Create GitHub release
- [ ] Upload DMG to release
- [ ] Update documentation

---

## Troubleshooting

### "App is damaged and can't be opened"
```bash
xattr -cr /Applications/Warp_Open.app
```

### Notarization fails with "invalid signature"
Ensure you're using the hardened runtime:
```bash
codesign --force --options runtime --deep --sign "Developer ID Application: ..."
```

### "The signature of the binary is invalid"
The app may have been modified after signing. Rebuild and re-sign.

### Gatekeeper still blocks after notarization
Make sure to staple the ticket:
```bash
xcrun stapler staple Warp_Open.app
```
