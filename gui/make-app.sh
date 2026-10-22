#!/bin/bash
# Build ~/Applications/SafeTorrent.app, a double-clickable launcher for the GUI.
set -euo pipefail
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
APP="$HOME/Applications/SafeTorrent.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cat > "$APP/Contents/MacOS/SafeTorrent" <<SH
#!/bin/bash
exec "$ROOT/gui/launch.sh"
SH
chmod +x "$APP/Contents/MacOS/SafeTorrent"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>SafeTorrent</string>
  <key>CFBundleDisplayName</key><string>SafeTorrent</string>
  <key>CFBundleIdentifier</key><string>local.safetorrent.launcher</string>
  <key>CFBundleExecutable</key><string>SafeTorrent</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSUIElement</key><true/>
</dict></plist>
PLIST
if [[ -f "$ROOT/gui/AppIcon.icns" ]]; then cp "$ROOT/gui/AppIcon.icns" "$APP/Contents/Resources/"; fi
touch "$APP"
echo "Built $APP"
