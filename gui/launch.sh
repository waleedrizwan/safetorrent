#!/bin/bash
# Start the safetorrent GUI server (if it isn't running) and open it in an app window.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
PORT=${SAFETORRENT_PORT:-8765}
TOKEN_FILE="$HOME/.config/safetorrent/gui-token"
LOG="$HOME/Library/Logs/safetorrent-gui.log"

if ! curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1; then
  mkdir -p "$(dirname "$LOG")"
  nohup /usr/bin/python3 "$ROOT/gui/server.py" >>"$LOG" 2>&1 &
  for _ in $(seq 1 50); do
    curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1 && break
    sleep 0.2
  done
fi

URL="http://127.0.0.1:$PORT/#t=$(cat "$TOKEN_FILE")"
# A Chromium browser can show it as a standalone app window; otherwise use the default browser.
for app in "Google Chrome" "Brave Browser" "Microsoft Edge"; do
  if [[ -d "/Applications/$app.app" ]]; then
    exec open -na "$app" --args --app="$URL" --window-size=1280,860
  fi
done
exec open "$URL"
