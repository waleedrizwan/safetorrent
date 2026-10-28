#!/bin/bash
# Start the safetorrent GUI server (if it isn't running) and open it in an app window.
set -euo pipefail
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
ROOT=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd)
PORT=${SAFETORRENT_PORT:-8765}
TOKEN_FILE="$HOME/.config/safetorrent/gui-token"
LOG="$HOME/Library/Logs/safetorrent-gui.log"

start_server() {
  mkdir -p "$(dirname "$LOG")"
  nohup /usr/bin/python3 "$ROOT/gui/server.py" >>"$LOG" 2>&1 &
  for _ in $(seq 1 50); do
    curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
}

# POST to the API with the token. The token never goes on a command line (any local
# user can read those with ps): the header reaches curl on stdin.
api() {
  printf 'X-Safetorrent-Token: %s\n' "$(<"$TOKEN_FILE")" \
    | curl -fsS -m 5 -X POST -H @- -H 'Content-Type: application/json' --data "$2" "http://127.0.0.1:$PORT$1"
}

# The page gets a one-time code to trade for the token, not the token itself.
launch_code() {
  api /api/launch-code '{}' | /usr/bin/python3 -c 'import json, sys; print(json.load(sys.stdin)["code"])'
}

curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1 || start_server
if ! CODE=$(launch_code 2>/dev/null); then
  # Probably a server from before launch codes, still running: replace it (the VM keeps running).
  api /api/quit '{"stop_vm": false}' >/dev/null 2>&1 || true
  for _ in $(seq 1 25); do
    curl -fsS -m 1 "http://127.0.0.1:$PORT/ping" >/dev/null 2>&1 || break
    sleep 0.2
  done
  start_server
  CODE=$(launch_code) || { echo "SafeTorrent's server didn't start; see $LOG" >&2; exit 1; }
fi
URL="http://127.0.0.1:$PORT/#c=$CODE"
# A Chromium browser can show it as a standalone app window; otherwise use the default browser.
for app in "Google Chrome" "Brave Browser" "Microsoft Edge"; do
  if [[ -d "/Applications/$app.app" ]]; then
    exec open -na "$app" --args --app="$URL" --window-size=1280,860
  fi
done
exec open "$URL"
