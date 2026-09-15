#!/bin/zsh
# Install session-guard as a root LaunchDaemon.   Usage: sudo ./install.sh
# Everything root executes is copied to root-owned paths so a user-level
# process cannot edit the daemon's code.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "run as root: sudo $0" >&2
  exit 1
fi
if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" ]]; then
  echo "run via sudo from the user account whose sessions should be guarded" >&2
  exit 1
fi

SRC=${0:A:h}
LIB=/usr/local/lib/session-guard
ETC=/usr/local/etc
LOG=/var/log/session-guard
LABEL=io.github.iakisme.session-guard

if [[ ! -x "$SRC/session-guard-launcher" ]]; then
  echo "building launcher..."
  cc -O2 -Wall -o "$SRC/session-guard-launcher" "$SRC/session-guard-launcher.c"
  codesign -s - -i "$LABEL" -f "$SRC/session-guard-launcher"
  chown "$SUDO_USER" "$SRC/session-guard-launcher"
fi

install -d -o root -g wheel -m 755 "$LIB" "$LOG" "$ETC"
install -o root -g wheel -m 755 "$SRC/session-guard-launcher" "$LIB/session-guard-launcher"
install -o root -g wheel -m 644 "$SRC/session_guard.py" "$LIB/session_guard.py"

if [[ -e "$ETC/session-guard.json" ]]; then
  echo "keeping existing $ETC/session-guard.json"
else
  # Prefer a local, already-tuned session-guard.json; otherwise start from the
  # example. Either way bake in the guarded user so the daemon (which has no
  # SUDO_USER) knows whose home to watch and whom to notify.
  template="$SRC/session-guard.json"
  [[ -e "$template" ]] || template="$SRC/session-guard.example.json"
  /usr/bin/python3 - "$template" "$ETC/session-guard.json" "$SUDO_USER" <<'PY'
import json, pwd, sys
src, dst, user = sys.argv[1:4]
cfg = json.load(open(src))
pw = pwd.getpwnam(user)
cfg.setdefault("notify", {})
cfg["notify"]["user"] = user
cfg["notify"]["uid"] = pw.pw_uid
cfg["home"] = pw.pw_dir
json.dump(cfg, open(dst, "w"), indent=2)
print("wrote %s for user %s (home %s)" % (dst, user, pw.pw_dir))
PY
  chmod 644 "$ETC/session-guard.json"
fi
install -o root -g wheel -m 644 "$SRC/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"

/usr/bin/python3 "$LIB/session_guard.py" --config "$ETC/session-guard.json" --check-config >/dev/null

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"

cat <<EOF

Installed and loaded $LABEL.

ONE MANUAL STEP: grant Full Disk Access to the launcher, otherwise eslogger
exits immediately ("not permitted") and launchd restarts it every 30 s.

  System Settings -> Privacy & Security -> Full Disk Access -> [+]
  press Cmd+Shift+G and enter:  $LIB/session-guard-launcher

Then:   sudo launchctl kickstart -k system/$LABEL
Check:  tail -f $LOG/guard.log      (expect a 'session-guard start' line and a heartbeat every 5 min)
        tail -f $LOG/daemon.err     (eslogger / launcher errors land here)
Test:   cat ~/.codex/auth.json > /dev/null   -> macOS notification within ~1 s
Remove: sudo launchctl bootout system/$LABEL && sudo rm -r $LIB /Library/LaunchDaemons/$LABEL.plist
EOF

open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
