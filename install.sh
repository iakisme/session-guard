#!/bin/zsh
# Install or update session-guard as a root LaunchDaemon.
#
#   sudo ./install.sh                   first install, or update code + plist (config kept)
#   sudo ./install.sh --replace-config  also overwrite the installed config from the local
#                                       session-guard.json (or the example), re-baking the user
#
# Everything root executes is copied to root-owned paths so a user-level
# process cannot edit the daemon's code.
set -euo pipefail

REPLACE_CONFIG=0
for arg in "$@"; do
  case "$arg" in
    --replace-config) REPLACE_CONFIG=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 64 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "run as root: sudo $0 $*" >&2
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

# The FDA grant is tied to the launcher's cdhash: warn when it changes.
launcher_changed=0
if [[ -e "$LIB/session-guard-launcher" ]] && ! cmp -s "$LIB/session-guard-launcher" "$SRC/session-guard-launcher"; then
  launcher_changed=1
fi
first_install=$([[ -e "$LIB/session-guard-launcher" ]] && echo 0 || echo 1)

install -d -o root -g wheel -m 755 "$LIB" "$LOG" "$ETC"
install -o root -g wheel -m 755 "$SRC/session-guard-launcher" "$LIB/session-guard-launcher"
install -o root -g wheel -m 644 "$SRC/session_guard.py" "$LIB/session_guard.py"

template="$SRC/session-guard.json"
[[ -e "$template" ]] || template="$SRC/session-guard.example.json"

bake_config() {
  /usr/bin/python3 - "$1" "$2" "$SUDO_USER" <<'PY'
import json, pwd, sys
src, dst, user = sys.argv[1:4]
cfg = json.load(open(src))
pw = pwd.getpwnam(user)
cfg.setdefault("notify", {})
cfg["notify"]["user"] = user
cfg["notify"]["uid"] = pw.pw_uid
cfg["home"] = pw.pw_dir
json.dump(cfg, open(dst, "w"), indent=2)
print("wrote %s from %s for user %s (home %s)" % (dst, src, user, pw.pw_dir))
PY
  chmod 644 "$2"
}

if [[ ! -e "$ETC/session-guard.json" ]]; then
  bake_config "$template" "$ETC/session-guard.json"
elif [[ $REPLACE_CONFIG -eq 1 ]]; then
  cp "$ETC/session-guard.json" "$ETC/session-guard.json.bak"
  bake_config "$template" "$ETC/session-guard.json"
  echo "previous config saved as $ETC/session-guard.json.bak"
else
  echo "keeping existing $ETC/session-guard.json"
  # Point out drift between the installed config and the local template.
  /usr/bin/python3 - "$template" "$ETC/session-guard.json" <<'PY' || true
import json, sys
local, installed = (json.load(open(p)) for p in sys.argv[1:3])
drift = []
for key in ("watch", "exclude"):
    missing = sorted(set(local.get(key, [])) - set(installed.get(key, [])))
    if missing:
        drift.append("%s missing in installed: %s" % (key, ", ".join(missing)))
names = {r.get("name") for r in installed.get("allow", [])}
missing = [r.get("name") for r in local.get("allow", []) if r.get("name") not in names]
if missing:
    drift.append("allow rules missing in installed: %s" % ", ".join(missing))
if drift:
    print("NOTE: installed config differs from %s:" % sys.argv[1])
    for d in drift:
        print("  - " + d)
    print("  re-run with --replace-config to deploy the local config")
PY
fi

install -o root -g wheel -m 644 "$SRC/$LABEL.plist" "/Library/LaunchDaemons/$LABEL.plist"

/usr/bin/python3 "$LIB/session_guard.py" --config "$ETC/session-guard.json" --check-config >/dev/null

launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "/Library/LaunchDaemons/$LABEL.plist"

echo
echo "Installed and (re)started $LABEL."
if [[ $first_install -eq 1 || $launcher_changed -eq 1 ]]; then
  cat <<EOF

ONE MANUAL STEP: grant Full Disk Access to the launcher, otherwise eslogger
exits immediately ("not permitted") and launchd restarts it every 30 s.
$([[ $launcher_changed -eq 1 ]] && echo "(The launcher binary changed, so its cdhash changed: remove the old entry and add it again.)")

  System Settings -> Privacy & Security -> Full Disk Access -> [+]
  press Cmd+Shift+G and enter:  $LIB/session-guard-launcher

Then:   sudo launchctl kickstart -k system/$LABEL
EOF
  open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles" 2>/dev/null || true
else
  echo "Launcher unchanged: the existing Full Disk Access grant still applies."
fi
cat <<EOF
Check:  tail -f $LOG/guard.log      (expect a 'session-guard start' line and a heartbeat every 5 min)
        tail -f $LOG/daemon.err     (eslogger / launcher errors land here)
Test:   cat ~/.codex/auth.json > /dev/null   -> macOS notification within ~1 s
Remove: sudo launchctl bootout system/$LABEL && sudo rm -r $LIB /Library/LaunchDaemons/$LABEL.plist
EOF
