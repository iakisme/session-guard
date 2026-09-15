#!/bin/zsh
# Run session-guard in the foreground from a terminal app that has Full Disk
# Access (Terminal.app / iTerm2 with FDA granted). No install, no LaunchDaemon;
# it dies with the terminal. Good for the first test and for the learn run.
#
#   ./run.sh              # guard mode: log + notify
#   ./run.sh --learn 300  # 5-minute census of who touches the session dirs, no alerts
#   ./run.sh --dump 3     # print 3 raw eslogger events for the paths (schema debugging)
#
# Uses session-guard.json if you created one, else session-guard.example.json.
# The guarded user is taken from SUDO_USER.
set -euo pipefail
SRC=${0:A:h}
CFG="$SRC/session-guard.json"
[[ -e "$CFG" ]] || CFG="$SRC/session-guard.example.json"
exec sudo /bin/sh -c "/usr/bin/eslogger open clone copyfile rename unlink \
  | /usr/bin/python3 '$SRC/session_guard.py' --config '$CFG' $*"
