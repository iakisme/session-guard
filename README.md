# session-guard

Get a macOS notification the moment **any process reads, copies, renames or
deletes** the local session data of your AI coding agents: Claude Code, OpenCode
and Codex. Those directories hold full conversation transcripts, tool output,
pasted secrets and, for Codex, the OAuth token. Any process running as your
user can read them silently. This tool makes it not silent.

```
┌ Claude Code session accessed ───────────────────────────────┐
│ cat[51234] open read                                        │
│ via zsh <- iTerm2  |  /Users/you/.claude/projects/…/x.jsonl │
└─────────────────────────────────────────────────────────────┘
```

## How it works

Reads leave no trace in the file system, so FSEvents / `fswatch` / launchd
`WatchPaths` cannot see them (they only report writes). The only supported way
on macOS to observe `open(2)` system-wide with process attribution is the
**Endpoint Security** framework. Apple ships a command-line client for it,
`/usr/bin/eslogger` (macOS 13+), which prints one JSON line per event with the
file path, the process executable, its code-signing identity and team ID,
pid / ppid / responsible pid and TTY.

```
/usr/bin/eslogger open clone copyfile rename unlink  |  session_guard.py
```

`session_guard.py` keeps events under the watched paths, drops known-good
readers (the three CLIs themselves, Spotlight, your EDR) and raises everything
else: macOS notification, `events.jsonl`, syslog, optional webhook command.

Subscribed events: `open` (read/write), `clone` and `copyfile` (on APFS `cp`
uses `clonefile(2)` and never `open`s the source), `rename` (moving data out),
`unlink` (destroying evidence).

## What is watched (default config)

| Tool | Paths |
|------|-------|
| Claude Code | `~/.claude/projects/` (transcripts), `transcripts/`, `sessions/`, `history.jsonl`, `file-history/`, `paste-cache/`, `session-env/`, `debug/`, `plans/`, `daemon/`, `~/.claude.json` |
| OpenCode | `~/.local/share/opencode/` (SQLite db, `storage/`, `snapshot/`, `tool-output/`) minus `bin/`, `log/` |
| Codex | `~/.codex/` (`sessions/`, `history.jsonl`, `auth.json`, sqlite stores) minus `cache/`, `log/`, `plugins/` |

`~/.claude/shell-snapshots/` is deliberately **not** watched: Claude Code's Bash
tool sources it through `/bin/zsh` on every command, which would alert constantly.

## Allow list

| Actor | Pinned by |
|-------|-----------|
| Claude Code | `com.anthropic.claude-code`, team `Q6L2SF6YDW` |
| Codex native binary | signing id `codex`, team `2DC432GLL2` |
| OpenCode | path `~/.opencode/bin/opencode` (ad-hoc signed, no team to pin) |
| Spotlight | `com.apple.mds`, `com.apple.mds_stores`, `com.apple.mdworker_shared` |

Deliberately **not** allowed: anything spawned *by* the CLIs. A `cat
~/.codex/auth.json` executed through Claude Code's Bash tool (say, after a
prompt injection) alerts, with the parent chain in the notification. Your own
scripts that scan the session dirs will alert too. That is the point; allow them
explicitly if you want.

Your EDR / antivirus / backup agent will show up in the learn run. Add it by
`team_id`, found with `codesign -dv /path/to/agent 2>&1 | grep TeamIdentifier`.

## Quick start (no install)

Requires a terminal app with **Full Disk Access** (System Settings → Privacy &
Security → Full Disk Access; Terminal.app and iTerm2 are common choices).

```sh
git clone https://github.com/iakisme/session-guard.git && cd session-guard
cp session-guard.example.json session-guard.json   # optional; git-ignored
./run.sh --learn 300      # 5 min census: who touches these paths on your Mac?
./run.sh                  # then guard for real; in another tab:
cat ~/.codex/auth.json > /dev/null                 # -> notification within ~1 s
```

Add legitimate `ALERT` rows from the learn table to `allow` in your
`session-guard.json` (prefer `team_id` / `signing_id` over paths).

## Persistent (LaunchDaemon)

```sh
cc -O2 -Wall -o session-guard-launcher session-guard-launcher.c
codesign -s - -i io.github.iakisme.session-guard -f session-guard-launcher
sudo ./install.sh
```

Then grant **Full Disk Access** to `/usr/local/lib/session-guard/session-guard-launcher`
(System Settings opens automatically: `+`, Cmd+Shift+G, paste the path).

Why a launcher: Endpoint Security requires the *responsible process* to hold
FDA, and for a LaunchDaemon that is the job's own executable. Granting FDA to
`/bin/sh` or `/usr/bin/python3` would hand it to every launchd job using those
interpreters; the 60-line launcher scopes it to exactly one daemon. It is
ad-hoc signed, so **rebuilding it changes its cdhash and the FDA grant must be
re-added**.

Files: code `/usr/local/lib/session-guard/` (root-owned), config
`/usr/local/etc/session-guard.json` (with your user baked in), logs
`/var/log/session-guard/` (`guard.log`, `events.jsonl`, `daemon.err`). A
heartbeat line every 5 minutes in `guard.log` proves the feed is alive; a
start-up notification proves the notification channel works.

## Alert channels

1. macOS notification (from the daemon via `launchctl asuser <uid> sudo -u <user> osascript`).
2. `events.jsonl`: one JSON object per event with every field (exe, signing id,
   team id, pid/ppid/responsible pid, tty, command lines).
3. syslog: `log stream --predicate 'eventMessage contains "session-guard"'`.
4. `notify.command`: any shell command; receives the alert JSON on stdin
   (webhook, chat bot, pager).

Notifications are rate-limited to one per (pid, executable) per
`cooldown_seconds` (default 60); the next one carries the suppressed count.
Every event is still logged.

## Limits

* Same-UID processes can always *read* your files; this detects, it does not
  prevent.
* A process already holding a file descriptor or a memory map does not re-`open`.
* Root can stop the daemon. Logs are root-owned, but this is not tamper-proof.
* `eslogger` is explicitly not API; Apple may change the JSON. `--dump 3`
  prints raw events if field names drift.
* Allow rules keyed on a bare path (OpenCode) can be impersonated by placing a
  binary at that path.

## Requirements

macOS 13 or later (`/usr/bin/eslogger`), the Apple-shipped `/usr/bin/python3`
(Command Line Tools), `cc` for the launcher. No third-party dependencies.
