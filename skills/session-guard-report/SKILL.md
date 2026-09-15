---
name: session-guard-report
description: Generate and open an HTML report of who accessed the local Claude Code / OpenCode / Codex session data, per day, from session-guard's access logs. Use when the user asks "谁在访问 session", "session 访问报告", "who read my sessions", "session access report", "who touched my Claude/Codex/OpenCode data", "/session-guard-report", or wants to review daily session-file access instead of live alerts.
---

# session-guard report

Turns the hourly access aggregates written by the session-guard daemon
(`/var/log/session-guard/access-YYYY-MM-DD.jsonl`, every matched access whether
allow-listed or not) into one self-contained HTML page: accesses per day,
day × hour heatmap, an actor table (executable + code-signing identity +
verdict, expandable to command line, parent, per-location counts) and a
location table. Periods before aggregation existed are backfilled with the
unlisted accesses from `events.jsonl`.

## Steps

1. Pick the range from the request. Default is the last 7 days; "today" →
   `--day $(date +%F)`; an explicit range → `--from`/`--to`.
2. Run the generator that sits next to this file (the skill base directory is
   printed when the skill loads):

   ```sh
   python3 <skill base dir>/report.py --days 7 --open --json
   ```

   `--open` opens the page in the browser; `--json` prints a summary to stdout.
   If `python3` is missing, use `/usr/bin/python3`.
3. From the JSON summary, tell the user in a few lines:
   - the report path and range;
   - total accesses and number of distinct actors;
   - every **unlisted** actor: name (executable basename, or signing id), team
     id if any, count, top locations, command line. These are the ones worth a
     look. Say plainly when there are none.
   - which known (allow-listed) actors were active, one line.
4. If `days_with_data` is empty, the daemon is probably not running or has not
   flushed yet (aggregates are flushed every 10 minutes): suggest
   `tail -3 /var/log/session-guard/guard.log` and `sudo launchctl print system/io.github.iakisme.session-guard | grep state`.
5. If the user wants to stop seeing an actor as unlisted, explain: add an
   `allow` rule to their local `session-guard.json` in the session-guard
   checkout (prefer `team_id` / `signing_id`; pin interpreters with `cwd`) and
   run `sudo ./install.sh --replace-config` there. Do not edit files under
   `/usr/local` or `/var/log` directly.

## Notes

- The report is per-viewer local HTML; nothing leaves the machine.
- Reports land in `~/Library/Logs/session-guard/reports/` unless `--out` is given.
- Times in the page are local time; the daemon aggregates in local time too.
