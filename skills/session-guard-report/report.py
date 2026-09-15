#!/usr/bin/env python3
"""session-guard report: who accessed your AI-agent session data, per day.

Reads the hourly access aggregates the session-guard daemon writes to
<log_dir>/access-YYYY-MM-DD.jsonl (every matched event, allowed or not) and,
for periods before aggregation existed, backfills unlisted accesses from
<log_dir>/events.jsonl. Produces one self-contained HTML file (no network,
inline SVG charts, light/dark aware) and optionally opens it.

    report.py --days 7 --open
    report.py --day 2026-09-15 --json      # machine-readable summary on stdout
"""
import argparse
import collections
import datetime as dt
import glob
import html
import json
import os
import subprocess
import sys
import time

DEFAULT_LOG_DIR = "/var/log/session-guard"
DEFAULT_OUT_DIR = os.path.expanduser("~/Library/Logs/session-guard/reports")


def local_day_hour(epoch):
    t = time.localtime(epoch)
    return time.strftime("%Y-%m-%d", t), t.tm_hour


def parse_utc_iso(s):
    """eslogger time: 2026-09-15T09:33:48.818357211Z -> epoch."""
    try:
        d = dt.datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
        return d.timestamp()
    except Exception:
        return None


def day_range(args):
    today = dt.date.today()
    if args.day:
        d = dt.date.fromisoformat(args.day)
        return [d.isoformat()]
    end = dt.date.fromisoformat(args.to) if args.to else today
    start = dt.date.fromisoformat(getattr(args, "from")) if getattr(args, "from") else end - dt.timedelta(days=args.days - 1)
    return [(start + dt.timedelta(days=i)).isoformat() for i in range((end - start).days + 1)]


class Rows:
    """day-level rows keyed by (day, exe, sid, tid, verdict, bucket, kind, mode)."""

    def __init__(self):
        self.rows = {}

    def add(self, day, hour, exe, sid, tid, verdict, tool, bucket, kind, mode, n, pids, first, last, sample, cmd, parent):
        key = (day, exe, sid or "", tid or "", verdict, bucket, kind, mode or "")
        r = self.rows.get(key)
        if r is None:
            r = self.rows[key] = {"d": day, "exe": exe, "sid": sid, "tid": tid, "v": verdict, "tool": tool, "b": bucket,
                                  "k": kind, "m": mode, "n": 0, "h": [0] * 24, "pids": set(), "first": first, "last": last,
                                  "sample": sample, "cmd": cmd, "parent": parent}
        r["n"] += n
        r["h"][hour] += n
        r["pids"].update(p for p in pids if p is not None)
        r["first"] = min(r["first"], first)
        r["last"] = max(r["last"], last)
        if not r["cmd"] and cmd:
            r["cmd"] = cmd
        if not r["parent"] and parent:
            r["parent"] = parent

    def export(self):
        out = []
        for r in self.rows.values():
            e = dict(r)
            e["pids"] = sorted(e["pids"])[:50]
            e["first"] = round(e["first"], 0)
            e["last"] = round(e["last"], 0)
            out.append(e)
        out.sort(key=lambda r: (r["d"], -r["n"]))
        return out


def load_access(log_dir, days, rows):
    """Returns per-day earliest aggregate timestamp (for the backfill cut-off)."""
    access_first = {}
    for day in days:
        p = os.path.join(log_dir, "access-%s.jsonl" % day)
        if not os.path.exists(p):
            continue
        with open(p) as fh:
            for line in fh:
                try:
                    a = json.loads(line)
                except ValueError:
                    continue
                hour = int(a["hour"][11:13])
                rows.add(day, hour, a["exe"], a.get("sid"), a.get("tid"), a.get("verdict", "ALERT"), a.get("tool", "?"),
                         a.get("bucket", "?"), a.get("kind", "?"), a.get("mode"), int(a.get("n", 1)), a.get("pids", []),
                         float(a.get("first", 0) or 0), float(a.get("last", 0) or 0), a.get("sample"), a.get("cmd"), a.get("parent"))
                f = float(a.get("first", 0) or 0)
                if f:
                    access_first[day] = min(access_first.get(day, f), f)
    return access_first


def tilde(p, home):
    return "~" + p[len(home):] if p and (p == home or p.startswith(home + "/")) else p


def bucket_of(path, home):
    """Mirror of the daemon's bucket rule for backfilled raw events."""
    rel = tilde(path, home)
    parts = rel.split("/")
    if rel.startswith("~/.claude/projects/"):
        return "/".join(parts[:4])
    if rel.startswith("~/.claude/"):
        return "/".join(parts[:3])
    if rel.startswith("~/.codex/"):
        return "/".join(parts[:3])
    if rel.startswith("~/.local/share/opencode/"):
        return "/".join(parts[:5])
    return rel


def tool_of(path):
    if "/.claude" in path:
        return "Claude Code"
    if "/opencode" in path:
        return "OpenCode"
    if "/.codex" in path:
        return "Codex"
    return "session"


def backfill_events(log_dir, days, rows, access_first, home):
    """Unlisted (alerted) events from events.jsonl for time before aggregation
    started on that day. Allowed actors are not in events.jsonl, so backfilled
    periods only show unlisted accesses."""
    p = os.path.join(log_dir, "events.jsonl")
    if not os.path.exists(p):
        return 0
    dayset = set(days)
    n = 0
    with open(p) as fh:
        for line in fh:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            ts = parse_utc_iso(e.get("ts", ""))
            if ts is None:
                continue
            day, hour = local_day_hour(ts)
            if day not in dayset:
                continue
            if day in access_first and ts >= access_first[day]:
                continue
            path = (e.get("paths") or ["?"])[0]
            rows.add(day, hour, e.get("exe", "?"), e.get("signing_id"), e.get("team_id"), "ALERT", e.get("tool") or tool_of(path),
                     bucket_of(path, home), e.get("event", "?"), e.get("mode"), 1, [e.get("pid")], ts, ts,
                     tilde(path, home), e.get("cmd"), e.get("parent_cmd"))
            n += 1
    return n


def summary(rows, days):
    actors = collections.OrderedDict()
    for r in rows:
        key = (r["exe"], r["sid"] or "", r["tid"] or "", r["v"])
        a = actors.setdefault(key, {"exe": r["exe"], "signing_id": r["sid"], "team_id": r["tid"], "verdict": r["v"],
                                    "n": 0, "days": set(), "buckets": collections.Counter(), "cmd": r["cmd"],
                                    "parent": r["parent"], "sample": r["sample"], "tools": set()})
        a["n"] += r["n"]
        a["days"].add(r["d"])
        a["buckets"][r["b"]] += r["n"]
        a["tools"].add(r["tool"])
        if not a["cmd"] and r["cmd"]:
            a["cmd"] = r["cmd"]
    out = []
    for a in actors.values():
        out.append({"exe": a["exe"], "signing_id": a["signing_id"], "team_id": a["team_id"], "verdict": a["verdict"],
                    "events": a["n"], "days": len(a["days"]), "tools": sorted(a["tools"]),
                    "top_buckets": [{"bucket": b, "events": n} for b, n in a["buckets"].most_common(3)],
                    "cmd": a["cmd"], "parent": a["parent"], "sample": a["sample"]})
    out.sort(key=lambda a: (a["verdict"] != "ALERT", -a["events"]))
    return out


TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Session access report</title>
<style>
:root {
  color-scheme: light;
  --page: #f9f9f7; --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,0.10);
  --known: #2a78d6; --unlisted: #eb6834;
  --seq1: #cde2fb; --seq2: #9ec5f4; --seq3: #6da7ec; --seq4: #3987e5; --seq5: #256abf; --seq6: #184f95; --seq7: #0d366b;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    color-scheme: dark;
    --page: #0d0d0d; --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,0.10);
    --known: #3987e5; --unlisted: #d95926;
    --seq1: #0d366b; --seq2: #104281; --seq3: #184f95; --seq4: #256abf; --seq5: #3987e5; --seq6: #6da7ec; --seq7: #9ec5f4;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--page); color: var(--ink); font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; padding-block: 24px; padding-inline: 20px; }
main { max-width: 1180px; margin: 0 auto; }
h1 { font-size: 22px; margin: 0 0 4px; font-weight: 650; }
h2 { font-size: 15px; margin: 0 0 10px; font-weight: 600; }
.sub { color: var(--ink-2); margin: 0 0 18px; }
.sub code { font-size: 12px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 18px; margin-bottom: 16px; }
.filters { display: flex; flex-wrap: wrap; gap: 10px 16px; align-items: center; margin-bottom: 16px; }
.filters label { color: var(--ink-2); font-size: 13px; display: flex; gap: 6px; align-items: center; }
select, input[type=search] { font: inherit; padding: 5px 8px; border: 1px solid var(--axis); border-radius: 6px; background: var(--surface); color: var(--ink); }
input[type=search] { min-width: 220px; }
button.link { background: none; border: none; color: var(--ink-2); text-decoration: underline; cursor: pointer; font: inherit; font-size: 13px; padding: 0; }
.kpis { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 16px; }
.kpi { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
.kpi .v { font-size: 30px; font-weight: 650; line-height: 1.1; }
.kpi .l { color: var(--ink-2); font-size: 13px; margin-top: 4px; }
.kpi .l .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }
.legend { display: flex; gap: 16px; color: var(--ink-2); font-size: 13px; margin: 0 0 8px; }
.legend span::before { content: ""; display: inline-block; width: 10px; height: 10px; border-radius: 3px; margin-right: 6px; vertical-align: -1px; background: var(--c); }
svg { display: block; width: 100%; height: auto; overflow: visible; }
svg text { font: 11px system-ui, -apple-system, sans-serif; fill: var(--muted); font-variant-numeric: tabular-nums; }
svg text.val { fill: var(--ink-2); }
.bar { cursor: pointer; }
.bar.dim { opacity: 0.35; }
.tip { position: fixed; pointer-events: none; background: var(--surface); color: var(--ink); border: 1px solid var(--border); box-shadow: 0 4px 16px rgba(0,0,0,0.12); border-radius: 8px; padding: 8px 10px; font-size: 12px; z-index: 10; max-width: 380px; display: none; }
.tip b { display: block; margin-bottom: 2px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 7px 8px; border-bottom: 1px solid var(--grid); vertical-align: top; }
th { color: var(--ink-2); font-weight: 600; cursor: pointer; white-space: nowrap; user-select: none; }
th.num, td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.mono { font-family: ui-monospace, Menlo, monospace; font-size: 12px; word-break: break-all; }
.tag { display: inline-block; padding: 1px 7px; border-radius: 999px; font-size: 11px; border: 1px solid var(--border); color: var(--ink-2); white-space: nowrap; }
.tag::before { content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 5px; background: var(--c); }
tr.actor { cursor: pointer; }
tr.actor:hover { background: color-mix(in srgb, var(--ink) 4%, transparent); }
tr.detail td { background: color-mix(in srgb, var(--ink) 3%, transparent); padding: 12px 14px; }
.kv { display: grid; grid-template-columns: 110px 1fr; gap: 3px 12px; font-size: 12px; margin-bottom: 10px; }
.kv .k { color: var(--muted); }
.kv .val { font-family: ui-monospace, Menlo, monospace; word-break: break-all; }
.spark { display: flex; align-items: flex-end; gap: 2px; height: 34px; }
.spark i { flex: 1; background: var(--known); border-radius: 2px 2px 0 0; min-height: 1px; }
.spark i.u { background: var(--unlisted); }
.hours { display: flex; justify-content: space-between; color: var(--muted); font-size: 10px; }
.sub-table { font-size: 12px; margin-top: 8px; }
.sub-table th { font-size: 12px; }
.empty { color: var(--muted); padding: 24px; text-align: center; }
.tablewrap { overflow-x: auto; }
.small { color: var(--muted); font-size: 12px; }
.note { color: var(--ink-2); font-size: 12px; margin-top: 8px; }
@media (max-width: 640px) { .kpi .v { font-size: 24px; } }
</style>
</head>
<body>
<main>
<h1>Session access report</h1>
<p class="sub" id="sub"></p>

<div class="filters">
  <label>Day <select id="fDay"></select></label>
  <label>Actors <select id="fVerdict">
    <option value="all">All</option>
    <option value="known">Known (allow-listed)</option>
    <option value="unlisted">Unlisted</option>
  </select></label>
  <label>Search <input id="fQ" type="search" placeholder="actor, path, team id…"></label>
  <button class="link" id="reset">Reset</button>
</div>

<div class="kpis" id="kpis"></div>

<div class="card">
  <h2>Accesses per day</h2>
  <div class="legend"><span style="--c: var(--known)">Known actors</span><span style="--c: var(--unlisted)">Unlisted actors</span>
    <button class="link" id="toggleDailyTable" style="margin-left:auto">Show as table</button></div>
  <div id="daily"></div>
  <p class="note">Click a day to filter the whole page to it.</p>
</div>

<div class="card">
  <h2>When: day × hour</h2>
  <div id="heat"></div>
  <p class="note" id="heatNote"></p>
</div>

<div class="card">
  <h2>Who: actors</h2>
  <div class="tablewrap"><table id="actors"></table></div>
  <p class="note">Click a row for command line, parent process, per-location counts and an hourly profile. An actor is a distinct executable + code-signing identity + verdict.</p>
</div>

<div class="card">
  <h2>What: locations</h2>
  <div class="tablewrap"><table id="buckets"></table></div>
</div>
</main>
<div class="tip" id="tip"></div>

<script id="data" type="application/json">__DATA__</script>
<script>
const DATA = JSON.parse(document.getElementById('data').textContent);
const ROWS = DATA.rows, DAYS = DATA.days, META = DATA.meta;
const $ = s => document.querySelector(s);
const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = n => n.toLocaleString();
const base = exe => { const b = exe.split('/').pop(); return b; };
// Executable basename, unless it is a version number (~/.local/share/claude/versions/2.1.272,
// .../sometool/versions/1.3.128): then the nearest meaningful directory name, else the signing id.
const actorName = r => {
  const parts = r.exe.split('/').filter(Boolean);
  let i = parts.length - 1;
  while (i > 0 && (/^\d/.test(parts[i]) || /^(versions?|bin|current|releases?)$/i.test(parts[i]))) i--;
  const b = parts[i] || base(r.exe);
  return /^\d/.test(b) ? (r.sid && r.sid !== 'a.out' ? r.sid : b) : b;
};
const actorKey = r => [r.exe, r.sid || '', r.tid || '', r.v].join('|');
const isUnlisted = r => r.v === 'ALERT';
const fmtTime = t => t ? new Date(t * 1000).toLocaleString(undefined, {month:'short', day:'numeric', hour:'2-digit', minute:'2-digit'}) : '—';

const state = { day: 'all', verdict: 'all', q: '', sort: {col: 'n', dir: -1}, open: new Set(), dailyTable: false };

function filtered(ignoreDay) {
  const q = state.q.trim().toLowerCase();
  return ROWS.filter(r =>
    (ignoreDay || state.day === 'all' || r.d === state.day) &&
    (state.verdict === 'all' || (state.verdict === 'unlisted') === isUnlisted(r)) &&
    (!q || [r.exe, r.sid, r.tid, r.b, r.cmd, r.parent, r.v, r.tool].some(x => x && String(x).toLowerCase().includes(q))));
}

function renderSub() {
  const from = DAYS[0], to = DAYS[DAYS.length - 1];
  let s = `${from === to ? from : from + ' → ' + to} · generated ${META.generated} · source <code>${esc(META.log_dir)}</code>`;
  if (META.access_since) s += ` · known actors recorded since ${META.access_since}`;
  if (META.backfilled) s += ` · ${fmt(META.backfilled)} unlisted events backfilled from events.jsonl`;
  $('#sub').innerHTML = s;
}

function renderKpis(rows) {
  const actors = new Set(rows.map(actorKey));
  const un = rows.filter(isUnlisted);
  const unActors = new Set(un.map(actorKey));
  const total = rows.reduce((a, r) => a + r.n, 0), unTotal = un.reduce((a, r) => a + r.n, 0);
  const tiles = [
    [fmt(total), 'accesses'],
    [fmt(actors.size), 'distinct actors'],
    [fmt(unActors.size), '<span class="dot" style="background:var(--unlisted)"></span>unlisted actors'],
    [fmt(unTotal), '<span class="dot" style="background:var(--unlisted)"></span>unlisted accesses'],
  ];
  $('#kpis').innerHTML = tiles.map(([v, l]) => `<div class="kpi"><div class="v">${v}</div><div class="l">${l}</div></div>`).join('');
}

// ---- tooltip -------------------------------------------------------------
const tip = $('#tip');
function showTip(e, htmlStr) { tip.innerHTML = htmlStr; tip.style.display = 'block'; moveTip(e); }
function moveTip(e) { const w = tip.offsetWidth, h = tip.offsetHeight; let x = e.clientX + 14, y = e.clientY + 14; if (x + w > innerWidth - 8) x = e.clientX - w - 14; if (y + h > innerHeight - 8) y = e.clientY - h - 14; tip.style.left = x + 'px'; tip.style.top = y + 'px'; }
function hideTip() { tip.style.display = 'none'; }

// ---- daily stacked bars ----------------------------------------------------
function roundedTop(x, y, w, h, r) {
  if (h <= 0) return '';
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h} V${y + r} Q${x},${y} ${x + r},${y} H${x + w - r} Q${x + w},${y} ${x + w},${y + r} V${y + h} Z`;
}
function renderDaily() {
  const rows = filtered(true);
  const per = DAYS.map(d => { const rs = rows.filter(r => r.d === d); return { d, known: rs.filter(r => !isUnlisted(r)).reduce((a, r) => a + r.n, 0), un: rs.filter(isUnlisted).reduce((a, r) => a + r.n, 0) }; });
  const el = $('#daily');
  if (state.dailyTable) {
    el.innerHTML = `<table><tr><th>Day</th><th class="num">Known</th><th class="num">Unlisted</th><th class="num">Total</th></tr>` +
      per.map(p => `<tr><td>${p.d}</td><td class="num">${fmt(p.known)}</td><td class="num">${fmt(p.un)}</td><td class="num">${fmt(p.known + p.un)}</td></tr>`).join('') + `</table>`;
    return;
  }
  const W = 1000, H = 220, padL = 44, padR = 12, padT = 22, padB = 28;
  const max = Math.max(1, ...per.map(p => p.known + p.un));
  const iw = (W - padL - padR) / per.length, bw = Math.min(56, iw * 0.62);
  const y = v => padT + (H - padT - padB) * (1 - v / max);
  const ticks = niceTicks(max, 4);
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Accesses per day, stacked by known and unlisted actors">`;
  ticks.forEach(t => { s += `<line x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}" stroke="var(--grid)" stroke-width="1"/><text x="${padL - 6}" y="${y(t) + 4}" text-anchor="end">${fmt(t)}</text>`; });
  s += `<line x1="${padL}" x2="${W - padR}" y1="${y(0)}" y2="${y(0)}" stroke="var(--axis)" stroke-width="1"/>`;
  per.forEach((p, i) => {
    const x = padL + iw * i + (iw - bw) / 2, tot = p.known + p.un;
    const dim = state.day !== 'all' && state.day !== p.d ? ' dim' : '';
    const hK = y(0) - y(p.known), hU = y(0) - y(p.un);
    const gap = p.known > 0 && p.un > 0 ? 2 : 0;
    // known segment anchored to the baseline, unlisted stacked above with a 2px surface gap
    if (p.known > 0) s += `<path class="bar${dim}" data-d="${p.d}" d="${p.un > 0 ? `M${x},${y(0)} V${y(p.known)} H${x + bw} V${y(0)} Z` : roundedTop(x, y(p.known), bw, hK, 4)}" fill="var(--known)"/>`;
    if (p.un > 0) s += `<path class="bar${dim}" data-d="${p.d}" d="${roundedTop(x, y(tot) , bw, Math.max(0, hU - gap), 4)}" fill="var(--unlisted)"/>`;
    if (tot > 0) s += `<text class="val" x="${x + bw / 2}" y="${y(tot) - 6}" text-anchor="middle">${fmt(tot)}</text>`;
    s += `<rect class="bar${dim}" data-d="${p.d}" x="${padL + iw * i}" y="${padT}" width="${iw}" height="${H - padT - padB}" fill="transparent"/>`;
    s += `<text x="${x + bw / 2}" y="${H - 8}" text-anchor="middle">${p.d.slice(5)}</text>`;
  });
  s += `</svg>`;
  el.innerHTML = s;
  el.querySelectorAll('.bar').forEach(b => {
    const p = per.find(q => q.d === b.dataset.d);
    b.addEventListener('mousemove', e => showTip(e, `<b>${p.d}</b>Known ${fmt(p.known)}<br>Unlisted ${fmt(p.un)}<br>Total ${fmt(p.known + p.un)}`));
    b.addEventListener('mouseleave', hideTip);
    b.addEventListener('click', () => { state.day = state.day === p.d ? 'all' : p.d; $('#fDay').value = state.day; render(); });
  });
}
function niceTicks(max, n) {
  const raw = max / n, mag = Math.pow(10, Math.floor(Math.log10(raw))), norm = raw / mag;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
  const out = []; for (let v = 0; v <= max + 1e-9; v += step) out.push(Math.round(v)); return out;
}

// ---- heatmap ------------------------------------------------------------------
function renderHeat() {
  const rows = filtered(false);
  const days = state.day === 'all' ? DAYS : [state.day];
  const grid = days.map(d => { const h = new Array(24).fill(0); rows.filter(r => r.d === d).forEach(r => r.h.forEach((v, i) => h[i] += v)); return h; });
  const max = Math.max(1, ...grid.flat());
  const W = 1000, padL = 84, padT = 18, cw = (W - padL - 8) / 24, ch = 22, H = padT + ch * days.length + 6;
  const col = v => { if (v <= 0) return 'var(--surface)'; const t = Math.log(v + 1) / Math.log(max + 1); return `var(--seq${Math.min(7, 1 + Math.floor(t * 6.999))})`; };
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Accesses by day and hour">`;
  for (let h = 0; h < 24; h += 2) s += `<text x="${padL + cw * h + cw / 2}" y="${padT - 6}" text-anchor="middle">${String(h).padStart(2, '0')}</text>`;
  days.forEach((d, di) => {
    s += `<text x="${padL - 8}" y="${padT + ch * di + ch / 2 + 4}" text-anchor="end">${d}</text>`;
    grid[di].forEach((v, h) => s += `<rect class="cell" data-d="${d}" data-h="${h}" data-v="${v}" x="${padL + cw * h + 1}" y="${padT + ch * di + 1}" width="${cw - 2}" height="${ch - 2}" rx="3" fill="${col(v)}" stroke="var(--grid)" stroke-width="${v > 0 ? 0 : 1}"/>`);
  });
  s += `</svg>`;
  $('#heat').innerHTML = s;
  $('#heatNote').textContent = `Stronger color = more accesses in that local hour (log scale, max ${fmt(max)} in one hour). Follows the filters above.`;
  $('#heat').querySelectorAll('.cell').forEach(c => {
    c.addEventListener('mousemove', e => showTip(e, `<b>${c.dataset.d} ${String(c.dataset.h).padStart(2, '0')}:00–${String(+c.dataset.h + 1).padStart(2, '0')}:00</b>${fmt(+c.dataset.v)} accesses`));
    c.addEventListener('mouseleave', hideTip);
  });
}

// ---- actors table -----------------------------------------------------------------
function groupActors(rows) {
  const m = new Map();
  rows.forEach(r => {
    const k = actorKey(r);
    let a = m.get(k);
    if (!a) a = m.set(k, { key: k, exe: r.exe, sid: r.sid, tid: r.tid, v: r.v, n: 0, days: new Set(), pids: new Set(), tools: new Set(), buckets: new Map(), kinds: new Map(), h: new Array(24).fill(0), first: Infinity, last: 0, cmd: r.cmd, parent: r.parent, sample: r.sample }).get(k);
    a.n += r.n; a.days.add(r.d); r.pids.forEach(p => a.pids.add(p)); a.tools.add(r.tool);
    a.buckets.set(r.b, (a.buckets.get(r.b) || 0) + r.n);
    const kk = r.k + (r.m ? ' ' + r.m : ''); a.kinds.set(kk, (a.kinds.get(kk) || 0) + r.n);
    r.h.forEach((v, i) => a.h[i] += v);
    a.first = Math.min(a.first, r.first); a.last = Math.max(a.last, r.last);
    if (!a.cmd && r.cmd) a.cmd = r.cmd; if (!a.parent && r.parent) a.parent = r.parent;
  });
  return [...m.values()];
}
const COLS = [
  ['name', 'Actor', a => actorName(a)],
  ['v', 'Verdict', a => a.v],
  ['n', 'Accesses', a => a.n, true],
  ['pids', 'Processes', a => a.pids.size, true],
  ['days', 'Days', a => a.days.size, true],
  ['tools', 'Tool', a => [...a.tools].sort().join(', ')],
  ['buckets', 'Top locations', a => [...a.buckets.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3).map(([b, n]) => `${b} (${fmt(n)})`).join(' · ')],
  ['last', 'Last seen', a => a.last, true],
];
function renderActors() {
  const actors = groupActors(filtered(false));
  const { col, dir } = state.sort;
  const c = COLS.find(x => x[0] === col) || COLS[2];
  actors.sort((a, b) => { const ua = isUnlisted(a), ub = isUnlisted(b); if (ua !== ub) return ua ? -1 : 1; const va = c[2](a), vb = c[2](b); return (va > vb ? 1 : va < vb ? -1 : 0) * dir; });
  const t = $('#actors');
  if (!actors.length) { t.innerHTML = `<tr><td class="empty">No accesses match the current filters.</td></tr>`; return; }
  let s = `<tr>` + COLS.map(([k, label, , num]) => `<th class="${num ? 'num' : ''}" data-col="${k}">${label}${state.sort.col === k ? (dir < 0 ? ' ▾' : ' ▴') : ''}</th>`).join('') + `</tr>`;
  actors.forEach(a => {
    const un = isUnlisted(a);
    const tag = `<span class="tag" style="--c: var(--${un ? 'unlisted' : 'known'})">${esc(un ? 'unlisted' : a.v)}</span>`;
    s += `<tr class="actor" data-k="${esc(a.key)}"><td><b>${esc(actorName(a))}</b><div class="small">${esc(a.sid || 'unsigned')}${a.tid ? ' · ' + esc(a.tid) : ''}</div></td>` +
      `<td>${tag}</td><td class="num">${fmt(a.n)}</td><td class="num">${fmt(a.pids.size)}</td><td class="num">${a.days.size}</td>` +
      `<td>${esc([...a.tools].sort().join(', '))}</td><td class="small">${esc(COLS[6][2](a))}</td><td class="num small">${fmtTime(a.last)}</td></tr>`;
    if (state.open.has(a.key)) {
      const maxH = Math.max(1, ...a.h);
      const buckets = [...a.buckets.entries()].sort((x, y) => y[1] - x[1]);
      s += `<tr class="detail"><td colspan="${COLS.length}">
        <div class="kv">
          <span class="k">executable</span><span class="val">${esc(a.exe)}</span>
          <span class="k">command</span><span class="val">${esc(a.cmd || '— (process exited before lookup)')}</span>
          <span class="k">parent</span><span class="val">${esc(a.parent || '—')}</span>
          <span class="k">sample path</span><span class="val">${esc(a.sample || '—')}</span>
          <span class="k">operations</span><span class="val">${esc([...a.kinds.entries()].sort((x, y) => y[1] - x[1]).map(([k, n]) => `${k} ${fmt(n)}`).join(' · '))}</span>
          <span class="k">pids</span><span class="val">${esc([...a.pids].sort((x, y) => x - y).join(', '))}${a.pids.size >= 50 ? ' …' : ''}</span>
          <span class="k">first / last</span><span class="val">${fmtTime(a.first)} → ${fmtTime(a.last)}</span>
        </div>
        <div class="small" style="margin-bottom:4px">Hourly profile (${state.day === 'all' ? 'all selected days' : state.day})</div>
        <div class="spark">${a.h.map((v, i) => `<i class="${un ? 'u' : ''}" style="height:${Math.max(1, Math.round(v / maxH * 34))}px" title="${String(i).padStart(2, '0')}:00 — ${fmt(v)}"></i>`).join('')}</div>
        <div class="hours"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div>
        <table class="sub-table"><tr><th>Location</th><th class="num">Accesses</th></tr>${buckets.map(([b, n]) => `<tr><td class="mono">${esc(b)}</td><td class="num">${fmt(n)}</td></tr>`).join('')}</table>
      </td></tr>`;
    }
  });
  t.innerHTML = s;
  t.querySelectorAll('th').forEach(th => th.addEventListener('click', () => { const k = th.dataset.col; state.sort = state.sort.col === k ? { col: k, dir: -state.sort.dir } : { col: k, dir: k === 'name' || k === 'v' || k === 'tools' ? 1 : -1 }; renderActors(); }));
  t.querySelectorAll('tr.actor').forEach(tr => tr.addEventListener('click', () => { const k = tr.dataset.k; state.open.has(k) ? state.open.delete(k) : state.open.add(k); renderActors(); }));
}

// ---- buckets table ------------------------------------------------------------------
function renderBuckets() {
  const rows = filtered(false);
  const m = new Map();
  rows.forEach(r => { let b = m.get(r.b); if (!b) b = m.set(r.b, { b: r.b, tool: r.tool, n: 0, un: 0, actors: new Map() }).get(r.b); b.n += r.n; if (isUnlisted(r)) b.un += r.n; const nm = actorName(r) + (isUnlisted(r) ? ' (unlisted)' : ''); b.actors.set(nm, (b.actors.get(nm) || 0) + r.n); });
  const list = [...m.values()].sort((a, b) => b.un - a.un || b.n - a.n);
  const t = $('#buckets');
  if (!list.length) { t.innerHTML = `<tr><td class="empty">Nothing to show.</td></tr>`; return; }
  t.innerHTML = `<tr><th>Location</th><th>Tool</th><th class="num">Accesses</th><th class="num">Unlisted</th><th>Actors</th></tr>` +
    list.map(b => `<tr><td class="mono">${esc(b.b)}</td><td>${esc(b.tool)}</td><td class="num">${fmt(b.n)}</td><td class="num">${b.un ? fmt(b.un) : '<span class="small">0</span>'}</td><td class="small">${esc([...b.actors.entries()].sort((x, y) => y[1] - x[1]).slice(0, 4).map(([a, n]) => `${a} (${fmt(n)})`).join(' · '))}${b.actors.size > 4 ? ` · +${b.actors.size - 4} more` : ''}</td></tr>`).join('');
}

function render() { const rows = filtered(false); renderKpis(rows); renderDaily(); renderHeat(); renderActors(); renderBuckets(); }

// ---- wiring ------------------------------------------------------------------------------
const fDay = $('#fDay');
fDay.innerHTML = `<option value="all">All ${DAYS.length} days</option>` + DAYS.map(d => `<option value="${d}">${d}</option>`).join('');
fDay.addEventListener('change', () => { state.day = fDay.value; render(); });
$('#fVerdict').addEventListener('change', e => { state.verdict = e.target.value; render(); });
$('#fQ').addEventListener('input', e => { state.q = e.target.value; render(); });
$('#reset').addEventListener('click', () => { state.day = 'all'; state.verdict = 'all'; state.q = ''; fDay.value = 'all'; $('#fVerdict').value = 'all'; $('#fQ').value = ''; render(); });
$('#toggleDailyTable').addEventListener('click', e => { state.dailyTable = !state.dailyTable; e.target.textContent = state.dailyTable ? 'Show as chart' : 'Show as table'; renderDaily(); });
renderSub(); render();
</script>
</body>
</html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log-dir", default=DEFAULT_LOG_DIR)
    ap.add_argument("--days", type=int, default=7, help="last N days (default 7)")
    ap.add_argument("--day", help="a single day, YYYY-MM-DD")
    ap.add_argument("--from", dest="from", help="range start YYYY-MM-DD")
    ap.add_argument("--to", help="range end YYYY-MM-DD (default today)")
    ap.add_argument("--out", help="output HTML path (default %s/session-access-<from>_<to>.html)" % DEFAULT_OUT_DIR)
    ap.add_argument("--open", action="store_true", help="open the report in the default browser")
    ap.add_argument("--json", action="store_true", help="print a machine-readable summary to stdout")
    ap.add_argument("--home", default=os.path.expanduser("~"), help="home dir to abbreviate as ~ in backfilled paths")
    ap.add_argument("--no-backfill", action="store_true", help="do not read events.jsonl for pre-aggregation periods")
    args = ap.parse_args()

    days = day_range(args)
    rows = Rows()
    access_first = load_access(args.log_dir, days, rows)
    backfilled = 0 if args.no_backfill else backfill_events(args.log_dir, days, rows, access_first, args.home)
    exported = rows.export()

    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M"),
        "log_dir": args.log_dir,
        "access_since": time.strftime("%Y-%m-%d %H:%M", time.localtime(min(access_first.values()))) if access_first else None,
        "backfilled": backfilled,
    }
    data = {"days": days, "rows": exported, "meta": meta}
    page = TEMPLATE.replace("__DATA__", json.dumps(data, ensure_ascii=False).replace("</", "<\\/"))

    out = args.out or os.path.join(DEFAULT_OUT_DIR, "session-access-%s_%s.html" % (days[0], days[-1]))
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as fh:
        fh.write(page)

    summ = summary(exported, days)
    total = sum(r["n"] for r in exported)
    result = {
        "report": os.path.abspath(out), "from": days[0], "to": days[-1],
        "accesses": total, "actors": len(summ),
        "unlisted_actors": [a for a in summ if a["verdict"] == "ALERT"],
        "known_actors": [{"verdict": a["verdict"], "exe": a["exe"], "events": a["events"]} for a in summ if a["verdict"] != "ALERT"],
        "access_since": meta["access_since"], "backfilled_events": backfilled,
        "days_with_data": sorted({r["d"] for r in exported}),
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("report: %s" % result["report"])
        print("range: %s → %s  accesses: %d  actors: %d  (unlisted: %d)" % (days[0], days[-1], total, len(summ), len(result["unlisted_actors"])))
        for a in result["unlisted_actors"][:15]:
            print("  UNLISTED %6d  %s  [%s %s]  %s" % (a["events"], a["exe"], a["signing_id"] or "unsigned", a["team_id"] or "-",
                                                     "; ".join("%s (%d)" % (b["bucket"], b["events"]) for b in a["top_buckets"])))
        if not exported:
            print("  no data: is the daemon running and writing %s/access-*.jsonl ?" % args.log_dir)
    if args.open:
        subprocess.run(["/usr/bin/open", out], check=False)


if __name__ == "__main__":
    main()
