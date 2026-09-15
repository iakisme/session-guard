#!/usr/bin/python3
"""session-guard: alert when any process touches AI-agent session data.

Reads eslogger(1) JSON Lines on stdin, e.g.

    sudo sh -c '/usr/bin/eslogger open clone copyfile rename unlink \
        | /usr/bin/python3 session_guard.py --config session-guard.json'

Every event whose file path falls under a configured `watch` prefix (and not
under an `exclude` prefix) is checked against the `allow` rules. Anything not
allowed is appended to <log_dir>/events.jsonl and raised as a macOS
notification (rate-limited per process) plus a syslog line.

Endpoint Security is the only reliable way on macOS to see *reads*: FSEvents /
fswatch only report writes. eslogger needs root and its responsible process
needs Full Disk Access (see README.md).

Compatible with the Apple-shipped /usr/bin/python3 (3.9).
"""
import argparse
import collections
import json
import os
import pwd
import re
import signal
import subprocess
import sys
import threading
import time

FREAD = 0x1
FWRITE = 0x2

# Path components too generic to serve as a cheap pre-filter substring.
GENERIC_COMPONENTS = {"", "Users", "Library", "Application Support", ".local",
                      "share", "private", "var", "tmp"}


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def base(path):
    return os.path.basename(path.rstrip("/")) if path else "?"


class Config:
    def __init__(self, raw):
        n = raw.get("notify") or {}
        # Which user's session data to guard. Under `sudo` this is SUDO_USER;
        # under launchd there is no such hint, so install.sh bakes it into the
        # installed config. Falls back to the invoking user.
        user = n.get("user") or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            sys.exit("session-guard: unknown user %r in config" % user)
        self.notify_user = user
        self.notify_uid = int(n.get("uid") or pw.pw_uid)
        self.home = raw.get("home") or pw.pw_dir
        self.watch = [self.expand(p) for p in raw.get("watch", [])]
        self.exclude = [self.expand(p) for p in raw.get("exclude", [])]
        self.allow = []
        for rule in raw.get("allow", []):
            r = dict(rule)
            for key in ("exe_prefix", "cwd"):
                if key in r:
                    v = r[key]
                    r[key] = [self.expand(x) for x in (v if isinstance(v, list) else [v])]
            if "cmd_regex" in r:
                r["cmd_regex"] = re.compile(r["cmd_regex"])
            self.allow.append(r)
        self.cooldown = int(raw.get("cooldown_seconds", 60))
        self.heartbeat = int(raw.get("heartbeat_seconds", 300))
        self.agg_flush = int(raw.get("aggregate_flush_seconds", 600))
        self.log_dir = raw.get("log_dir", "/var/log/session-guard")
        self.notify_macos = bool(n.get("macos_notification", True))
        self.notify_on_start = bool(n.get("on_start", True))
        self.notify_command = n.get("command")
        self.markers = self._markers()

    def expand(self, p):
        if p == "~":
            return self.home
        if p.startswith("~/"):
            return os.path.join(self.home, p[2:])
        return p

    def _markers(self):
        """Slash-free substrings that must appear in a raw line for it to be
        relevant. Lets us skip json.loads() for the vast majority of events.
        Slash-free so it works whether eslogger escapes '/' as '\\/' or not."""
        out = set()
        for p in self.watch:
            rel = p[len(self.home):] if p.startswith(self.home) else p
            for comp in rel.split("/"):
                if comp not in GENERIC_COMPONENTS:
                    out.add(comp)
                    break
            else:
                out.add(base(p))
        return sorted(out)


def load_config(path):
    with open(path) as fh:
        return Config(json.load(fh))


def collect_paths(node, out):
    """Collect every file path mentioned in an eslogger `event` subtree,
    including composed target paths for clone/copyfile/rename."""
    if isinstance(node, dict):
        p = node.get("path")
        if isinstance(p, str):
            out.append(p)
        td, tn = node.get("target_dir"), node.get("target_name")
        if isinstance(td, dict) and isinstance(tn, str) and isinstance(td.get("path"), str):
            out.append(td["path"].rstrip("/") + "/" + tn)
        d, fn = node.get("dir"), node.get("filename")
        if isinstance(d, dict) and isinstance(fn, str) and isinstance(d.get("path"), str):
            out.append(d["path"].rstrip("/") + "/" + fn)
        for k, v in node.items():
            if k == "stat":
                continue
            collect_paths(v, out)
    elif isinstance(node, list):
        for v in node:
            collect_paths(v, out)


class ProcCache:
    """Best-effort pid -> command line / cwd, cached briefly (short-lived `cat`
    processes are usually gone by the time we look, parents are not)."""

    def __init__(self, ttl=5.0):
        self.ttl = ttl
        self.cache = {}

    def _get(self, key, pid, fn):
        if not pid or pid <= 0:
            return None
        hit = self.cache.get((key, pid))
        now = time.time()
        if hit and now - hit[0] < self.ttl:
            return hit[1]
        try:
            val = fn(pid)
        except Exception:
            val = None
        self.cache[(key, pid)] = (now, val)
        if len(self.cache) > 4000:
            self.cache.clear()
        return val

    def command(self, pid):
        def run(p):
            out = subprocess.run(["/bin/ps", "-o", "command=", "-p", str(p)],
                                 capture_output=True, text=True, timeout=3).stdout.strip()
            return out[:300] or None
        return self._get("cmd", pid, run)

    def cwd(self, pid):
        def run(p):
            out = subprocess.run(["/usr/sbin/lsof", "-a", "-p", str(p), "-d", "cwd", "-Fn"],
                                 capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.startswith("n"):
                    return line[1:]
            return None
        return self._get("cwd", pid, run)


class Guard:
    def __init__(self, cfg, learn=None, dump=0):
        self.cfg = cfg
        self.learn = learn
        self.dump = dump
        self.procs = ProcCache()
        self.tally = collections.Counter()
        self.tally_sample = {}
        self.state = {}  # (pid, exe) -> {"last_notify": t, "pending": n}
        self.threads = []
        self.stats = collections.Counter()
        self.last_heartbeat = time.time()
        # Hourly access aggregates for EVERY matched event (allowed or not),
        # flushed to access-YYYY-MM-DD.jsonl; the report tool reads those.
        self.agg = {}
        self.agg_last_flush = time.time()
        self.lock = threading.Lock()
        self._open_logs()

    # -- logging -----------------------------------------------------------
    def _open_logs(self):
        d = self.cfg.log_dir
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".w")
            open(probe, "a").close()
            os.remove(probe)
        except Exception:
            d = os.path.join(self.cfg.home, "Library", "Logs", "session-guard")
            os.makedirs(d, exist_ok=True)
        self.log_dir = d
        self.events_path = os.path.join(d, "events.jsonl")
        self.guard_path = os.path.join(d, "guard.log")
        for p in (self.events_path, self.guard_path):
            open(p, "a").close()
            try:
                os.chmod(p, 0o644)
            except Exception:
                pass

    def log(self, msg):
        line = "%s %s\n" % (now_iso(), msg)
        with open(self.guard_path, "a") as fh:
            fh.write(line)
        sys.stderr.write(line)
        sys.stderr.flush()

    def record(self, rec):
        with open(self.events_path, "a") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n")

    # -- matching ----------------------------------------------------------
    def watched(self, path):
        for ex in self.cfg.exclude:
            if path.startswith(ex):
                return False
        for w in self.cfg.watch:
            if w.endswith("/"):
                if path.startswith(w) or path == w[:-1]:
                    return True
            elif path == w:
                return True
        return False

    def allowed(self, exe, sid, tid, platform, pid=None):
        """First matching allow rule name, else None. Cheap fields (from the
        event itself) are checked first; `cwd` and `cmd_regex` need a live
        process lookup and are only consulted when the cheap fields passed.
        A lookup that fails (process already gone) does NOT match: fail closed."""
        for r in self.cfg.allow:
            ok = True
            if "exe_prefix" in r:
                ok = ok and any(exe.startswith(p) for p in r["exe_prefix"])
            if "signing_id" in r:
                ok = ok and sid == r["signing_id"]
            if "signing_id_prefix" in r:
                ok = ok and bool(sid) and sid.startswith(r["signing_id_prefix"])
            if "team_id" in r:
                ok = ok and tid == r["team_id"]
            if "platform_binary" in r:
                ok = ok and platform == bool(r["platform_binary"])
            if ok and "cwd" in r:
                cwd = self.procs.cwd(pid)
                ok = bool(cwd) and any(cwd == c.rstrip("/") or cwd.startswith(c.rstrip("/") + "/") for c in r["cwd"])
            if ok and "cmd_regex" in r:
                cmd = self.procs.command(pid)
                ok = bool(cmd) and r["cmd_regex"].search(cmd) is not None
            if ok:
                return r.get("name", "?")
        return None

    @staticmethod
    def tool_of(path):
        if "/.claude" in path:
            return "Claude Code"
        if "/opencode" in path:
            return "OpenCode"
        if "/.codex" in path:
            return "Codex"
        return "session"

    def tilde(self, p):
        h = self.cfg.home
        return "~" + p[len(h):] if p == h or p.startswith(h + "/") else p

    def bucket_of(self, path):
        """Coarse location for aggregation: the watch prefix plus one path
        component (e.g. ~/.claude/projects/<project>, ~/.codex/sessions)."""
        for w in self.cfg.watch:
            if w.endswith("/") and (path.startswith(w) or path == w[:-1]):
                first = path[len(w):].split("/", 1)[0]
                return self.tilde(w + first if first else w[:-1])
            if path == w:
                return self.tilde(w)
        return self.tilde(path)

    # -- access aggregation --------------------------------------------------
    def aggregate(self, hits, kind, mode, exe, sid, tid, verdict, pid, ppid):
        now = time.time()
        hour = time.strftime("%Y-%m-%dT%H", time.localtime(now))
        key = (hour, exe, sid or "", tid or "", verdict, self.bucket_of(hits[0]), kind, mode or "")
        a = self.agg.get(key)
        if a is None:
            a = self.agg[key] = {"n": 0, "pids": set(), "first": now, "last": now, "sample": hits[0],
                                 "tool": self.tool_of(hits[0]),
                                 "cmd": self.procs.command(pid), "parent": self.procs.command(ppid)}
        a["n"] += 1
        a["last"] = now
        if len(a["pids"]) < 50:
            a["pids"].add(pid)

    def flush_agg(self):
        self.agg_last_flush = time.time()
        if not self.agg:
            return
        by_day = collections.defaultdict(list)
        for (hour, exe, sid, tid, verdict, bucket, kind, mode), a in self.agg.items():
            by_day[hour[:10]].append({
                "hour": hour, "exe": exe, "sid": sid or None, "tid": tid or None, "verdict": verdict,
                "tool": a["tool"], "bucket": bucket, "kind": kind, "mode": mode or None, "n": a["n"],
                "pids": sorted(p for p in a["pids"] if p is not None), "first": round(a["first"], 3),
                "last": round(a["last"], 3), "sample": self.tilde(a["sample"]), "cmd": a["cmd"], "parent": a["parent"]})
        for day, rows in by_day.items():
            p = os.path.join(self.log_dir, "access-%s.jsonl" % day)
            new = not os.path.exists(p)
            with open(p, "a") as fh:
                for r in rows:
                    fh.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
            if new:
                try:
                    os.chmod(p, 0o644)
                except Exception:
                    pass
            self.stats["agg_rows"] += len(rows)
        self.agg.clear()

    # -- main loop ---------------------------------------------------------
    def run(self, stream):
        markers = self.cfg.markers
        self.log("session-guard start pid=%d euid=%d user=%s home=%s log_dir=%s watch=%d exclude=%d allow=%d markers=%s%s"
                 % (os.getpid(), os.geteuid(), self.cfg.notify_user, self.cfg.home, self.log_dir, len(self.cfg.watch),
                    len(self.cfg.exclude), len(self.cfg.allow), ",".join(markers), " LEARN=%ss" % self.learn if self.learn else ""))
        if self.cfg.notify_uid == 0:
            self.log("WARNING: guarding root's home (%s). Set notify.user in the config to the real user." % self.cfg.home)
        if self.learn:
            signal.signal(signal.SIGALRM, lambda *_: self.finish_learn())
            signal.alarm(self.learn)
        elif self.cfg.notify_on_start:
            self.notify("session-guard started", "watching %d paths" % len(self.cfg.watch),
                        "Endpoint Security feed is live.", {"type": "start"})
        for raw in stream:
            self.stats["lines"] += 1
            if not any(m in raw for m in markers):
                self.heartbeat()
                continue
            try:
                ev = json.loads(raw)
            except ValueError:
                self.stats["bad_json"] += 1
                continue
            self.handle(ev, raw)
            self.heartbeat()
        if self.learn:
            self.finish_learn()
        self.shutdown("stdin closed (eslogger exited)")
        for t in self.threads:  # let in-flight notifications finish before exit
            t.join(timeout=15)

    def heartbeat(self):
        t = time.time()
        if self.agg and t - self.agg_last_flush >= self.cfg.agg_flush:
            self.flush_agg()
        if t - self.last_heartbeat >= self.cfg.heartbeat:
            self.last_heartbeat = t
            self.log("heartbeat lines=%d matched=%d allowed=%d alerts=%d notified=%d agg_rows=%d bad_json=%d"
                     % tuple(self.stats[k] for k in ("lines", "matched", "allowed", "alerts", "notified", "agg_rows", "bad_json")))

    def shutdown(self, reason):
        self.flush_agg()
        self.log("%s; lines=%d matched=%d alerts=%d agg_rows=%d"
                 % (reason, self.stats["lines"], self.stats["matched"], self.stats["alerts"], self.stats["agg_rows"]))

    def handle(self, ev, raw):
        event = ev.get("event") or {}
        paths = []
        collect_paths(event, paths)
        hits = [p for p in dict.fromkeys(paths) if self.watched(p)]
        if not hits:
            return
        self.stats["matched"] += 1
        if self.dump > 0:
            self.dump -= 1
            sys.stderr.write("RAW " + raw.rstrip() + "\n")

        proc = ev.get("process") or {}
        tok = proc.get("audit_token") or {}
        exe = ((proc.get("executable") or {}).get("path")) or "?"
        sid = proc.get("signing_id")
        tid = proc.get("team_id")
        platform = bool(proc.get("is_platform_binary"))
        pid = tok.get("pid")
        ppid = proc.get("ppid")
        rpid = (proc.get("responsible_audit_token") or {}).get("pid")
        kind = next(iter(event), "?")
        mode = None
        if kind == "open":
            ff = event["open"].get("fflag", 0) or 0
            mode = "read+write" if (ff & FREAD and ff & FWRITE) else ("write" if ff & FWRITE else "read")

        rule = self.allowed(exe, sid, tid, platform, pid)
        if self.learn is None:
            self.aggregate(hits, kind, mode, exe, sid, tid, rule or "ALERT", pid, ppid)
        if self.learn is not None:
            key = (exe, sid or "-", tid or "-", rule or "ALERT")
            self.tally[key] += 1
            if key not in self.tally_sample:
                self.tally_sample[key] = "%s %s %s" % (kind, mode or "", hits[0])
                self.log("learn: new actor %s sid=%s team=%s -> %s (%s)" % (exe, sid, tid, rule or "ALERT", hits[0]))
            return
        if rule:
            self.stats["allowed"] += 1
            return

        self.stats["alerts"] += 1
        rec = {
            "ts": ev.get("time") or now_iso(),
            "event": kind,
            "mode": mode,
            "paths": hits[:20],
            "tool": self.tool_of(hits[0]),
            "pid": pid, "ppid": ppid, "responsible_pid": rpid,
            "euid": tok.get("euid"),
            "exe": exe, "signing_id": sid, "team_id": tid, "platform_binary": platform,
            "tty": (proc.get("tty") or {}).get("path"),
            "cmd": self.procs.command(pid),
            "parent_cmd": self.procs.command(ppid),
            "responsible_cmd": self.procs.command(rpid) if rpid and rpid not in (pid, ppid) else None,
        }
        self.record(rec)
        self.maybe_notify(rec)

    def maybe_notify(self, rec):
        key = (rec["pid"], rec["exe"])
        t = time.time()
        with self.lock:
            st = self.state.get(key)
            if st and t - st["last_notify"] < self.cfg.cooldown:
                st["pending"] += 1
                return
            pending = st["pending"] if st else 0
            self.state[key] = {"last_notify": t, "pending": 0}
            if len(self.state) > 5000:
                self.state = {k: v for k, v in self.state.items() if t - v["last_notify"] < self.cfg.cooldown}
        more = " (+%d more in last %ds)" % (pending, self.cfg.cooldown) if pending else ""
        who = base(rec["exe"])
        if who[:1].isdigit() and rec.get("signing_id"):  # e.g. ~/.local/share/claude/versions/2.1.272
            who = rec["signing_id"]
        via = []
        if rec.get("parent_cmd"):
            via.append(base(rec["parent_cmd"].split(" ")[0]))
        if rec.get("responsible_cmd"):
            via.append(base(rec["responsible_cmd"].split(" ")[0]))
        title = "%s session accessed" % rec["tool"]
        subtitle = "%s[%s] %s %s%s" % (who, rec["pid"], rec["event"], rec["mode"] or "", more)
        body = rec["paths"][0]
        if via:
            body = "via %s  |  %s" % (" <- ".join(via), body)
        self.stats["notified"] += 1
        self.log("ALERT %s %s pid=%s exe=%s sid=%s team=%s tty=%s path=%s parent=%r"
                 % (rec["event"], rec["mode"], rec["pid"], rec["exe"], rec["signing_id"], rec["team_id"],
                    rec["tty"], rec["paths"][0], rec.get("parent_cmd")))
        t = threading.Thread(target=self.notify, args=(title, subtitle, body, rec), daemon=True)
        t.start()
        self.threads = [x for x in self.threads if x.is_alive()] + [t]

    # -- delivery ----------------------------------------------------------
    def notify(self, title, subtitle, body, rec):
        cfg = self.cfg
        msg = "%s | %s | %s" % (title, subtitle, body)
        try:
            subprocess.run(["/usr/bin/logger", "-t", "session-guard", "-p", "user.warning", msg], timeout=5)
        except Exception:
            pass
        if cfg.notify_macos:
            script = 'display notification %s with title %s subtitle %s sound name "Basso"' % (
                self.as_str(body[:200]), self.as_str(title), self.as_str(subtitle[:200]))
            cmd = ["/usr/bin/osascript", "-e", script]
            if os.geteuid() == 0 and cfg.notify_uid != 0:
                # Daemon context: post into the logged-in user's GUI session.
                cmd = ["/bin/launchctl", "asuser", str(cfg.notify_uid),
                       "/usr/bin/sudo", "-u", cfg.notify_user] + cmd
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                if r.returncode != 0:
                    self.log("notify failed rc=%d: %s" % (r.returncode, (r.stderr or "").strip()[:300]))
            except Exception as e:
                self.log("notify error: %r" % (e,))
        if cfg.notify_command:
            try:
                subprocess.run(cfg.notify_command, shell=True, input=json.dumps(rec).encode(),
                               timeout=60, capture_output=True)
            except Exception as e:
                self.log("notify command error: %r" % (e,))

    @staticmethod
    def as_str(s):
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'

    # -- learn mode --------------------------------------------------------
    def finish_learn(self):
        rows = sorted(self.tally.items(), key=lambda kv: -kv[1])
        out = ["", "learn summary: %d lines scanned, %d matched events, %d distinct actors"
               % (self.stats["lines"], sum(self.tally.values()), len(rows)),
               "%-7s %-16s %-36s %-12s %s" % ("count", "verdict", "signing_id", "team_id", "exe  |  sample")]
        for (exe, sid, tid, verdict), n in rows:
            out.append("%-7d %-16s %-36s %-12s %s  |  %s" % (n, verdict[:16], sid[:36], tid, exe, self.tally_sample.get((exe, sid, tid, verdict), "")))
        out.append("")
        out.append("Add legitimate 'ALERT' actors to the allow list in the config (prefer team_id/signing_id over bare paths).")
        sys.stdout.write("\n".join(out) + "\n")
        sys.stdout.flush()
        os._exit(0)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default="/usr/local/etc/session-guard.json",
                    help="JSON config (default: %(default)s); see session-guard.example.json")
    ap.add_argument("--learn", type=int, metavar="SECONDS",
                    help="tally every actor touching watched paths for N seconds, print a table, exit (no alerts)")
    ap.add_argument("--dump", type=int, default=0, metavar="N", help="print the first N matching raw events to stderr")
    ap.add_argument("--check-config", action="store_true", help="print the expanded config and exit")
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.check_config:
        print(json.dumps({"home": cfg.home, "watch": cfg.watch, "exclude": cfg.exclude, "allow": cfg.allow,
                          "markers": cfg.markers, "log_dir": cfg.log_dir,
                          "notify": {"user": cfg.notify_user, "uid": cfg.notify_uid, "macos": cfg.notify_macos,
                                     "command": cfg.notify_command}}, indent=2))
        return
    g = Guard(cfg, learn=args.learn, dump=args.dump)
    signal.signal(signal.SIGTERM, lambda *_: (g.shutdown("SIGTERM, exiting"), os._exit(0)))
    try:
        g.run(sys.stdin)
    except KeyboardInterrupt:
        g.shutdown("interrupted")


if __name__ == "__main__":
    main()
