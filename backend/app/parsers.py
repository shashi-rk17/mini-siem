"""Turn raw log lines into structured events (dicts). Returns None if line is not parseable."""
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

NGINX_RE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
SSH_SYSLOG = re.compile(r'^(?P<mon>\w{3})\s+(?P<day>\d+) (?P<time>[\d:]+) \S+ sshd\[\d+\]: (?P<msg>.*)$')
SSH_ISO = re.compile(r'^(?P<ts>\d{4}-\d\d-\d\dT\S+) \S+ sshd(?:\[\d+\])?: (?P<msg>.*)$')
SSH_PATTERNS = [
    (re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)'), "auth_failure"),
    (re.compile(r'Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+)'), "auth_success"),
    (re.compile(r'Invalid user (?P<user>\S+) from (?P<ip>\S+)'), "invalid_user"),
]


def _ev(source, event_type, ts, **kw):
    e = {"ts": ts, "source": source, "event_type": event_type, "src_ip": None, "username": None,
         "method": None, "path": None, "status": None, "user_agent": None, "extra": {}}
    e.update(kw)
    return e


def parse_nginx(line):
    m = NGINX_RE.match(line)
    if not m:
        return None
    ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    path = unquote_plus(unquote_plus(m["path"]))  # twice: catches double-encoded payloads
    user = None if m["user"] == "-" else m["user"]
    return _ev("nginx", "http_request", ts, src_ip=m["ip"], username=user, method=m["method"],
               path=path, status=int(m["status"]), user_agent=m["ua"])


def parse_ssh(line):
    m = SSH_SYSLOG.match(line)
    if m:
        now = datetime.now(timezone.utc)
        ts = datetime.strptime(f"{m['mon']} {m['day']} {m['time']} {now.year}", "%b %d %H:%M:%S %Y")
        ts = ts.replace(tzinfo=timezone.utc)
    else:
        m = SSH_ISO.match(line)
        if not m:
            return None
        ts = datetime.fromisoformat(m["ts"])
    for rx, etype in SSH_PATTERNS:
        hit = rx.search(m["msg"])
        if hit:
            return _ev("ssh", etype, ts, src_ip=hit["ip"], username=hit["user"])
    return None


def parse_app(line):
    """JSON lines: {"ts": "...", "event": "login_failed", "ip": "1.2.3.4", "user": "bob", ...}"""
    d = json.loads(line)
    ts = datetime.fromisoformat(d["ts"]) if d.get("ts") else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    extra = {k: v for k, v in d.items() if k not in ("ts", "event", "ip", "user")}
    return _ev("app", d.get("event", "unknown"), ts, src_ip=d.get("ip"), username=d.get("user"), extra=extra)


PARSERS = {"nginx": parse_nginx, "ssh": parse_ssh, "app": parse_app}


def parse_line(source, line):
    line = line.strip()
    fn = PARSERS.get(source)
    if not line or fn is None:
        return None
    try:
        ev = fn(line)
    except Exception:
        return None
    if ev:
        ev["raw"] = line[:2000]
    return ev
