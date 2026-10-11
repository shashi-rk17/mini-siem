#!/usr/bin/env python3
"""Append fake attack traffic to ./logs so you can demo detections without DVWA.
usage: python scripts/attack_sim.py {ssh|weblogin|scan|sqli|xss|traversal|vault|all} [--ip 203.0.113.7]"""
import argparse
import json
import time
from datetime import datetime, timezone
from pathlib import Path

LOGS = Path(__file__).resolve().parent.parent / "logs"


def w(file, line):
    p = LOGS / file
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as f:
        f.write(line + "\n")


def nginx(ip, method, path, status):
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    w("nginx/access.log", f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} 512 "-" "sim/1.0"')


def run(mode, ip):
    if mode == "ssh":
        for u in ["root", "admin", "ubuntu", "test", "oracle", "pi", "git"]:
            ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
            w("auth.log", f"{ts} host sshd[999]: Failed password for invalid user {u} from {ip} port 4242 ssh2")
            time.sleep(0.2)
    elif mode == "weblogin":
        for i in range(12):
            nginx(ip, "POST", "/login.php", 302); time.sleep(0.1)
    elif mode == "scan":
        for p in range(25):
            nginx(ip, "GET", f"/admin{p}.php", 404); time.sleep(0.05)
    elif mode == "sqli":
        nginx(ip, "GET", "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+user,password+FROM+users--&Submit=Submit", 200)
    elif mode == "xss":
        nginx(ip, "GET", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200)
    elif mode == "traversal":
        nginx(ip, "GET", "/download?file=../../../../etc/passwd", 200)
    elif mode == "vault":
        for i in range(6):
            w("app.log", json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "event": "login_failed",
                                     "ip": ip, "user": "shashi"}))
            time.sleep(0.2)
    elif mode == "all":
        for m in ["ssh", "weblogin", "scan", "sqli", "xss", "traversal", "vault"]:
            run(m, ip)
    print("sent:", mode)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["ssh", "weblogin", "scan", "sqli", "xss", "traversal", "vault", "all"])
    ap.add_argument("--ip", default="203.0.113.7")
    a = ap.parse_args()
    run(a.mode, a.ip)
