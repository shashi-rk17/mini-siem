from datetime import datetime, timezone

import fakeredis

from app.parsers import parse_line
from app.rules import Engine, load_rules

NOW = datetime.now(timezone.utc)
NGINX_TS = NOW.strftime("%d/%b/%Y:%H:%M:%S +0000")
SSH_TS = NOW.strftime("%b %d %H:%M:%S")


def engine():
    return Engine(load_rules("rules/rules.yml"), fakeredis.FakeRedis(decode_responses=True))


def nginx(path, status=200, method="GET", ip="1.2.3.4"):
    return f'{ip} - - [{NGINX_TS}] "{method} {path} HTTP/1.1" {status} 512 "-" "curl/8"'


def test_parse_nginx_decodes_path():
    ev = parse_line("nginx", nginx("/a?id=1%27+or+1%3D1"))
    assert ev["src_ip"] == "1.2.3.4" and ev["status"] == 200 and "or 1=1" in ev["path"]


def test_parse_ssh_and_app():
    ev = parse_line("ssh", f"{SSH_TS} host sshd[1]: Failed password for invalid user admin from 9.9.9.9 port 22 ssh2")
    assert ev["event_type"] == "auth_failure" and ev["src_ip"] == "9.9.9.9" and ev["username"] == "admin"
    ev = parse_line("app", '{"event":"login_failed","ip":"5.5.5.5","user":"bob"}')
    assert ev["event_type"] == "login_failed" and ev["username"] == "bob"


def test_ssh_bruteforce_triggers_once():
    e = engine()
    line = f"{SSH_TS} host sshd[1]: Failed password for root from 9.9.9.9 port 22 ssh2"
    fired = [e.evaluate(parse_line("ssh", line)) for _ in range(7)]
    assert [len(f) for f in fired] == [0, 0, 0, 0, 1, 0, 0]  # 5th hit alerts, cooldown silences the rest


def test_sqli_xss_traversal_single_hit():
    e = engine()
    for path, rule in [("/p?id=1+UNION+SELECT+1,2", "sqli_attempt"),
                       ("/s?q=<script>alert(1)</script>", "xss_attempt"),
                       ("/f?file=../../etc/passwd", "path_traversal")]:
        ids = [a["rule_id"] for a in e.evaluate(parse_line("nginx", nginx(path)))]
        assert rule in ids


def test_benign_request_is_quiet():
    assert engine().evaluate(parse_line("nginx", nginx("/index.html"))) == []
