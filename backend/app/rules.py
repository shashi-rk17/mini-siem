"""Rules engine: YAML rules + Redis sliding-window counters (sorted sets)."""
import re
import uuid

import yaml

from .config import ALERT_COOLDOWN


def load_rules(path):
    with open(path) as f:
        return yaml.safe_load(f)["rules"]


def _match(event, cond):
    for field, want in cond.items():
        val = event.get(field)
        if isinstance(want, dict):
            if "regex" in want:
                if val is None or not re.search(want["regex"], str(val), re.I):
                    return False
            if "gte" in want and (val is None or val < want["gte"]):
                return False
        elif isinstance(want, list):
            if val not in want:
                return False
        elif val != want:
            return False
    return True


class Engine:
    def __init__(self, rules, redis_client):
        self.rules = rules
        self.r = redis_client

    def evaluate(self, event):
        alerts = []
        for rule in self.rules:
            if not _match(event, rule["match"]):
                continue
            key = event.get(rule.get("group_by", "src_ip")) or "unknown"
            window = int(rule.get("window", 60))
            threshold = int(rule.get("threshold", 1))
            ts = event["ts"].timestamp()

            zkey = f"win:{rule['id']}:{key}"
            pipe = self.r.pipeline()
            pipe.zremrangebyscore(zkey, 0, ts - window)   # drop events outside the window
            pipe.zadd(zkey, {uuid.uuid4().hex: ts})       # add this event
            pipe.zcard(zkey)                              # count what's left
            pipe.expire(zkey, window * 2)
            count = pipe.execute()[2]
            if count < threshold:
                continue

            cooldown = int(rule.get("cooldown", ALERT_COOLDOWN))
            if not self.r.set(f"cd:{rule['id']}:{key}", 1, nx=True, ex=cooldown):
                continue  # already alerted recently for this rule + key

            alerts.append({
                "ts": event["ts"], "rule_id": rule["id"], "severity": rule.get("severity", "medium"),
                "description": rule.get("description", rule["id"]),
                "group_key": f"{rule.get('group_by', 'src_ip')}={key}",
                "count": count, "window_s": window,
                "sample": {"path": event.get("path"), "username": event.get("username"), "raw": event.get("raw")},
            })
        return alerts
