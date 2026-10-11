import time

import psycopg2
from psycopg2.extras import Json

from .config import DATABASE_URL

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  source TEXT NOT NULL,
  event_type TEXT NOT NULL,
  src_ip TEXT, username TEXT, method TEXT, path TEXT, status INT, user_agent TEXT,
  raw TEXT, extra JSONB DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events (src_ip);
CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL,
  rule_id TEXT NOT NULL, severity TEXT NOT NULL, description TEXT,
  group_key TEXT, count INT, window_s INT, sample JSONB
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts DESC);
"""


def connect(retries=30):
    for _ in range(retries):
        try:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            return conn
        except psycopg2.OperationalError:
            time.sleep(1)
    raise RuntimeError("postgres not reachable")


def init_schema(conn):
    with conn.cursor() as c:
        c.execute("SELECT pg_advisory_lock(42)")  # collector and api may start together
        c.execute(SCHEMA)
        c.execute("SELECT pg_advisory_unlock(42)")


def insert_event(conn, e):
    e = {**e, "extra": Json(e.get("extra") or {})}
    with conn.cursor() as c:
        c.execute("""INSERT INTO events (ts,source,event_type,src_ip,username,method,path,status,user_agent,raw,extra)
                     VALUES (%(ts)s,%(source)s,%(event_type)s,%(src_ip)s,%(username)s,%(method)s,%(path)s,
                             %(status)s,%(user_agent)s,%(raw)s,%(extra)s)""", e)


def insert_alert(conn, a):
    a = {**a, "sample": Json(a["sample"])}
    with conn.cursor() as c:
        c.execute("""INSERT INTO alerts (ts,rule_id,severity,description,group_key,count,window_s,sample)
                     VALUES (%(ts)s,%(rule_id)s,%(severity)s,%(description)s,%(group_key)s,%(count)s,
                             %(window_s)s,%(sample)s)""", a)
