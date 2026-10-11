from contextlib import asynccontextmanager
from typing import Optional

import psycopg2.extras
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware

from .db import connect, init_schema


@asynccontextmanager
async def lifespan(app):
    conn = connect()
    init_schema(conn)
    conn.close()
    yield


app = FastAPI(title="mini-siem", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"], allow_headers=["*"])


def q(sql, params=()):
    conn = connect()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
            c.execute(sql, params)
            return c.fetchall()
    finally:
        conn.close()


@app.get("/api/events")
def events(limit: int = Query(100, le=1000), ip: Optional[str] = None, source: Optional[str] = None):
    return q("""SELECT id, ts, source, event_type, src_ip, username, method, path, status
                FROM events WHERE (%s::text IS NULL OR src_ip = %s) AND (%s::text IS NULL OR source = %s)
                ORDER BY ts DESC LIMIT %s""", (ip, ip, source, source, limit))


@app.get("/api/alerts")
def alerts(limit: int = Query(50, le=500)):
    return q("SELECT * FROM alerts ORDER BY ts DESC LIMIT %s", (limit,))


@app.get("/api/stats")
def stats(minutes: int = Query(60, le=1440)):
    return {
        "timeline": q("""SELECT date_trunc('minute', ts) AS t, count(*)::int AS events FROM events
                         WHERE ts > now() - make_interval(mins => %s) GROUP BY 1 ORDER BY 1""", (minutes,)),
        "top_ips": q("""SELECT src_ip, count(*)::int AS events FROM events
                        WHERE ts > now() - make_interval(mins => %s) AND src_ip IS NOT NULL
                        GROUP BY 1 ORDER BY 2 DESC LIMIT 10""", (minutes,)),
        "alerts_by_severity": q("""SELECT severity, count(*)::int AS alerts FROM alerts
                                   WHERE ts > now() - make_interval(mins => %s) GROUP BY 1""", (minutes,)),
        "alerts_by_rule": q("""SELECT rule_id, count(*)::int AS alerts FROM alerts
                               WHERE ts > now() - make_interval(mins => %s) GROUP BY 1 ORDER BY 2 DESC""", (minutes,)),
    }
