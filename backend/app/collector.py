"""Tails log files (watchdog), parses lines, stores events, runs rules, sends alerts."""
import os
import threading
import time
from pathlib import Path

import redis
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver  # polling works on Docker bind mounts everywhere

from . import config
from .alerts import notify
from .db import connect, init_schema, insert_alert, insert_event
from .parsers import parse_line
from .rules import Engine, load_rules


class Tailer(FileSystemEventHandler):
    def __init__(self, source, path, on_event):
        self.source, self.path, self.on_event = source, os.path.abspath(path), on_event
        self.lock = threading.Lock()
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        Path(self.path).touch(exist_ok=True)
        self.offset = 0 if config.FROM_START else os.path.getsize(self.path)

    def on_any_event(self, ev):
        if not ev.is_directory and os.path.abspath(ev.src_path) == self.path:
            self.read_new()

    def read_new(self):
        with self.lock:
            size = os.path.getsize(self.path)
            if size < self.offset:  # truncated / rotated
                self.offset = 0
            with open(self.path, "rb") as f:
                f.seek(self.offset)
                data = f.read()
            end = data.rfind(b"\n")
            if end == -1:
                return  # no complete line yet
            self.offset += end + 1
            for raw in data[:end].decode("utf-8", "replace").splitlines():
                ev = parse_line(self.source, raw)
                if ev:
                    self.on_event(ev)


def main():
    conn = connect()
    init_schema(conn)
    engine = Engine(load_rules(config.RULES_FILE), redis.from_url(config.REDIS_URL, decode_responses=True))

    def handle(ev):
        insert_event(conn, ev)
        for a in engine.evaluate(ev):
            insert_alert(conn, a)
            notify(a)

    observer = PollingObserver(timeout=1)
    for spec in filter(None, config.LOG_SOURCES.split(",")):
        source, path = spec.split(":", 1)
        tailer = Tailer(source.strip(), path.strip(), handle)
        observer.schedule(tailer, os.path.dirname(tailer.path), recursive=False)
        print(f"tailing {source} -> {tailer.path}", flush=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()


if __name__ == "__main__":
    main()
