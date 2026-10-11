import threading

import requests

from .config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID


def _send_telegram(text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    for attempt in range(3):
        try:
            r = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=(5, 20))
            if not r.ok:
                print("telegram error:", r.status_code, r.text, flush=True)
            return
        except requests.RequestException as e:
            print(f"telegram attempt {attempt + 1} failed: {e}", flush=True)


def notify(alert):
    text = (f"[{alert['severity'].upper()}] {alert['rule_id']}\n{alert['description']}\n"
            f"{alert['group_key']}  |  {alert['count']} hits / {alert['window_s']}s")
    print("ALERT>", text.replace("\n", " | "), flush=True)
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    threading.Thread(target=_send_telegram, args=(text,), daemon=True).start()