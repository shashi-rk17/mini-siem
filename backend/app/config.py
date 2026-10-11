import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://siem:siem@localhost:5432/siem")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# "source:path,source:path" e.g. nginx:/logs/nginx/access.log,ssh:/logs/auth.log
LOG_SOURCES = os.getenv("LOG_SOURCES", "")
FROM_START = os.getenv("FROM_START", "0") == "1"
RULES_FILE = os.getenv("RULES_FILE", "rules/rules.yml")
ALERT_COOLDOWN = int(os.getenv("ALERT_COOLDOWN", "120"))
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
