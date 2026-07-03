CREATE TABLE IF NOT EXISTS companies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name   TEXT NOT NULL UNIQUE,
    server_name    TEXT NOT NULL,
    host           TEXT NOT NULL,
    ssh_user       TEXT NOT NULL DEFAULT 'root',
    ssh_port       INTEGER NOT NULL DEFAULT 22,
    slack_webhook  TEXT,
    telegram_bot   TEXT,
    telegram_chat  TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    last_updated   TEXT
);

CREATE INDEX IF NOT EXISTS idx_companies_status ON companies(status);
