PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS companies (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    -- COLLATE NOCASE: "Acme" and "acme" are the same company as far as
    -- the DB is concerned, since they'd otherwise collide on the same
    -- lowercased Wazuh agent-group slug (see lib/config.sh company_slug).
    company_name   TEXT NOT NULL UNIQUE COLLATE NOCASE,
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
