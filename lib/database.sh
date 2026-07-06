#!/bin/bash
# lib/database.sh — SQLite helpers for companies.db
# Sourced by other scripts; do not execute directly.

DB_FILE="${DB_FILE:-$MANAGER_HOME/companies.db}"
SCHEMA_FILE="${SCHEMA_FILE:-$MANAGER_HOME/schema.sql}"

# shellcheck source=lib/secrets.sh
source "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"

db_require() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "sqlite3 is not installed. Install it with: dnf install -y sqlite  (or apt install sqlite3)" >&2
        return 1
    fi
}

db_init() {
    db_require || return 1
    secrets_init || echo "Warning: openssl not available — Slack/Telegram credentials will be stored in plaintext." >&2
    if [ ! -f "$DB_FILE" ]; then
        sqlite3 "$DB_FILE" < "$SCHEMA_FILE"
        chmod 600 "$DB_FILE"
    fi
}

# sql_escape: double single-quotes so user input can't break out of the
# SQL string literal it's placed in (basic SQL-injection guard — this is
# a local admin tool, not internet-facing, but inputs are still untrusted
# free text).
sql_escape() {
    printf '%s' "$1" | sed "s/'/''/g"
}

# Every read/write against companies.db goes through db_query/db_exec, and
# both take a real flock (not the caller-level soc-manager.lock, which
# only the interactive menu/integration.sh/rollback.sh hold) — one-shot
# scripts like deploy.sh call db_set_status without ever taking that
# session lock, so without a lock at this layer two of those running back
# to back could still interleave writes.
DB_LOCK_FILE="${DB_LOCK_FILE:-$MANAGER_HOME/.companies.db.lock}"
DB_LOCK_FD=201
DB_LOCK_WAIT="${DB_LOCK_WAIT:-15}"

_db_locked() {
    # Runs "$@" (a single sqlite3 invocation) under an exclusive flock,
    # held only for the duration of that one call. busy_timeout is set as
    # a second line of defense in case something outside soc-manager
    # (a manual `sqlite3 companies.db` session) is also touching the file.
    eval "exec ${DB_LOCK_FD}>\"\$DB_LOCK_FILE\"" 2>/dev/null || {
        echo "Could not open database lock file $DB_LOCK_FILE" >&2
        return 1
    }
    if ! flock -w "$DB_LOCK_WAIT" -x "$DB_LOCK_FD"; then
        echo "Could not acquire the database lock within ${DB_LOCK_WAIT}s — another soc-manager process may be stuck." >&2
        eval "exec ${DB_LOCK_FD}>&- 2>/dev/null"
        return 1
    fi
    "$@"
    local rc=$?
    flock -u "$DB_LOCK_FD" 2>/dev/null
    eval "exec ${DB_LOCK_FD}>&- 2>/dev/null"
    return $rc
}

_db_query_raw() {
    sqlite3 -cmd "PRAGMA busy_timeout=5000;" -separator '|' "$DB_FILE" "$1"
}

_db_exec_raw() {
    sqlite3 -cmd "PRAGMA busy_timeout=5000;" "$DB_FILE" "$1"
}

db_query() {
    # Runs an arbitrary read query and prints pipe-delimited rows.
    _db_locked _db_query_raw "$1"
}

db_exec() {
    _db_locked _db_exec_raw "$1"
}

# db_transaction <sql_statements...>: runs multiple statements as a single
# atomic BEGIN/COMMIT unit under the same lock as everything else, for
# callers that need more than one statement to succeed-or-fail together.
# (Most soc-manager writes are a single UPDATE/INSERT, which SQLite already
# makes atomic on its own — this is for the few call sites that aren't.)
db_transaction() {
    local sql="BEGIN IMMEDIATE; $1 COMMIT;"
    _db_locked _db_exec_raw "$sql"
}

db_company_exists() {
    local name esc count
    name="$1"
    esc="$(sql_escape "$name")"
    count="$(db_query "SELECT COUNT(*) FROM companies WHERE company_name = '${esc}';")"
    [ "$count" -gt 0 ]
}

db_add_company() {
    # $1 name $2 server_name $3 host $4 ssh_user $5 ssh_port
    # $6 slack_webhook $7 telegram_bot $8 telegram_chat
    local name server_name host user port slack tgbot tgchat
    name="$(sql_escape "$1")"; server_name="$(sql_escape "$2")"; host="$(sql_escape "$3")"
    user="$(sql_escape "$4")"; port="$5"
    slack="$(sql_escape "$(secrets_encrypt "${6:-}")")"
    tgbot="$(sql_escape "$(secrets_encrypt "${7:-}")")"
    tgchat="$(sql_escape "$(secrets_encrypt "${8:-}")")"

    db_exec "INSERT INTO companies
        (company_name, server_name, host, ssh_user, ssh_port, slack_webhook, telegram_bot, telegram_chat, status, last_updated)
        VALUES ('${name}','${server_name}','${host}','${user}',${port},'${slack}','${tgbot}','${tgchat}','pending', datetime('now'));"
}

db_update_field() {
    # $1 name $2 column $3 value
    local name col val esc_name esc_val
    name="$1"; col="$2"; val="$3"
    esc_name="$(sql_escape "$name")"

    case "$col" in
        ssh_port)
            db_exec "UPDATE companies SET ssh_port=${val}, last_updated=datetime('now') WHERE company_name='${esc_name}';"
            ;;
        slack_webhook|telegram_bot|telegram_chat)
            esc_val="$(sql_escape "$(secrets_encrypt "$val")")"
            db_exec "UPDATE companies SET ${col}='${esc_val}', last_updated=datetime('now') WHERE company_name='${esc_name}';"
            ;;
        *)
            esc_val="$(sql_escape "$val")"
            db_exec "UPDATE companies SET ${col}='${esc_val}', last_updated=datetime('now') WHERE company_name='${esc_name}';"
            ;;
    esac
}

db_set_status() {
    local name status esc_name esc_status
    name="$1"; status="$2"
    esc_name="$(sql_escape "$name")"
    esc_status="$(sql_escape "$status")"
    db_exec "UPDATE companies SET status='${esc_status}', last_updated=datetime('now') WHERE company_name='${esc_name}';"
}

db_delete_company() {
    local name esc
    name="$1"
    esc="$(sql_escape "$name")"
    db_exec "DELETE FROM companies WHERE company_name='${esc}';"
}

db_get_company() {
    # Prints: id|company_name|server_name|host|ssh_user|ssh_port|slack_webhook|telegram_bot|telegram_chat|status|last_updated
    # (slack_webhook/telegram_bot/telegram_chat are decrypted here, so
    # every caller of db_get_company automatically gets plaintext back
    # without needing to know about secrets.sh.)
    local name esc row
    name="$1"
    esc="$(sql_escape "$name")"
    row="$(db_query "SELECT id, company_name, server_name, host, ssh_user, ssh_port, slack_webhook, telegram_bot, telegram_chat, status, last_updated
              FROM companies WHERE company_name='${esc}' LIMIT 1;")"
    [ -z "$row" ] && return 0

    local id cname server_name host user port slack tgbot tgchat status last_updated
    IFS='|' read -r id cname server_name host user port slack tgbot tgchat status last_updated <<< "$row"
    slack="$(secrets_decrypt "$slack")"
    tgbot="$(secrets_decrypt "$tgbot")"
    tgchat="$(secrets_decrypt "$tgchat")"
    printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$id" "$cname" "$server_name" "$host" "$user" "$port" "$slack" "$tgbot" "$tgchat" "$status" "$last_updated"
}

db_list_companies() {
    db_query "SELECT company_name, server_name, host, ssh_port, status, last_updated FROM companies ORDER BY company_name;"
}

db_company_names() {
    db_query "SELECT company_name FROM companies ORDER BY company_name;"
}

# db_slug_collision <slug>: true if any EXISTING company already normalizes
# to this same Wazuh agent-group slug. company_name is stored verbatim and
# is only case-insensitively unique (see schema.sql), but two differently
# punctuated names — "Acme Corp" and "Acme-Corp" — can still both slugify
# to "acme-corp" via company_slug() and silently share one agent group.
# Requires company_slug() (lib/config.sh) to already be sourced.
db_slug_collision() {
    local new_slug="$1" existing
    while IFS= read -r existing; do
        [ -z "$existing" ] && continue
        if [ "$(company_slug "$existing")" = "$new_slug" ]; then
            echo "$existing"
            return 0
        fi
    done < <(db_company_names)
    return 1
}
