#!/bin/bash
# lib/database.sh — SQLite helpers for companies.db
# Sourced by other scripts; do not execute directly.

DB_FILE="${DB_FILE:-$MANAGER_HOME/companies.db}"
SCHEMA_FILE="${SCHEMA_FILE:-$MANAGER_HOME/schema.sql}"

db_require() {
    if ! command -v sqlite3 >/dev/null 2>&1; then
        echo "sqlite3 is not installed. Install it with: dnf install -y sqlite  (or apt install sqlite3)" >&2
        return 1
    fi
}

db_init() {
    db_require || return 1
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

db_query() {
    # Runs an arbitrary read query and prints pipe-delimited rows.
    sqlite3 -separator '|' "$DB_FILE" "$1"
}

db_exec() {
    sqlite3 "$DB_FILE" "$1"
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
    slack="$(sql_escape "${6:-}")"; tgbot="$(sql_escape "${7:-}")"; tgchat="$(sql_escape "${8:-}")"

    db_exec "INSERT INTO companies
        (company_name, server_name, host, ssh_user, ssh_port, slack_webhook, telegram_bot, telegram_chat, status, last_updated)
        VALUES ('${name}','${server_name}','${host}','${user}',${port},'${slack}','${tgbot}','${tgchat}','pending', datetime('now'));"
}

db_update_field() {
    # $1 name $2 column $3 value
    local name col val esc_name esc_val
    name="$1"; col="$2"; val="$3"
    esc_name="$(sql_escape "$name")"
    esc_val="$(sql_escape "$val")"

    case "$col" in
        ssh_port) db_exec "UPDATE companies SET ssh_port=${val}, last_updated=datetime('now') WHERE company_name='${esc_name}';" ;;
        *)        db_exec "UPDATE companies SET ${col}='${esc_val}', last_updated=datetime('now') WHERE company_name='${esc_name}';" ;;
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
    local name esc
    name="$1"
    esc="$(sql_escape "$name")"
    db_query "SELECT id, company_name, server_name, host, ssh_user, ssh_port, slack_webhook, telegram_bot, telegram_chat, status, last_updated
              FROM companies WHERE company_name='${esc}' LIMIT 1;"
}

db_list_companies() {
    db_query "SELECT company_name, server_name, host, ssh_port, status, last_updated FROM companies ORDER BY company_name;"
}

db_company_names() {
    db_query "SELECT company_name FROM companies ORDER BY company_name;"
}
