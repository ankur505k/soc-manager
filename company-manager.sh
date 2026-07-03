#!/bin/bash
# company-manager.sh — main interactive menu for the SOC manager.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
LOCK_FILE="/var/run/soc-manager.lock"

source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/ssh.sh"
source "$MANAGER_HOME/lib/config.sh"
source "$MANAGER_HOME/lib/wazuh_integration.sh"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"
ok() { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
pause() { echo; read -r -p "Press Enter to continue..." _; }
confirm() { read -r -p "$1 [y/N]: " a; [[ "$a" =~ ^[Yy]$ ]]; }
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [menu] $1" >> "$LOG_FILE"; }

trap 'echo; warn "Interrupted."; rm -f "$LOCK_FILE"; exit 130' INT TERM
trap 'rm -f "$LOCK_FILE"' EXIT

root_check() {
    if [ "$EUID" -ne 0 ]; then
        echo "Run as root: sudo $0"
        exit 1
    fi
}

acquire_lock() {
    if [ -f "$LOCK_FILE" ]; then
        local pid; pid="$(cat "$LOCK_FILE" 2>/dev/null || echo "")"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            fail "Another instance is already running (PID $pid)."
            exit 1
        fi
    fi
    echo $$ > "$LOCK_FILE"
}

require_wazuh_manager() {
    if [ ! -d /var/ossec ] || [ ! -x /var/ossec/bin/agent_groups ]; then
        fail "This doesn't look like a Wazuh manager host (no /var/ossec/bin/agent_groups)."
        echo "company-manager.sh must run on the Wazuh manager itself — see README."
        exit 1
    fi
}

add_company() {
    clear
    echo "========= ADD COMPANY ========="
    echo

    local name
    read -r -p "Company name (letters/numbers/-/_, 2-40 chars): " name
    if ! validate_company_name "$name"; then
        fail "Invalid company name."
        pause; return
    fi
    if db_company_exists "$name"; then
        fail "Company '$name' already exists."
        pause; return
    fi
    local slug; slug="$(company_slug "$name")"

    local server_name host user port
    read -r -p "Server label (e.g. Delhi01): " server_name
    read -r -p "Server IP or hostname: " host
    if ! validate_host "$host"; then fail "Invalid host."; pause; return; fi
    read -r -p "SSH user [root]: " user; user="${user:-root}"
    if ! validate_ssh_user "$user"; then fail "Invalid SSH user."; pause; return; fi
    read -r -p "SSH port [22]: " port; port="${port:-22}"
    if ! validate_ssh_port "$port"; then fail "Invalid SSH port."; pause; return; fi

    local slack tgbot tgchat
    read -r -p "Slack webhook URL (blank to skip): " slack
    if ! validate_slack_webhook "$slack"; then fail "Invalid Slack webhook."; pause; return; fi
    read -r -p "Telegram bot token (blank to skip): " tgbot
    if ! validate_telegram_bot "$tgbot"; then fail "Invalid Telegram bot token."; pause; return; fi
    read -r -p "Telegram chat ID (blank to skip): " tgchat
    if ! validate_telegram_chat "$tgchat"; then fail "Invalid Telegram chat ID."; pause; return; fi
    if [ -n "$tgbot" ] && [ -z "$tgchat" ]; then fail "Telegram bot token given without a chat ID."; pause; return; fi
    if [ -z "$tgbot" ] && [ -n "$tgchat" ]; then fail "Telegram chat ID given without a bot token."; pause; return; fi

    db_add_company "$name" "$server_name" "$host" "$user" "$port" "$slack" "$tgbot" "$tgchat"
    ok "Company '$name' added to database."

    info "Creating Wazuh agent group '$slug' on this manager..."
    if mgr_create_group "$slug"; then
        ok "Group '$slug' ready."
    else
        fail "Could not create group '$slug'. Check $LOG_FILE."
        pause; return
    fi

    if [ -n "$slack" ] || [ -n "$tgbot" ]; then
        info "Registering notification routing on the manager (this restarts wazuh-manager)..."
        if mgr_sync_company_integrations "$slug" "$slack" "$tgbot" "$tgchat"; then
            ok "Notification routing configured for '$name'."
        else
            fail "Failed to configure notification routing. See $LOG_FILE."
        fi
    fi

    log "ADD company=$name slug=$slug host=$host"
    echo
    echo "Next step: run client-setup.sh on $host. See:"
    echo "  ./deploy.sh \"$name\""
    pause
}

update_company() {
    clear
    echo "========= UPDATE COMPANY ========="
    list_companies_table
    echo
    local name
    read -r -p "Company name to update: " name
    if ! db_company_exists "$name"; then fail "No such company."; pause; return; fi
    local slug; slug="$(company_slug "$name")"

    IFS='|' read -r id cname server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$name")"

    echo "1) Server IP/host        [current: $host]"
    echo "2) SSH user               [current: $user]"
    echo "3) SSH port               [current: $port]"
    echo "4) Slack webhook          [current: $(mask "$slack")]"
    echo "5) Telegram bot token     [current: $(mask "$tgbot")]"
    echo "6) Telegram chat ID       [current: ${tgchat:-none}]"
    echo "0) Back"
    read -r -p "Field to update: " f

    case "$f" in
        1) read -r -p "New host: " v; validate_host "$v" && db_update_field "$name" host "$v" || fail "Invalid host." ;;
        2) read -r -p "New SSH user: " v; validate_ssh_user "$v" && db_update_field "$name" ssh_user "$v" || fail "Invalid user." ;;
        3) read -r -p "New SSH port: " v; validate_ssh_port "$v" && db_update_field "$name" ssh_port "$v" || fail "Invalid port." ;;
        4)
            read -r -p "New Slack webhook (blank to remove): " v
            if validate_slack_webhook "$v"; then
                db_update_field "$name" slack_webhook "$v"
                sync_after_change "$name" "$slug"
            else
                fail "Invalid webhook."
            fi
            ;;
        5)
            read -r -p "New Telegram bot token (blank to remove): " v
            if validate_telegram_bot "$v"; then
                db_update_field "$name" telegram_bot "$v"
                sync_after_change "$name" "$slug"
            else
                fail "Invalid bot token."
            fi
            ;;
        6)
            read -r -p "New Telegram chat ID (blank to remove): " v
            if validate_telegram_chat "$v"; then
                db_update_field "$name" telegram_chat "$v"
                sync_after_change "$name" "$slug"
            else
                fail "Invalid chat ID."
            fi
            ;;
        0) return ;;
        *) warn "Invalid option." ;;
    esac
    pause
}

sync_after_change() {
    local name="$1" slug="$2"
    IFS='|' read -r id cname server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$name")"
    info "Updating notification routing on the manager..."
    if mgr_sync_company_integrations "$slug" "$slack" "$tgbot" "$tgchat"; then
        ok "Routing updated for '$name'."
    else
        fail "Failed to update routing. See $LOG_FILE."
    fi
}

mask() {
    local s="$1"; local len=${#s}
    [ -z "$s" ] && { echo "none"; return; }
    [ "$len" -le 8 ] && { echo "****"; return; }
    echo "${s:0:4}...${s: -4}"
}

delete_company() {
    clear
    echo "========= DELETE COMPANY ========="
    list_companies_table
    echo
    local name
    read -r -p "Company name to delete: " name
    if ! db_company_exists "$name"; then fail "No such company."; pause; return; fi
    local slug; slug="$(company_slug "$name")"

    if ! confirm "Delete '$name'? This removes it from the database and its manager-side notification routing."; then
        pause; return
    fi

    mgr_remove_company_integrations "$slug" || warn "Could not cleanly remove integration blocks — check $LOG_FILE."
    mgr_delete_group "$slug" || warn "Could not remove agent group '$slug'."
    db_delete_company "$name"
    ok "Deleted '$name'."
    log "DELETE company=$name slug=$slug"
    pause
}

list_companies_table() {
    echo
    printf "%-24s %-16s %-18s %-6s %-10s %s\n" "COMPANY" "SERVER" "HOST" "PORT" "STATUS" "LAST UPDATED"
    printf '%.0s-' {1..100}; echo
    while IFS='|' read -r cname server_name host port status last_updated; do
        [ -z "$cname" ] && continue
        printf "%-24s %-16s %-18s %-6s %-10s %s\n" "$cname" "$server_name" "$host" "$port" "$status" "$last_updated"
    done < <(db_list_companies)
}

menu() {
    while true; do
        clear
        echo "===================================="
        echo "        SOC MANAGEMENT"
        echo "===================================="
        echo "1  Add Company"
        echo "2  Update Company"
        echo "3  Delete Company"
        echo "4  List Companies"
        echo "5  Test Connection (SSH/agent health)"
        echo "6  Check / Complete Enrollment"
        echo "7  Test Alert (Slack/Telegram credentials)"
        echo "0  Exit"
        echo "===================================="
        read -r -p "Select: " op

        case "$op" in
            1) add_company ;;
            2) update_company ;;
            3) delete_company ;;
            4) list_companies_table; pause ;;
            5) read -r -p "Company name: " n; "$MANAGER_HOME/verify.sh" "$n"; pause ;;
            6) read -r -p "Company name: " n; "$MANAGER_HOME/deploy.sh" "$n"; pause ;;
            7) read -r -p "Company name: " n; "$MANAGER_HOME/test-alert.sh" "$n"; pause ;;
            0) echo "Goodbye."; exit 0 ;;
            *) warn "Invalid option."; sleep 1 ;;
        esac
    done
}

main() {
    root_check
    require_wazuh_manager
    ssh_require || exit 1
    mkdir -p "$MANAGER_HOME/logs" "$MANAGER_HOME/backup"
    touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
    acquire_lock
    db_init || exit 1
    menu
}

main "$@"
