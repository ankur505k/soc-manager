#!/bin/bash
# integration.sh — manual CLI for a company's manager-side <integration>
# blocks. company-manager.sh calls the same lib/wazuh_integration.sh
# functions automatically on Add/Update/Delete; this exists for re-syncing
# by hand (e.g. after a manual manager restore, or to debug drift) without
# going through the full interactive menu.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/lock.sh"
source "$MANAGER_HOME/lib/preflight.sh"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/config.sh"
source "$MANAGER_HOME/lib/docker.sh"
source "$MANAGER_HOME/lib/wazuh_integration.sh"

LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [integration] $1" >> "$LOG_FILE"; }

preflight_check || exit 1
soc_acquire_lock || exit 1

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

usage() {
    cat >&2 <<EOF
Usage:
  $0 sync <company>     Rebuild this company's Slack/Telegram <integration>
                         blocks on the manager from current DB values.
  $0 remove <company>   Remove this company's <integration> blocks (does
                         NOT delete the company from the database or its
                         agent group — use company-manager.sh for that).
  $0 status <company>   Show whether Slack/Telegram blocks are present.
EOF
    exit 1
}

[ $# -eq 2 ] || usage
ACTION="$1"
COMPANY="$2"

db_init || exit 1
wazuh_ready || { fail "No Wazuh manager detected (Docker or native)."; exit 1; }

if ! db_company_exists "$COMPANY"; then
    fail "No such company: $COMPANY"
    exit 1
fi

SLUG="$(company_slug "$COMPANY")"

case "$ACTION" in
    sync)
        IFS='|' read -r id name server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$COMPANY")"
        if mgr_sync_company_integrations "$SLUG" "$slack" "$tgbot" "$tgchat"; then
            ok "Synced integration blocks for '$COMPANY' (group: $SLUG)."
            log "SYNC company=$COMPANY slug=$SLUG"
        else
            fail "Sync failed. See $LOG_FILE."
            exit 1
        fi
        ;;
    remove)
        if mgr_remove_company_integrations "$SLUG"; then
            ok "Removed integration blocks for '$COMPANY' (group: $SLUG)."
            log "REMOVE-INTEGRATIONS company=$COMPANY slug=$SLUG"
        else
            fail "Removal failed. See $LOG_FILE."
            exit 1
        fi
        ;;
    status)
        if mgr_integration_block_present "$(printf '<!-- soc-manager:integration:slack:%s -->' "$SLUG")"; then
            ok "Slack integration block present for '$COMPANY'."
        else
            warn "No Slack integration block for '$COMPANY'."
        fi
        if mgr_integration_block_present "$(printf '<!-- soc-manager:integration:telegram:%s -->' "$SLUG")"; then
            ok "Telegram integration block present for '$COMPANY'."
        else
            warn "No Telegram integration block for '$COMPANY'."
        fi
        ;;
    *)
        usage
        ;;
esac
