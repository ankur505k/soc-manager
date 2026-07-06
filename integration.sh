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

trap 'echo; echo "Interrupted." >&2; exit 130' INT TERM

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
  $0 resync-all         Rebuild EVERY company's blocks from the database,
                         one at a time. Run this after any manual manager
                         edit/restore, or whenever you suspect drift
                         between companies.db and ossec.conf.
  $0 prune              Find soc-manager blocks on the manager whose slug
                         doesn't match ANY company currently in the
                         database (leftovers from an interrupted delete,
                         or a company removed some other way) and remove
                         them after confirmation.
EOF
    exit 1
}

[ $# -ge 1 ] || usage
ACTION="$1"

db_init || exit 1
wazuh_ready || { fail "No Wazuh manager detected (Docker or native)."; exit 1; }

if [ "$ACTION" = "resync-all" ]; then
    [ $# -eq 1 ] || usage
    fail_count=0
    total=0
    while IFS= read -r cname; do
        [ -z "$cname" ] && continue
        total=$((total + 1))
        slug="$(company_slug "$cname")"
        IFS='|' read -r id name server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$cname")"
        echo "-- Resyncing '$cname' (group: $slug) --"
        if mgr_sync_company_integrations "$slug" "$slack" "$tgbot" "$tgchat"; then
            ok "'$cname' matches the database."
            log "RESYNC-ALL company=$cname slug=$slug result=ok"
        else
            fail "'$cname' failed to resync — see $LOG_FILE."
            log "RESYNC-ALL company=$cname slug=$slug result=failed"
            fail_count=$((fail_count + 1))
        fi
    done < <(db_company_names)
    echo
    if [ "$fail_count" -eq 0 ]; then
        ok "Resynced $total compan$([ "$total" -eq 1 ] && echo y || echo ies) — all match the database."
        exit 0
    else
        fail "$fail_count of $total compan$([ "$total" -eq 1 ] && echo y || echo ies) failed to resync. See $LOG_FILE."
        exit 1
    fi
elif [ "$ACTION" = "prune" ]; then
    [ $# -eq 1 ] || usage
    mapfile -t live_slugs < <(mgr_list_marker_slugs)
    if [ "${#live_slugs[@]}" -eq 0 ]; then
        ok "No soc-manager integration blocks found on the manager at all."
        exit 0
    fi
    mapfile -t db_slugs < <(db_company_names | while IFS= read -r n; do [ -n "$n" ] && company_slug "$n"; done | sort -u)
    orphans=()
    for s in "${live_slugs[@]}"; do
        is_known=false
        for k in "${db_slugs[@]}"; do [ "$s" = "$k" ] && { is_known=true; break; }; done
        $is_known || orphans+=("$s")
    done
    if [ "${#orphans[@]}" -eq 0 ]; then
        ok "Every soc-manager block on the manager matches a company in the database. Nothing to prune."
        exit 0
    fi
    echo "Found ${#orphans[@]} orphaned slug(s) with soc-manager blocks but no matching company in the database:"
    printf '  - %s\n' "${orphans[@]}"
    read -r -p "Remove these blocks from the manager? [y/N]: " a
    if [[ ! "$a" =~ ^[Yy]$ ]]; then
        echo "Aborted — nothing changed."
        exit 0
    fi
    fail_count=0
    for s in "${orphans[@]}"; do
        echo "-- Removing orphaned blocks for '$s' --"
        if mgr_remove_company_integrations "$s"; then
            ok "Removed '$s'."
            log "PRUNE slug=$s result=ok"
        else
            fail "Could not fully remove '$s' — see $LOG_FILE."
            log "PRUNE slug=$s result=failed"
            fail_count=$((fail_count + 1))
        fi
    done
    [ "$fail_count" -eq 0 ] && exit 0 || exit 1
fi

[ $# -eq 2 ] || usage
COMPANY="$2"

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
