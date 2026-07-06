#!/bin/bash
# fim.sh — manual CLI for a company's VICIdial + AlmaLinux FIM (syscheck)
# config. company-manager.sh pushes this automatically when a company is
# added (see add_company in company-manager.sh); this exists to backfill
# companies that already existed before this feature, or to re-push/debug
# by hand.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/lock.sh"
source "$MANAGER_HOME/lib/preflight.sh"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/config.sh"
source "$MANAGER_HOME/lib/docker.sh"
source "$MANAGER_HOME/lib/ssh.sh"
source "$MANAGER_HOME/lib/wazuh_integration.sh"
source "$MANAGER_HOME/lib/fim.sh"

LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [fim] $1" >> "$LOG_FILE"; }

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
  $0 push <company>     Push/refresh this company's FIM agent.conf on the
                         manager, then restart its agent over SSH so the
                         new rules apply immediately (falls back silently
                         to "will apply on next sync" if SSH isn't up yet).
  $0 remove <company>   Delete this company's FIM agent.conf from the
                         manager's shared group folder.
  $0 push-all           Push/refresh FIM for EVERY company in the
                         database. Use this once to backfill companies
                         that were added before this feature existed.
EOF
    exit 1
}

[ $# -ge 1 ] || usage
ACTION="$1"

db_init || exit 1
wazuh_ready || { fail "No Wazuh manager detected (Docker or native)."; exit 1; }

push_one() {
    local cname="$1" slug host user port
    slug="$(company_slug "$cname")"
    IFS='|' read -r _id _name _server_name host user port _slack _tgbot _tgchat _status _last_updated <<< "$(db_get_company "$cname")"

    if ! mgr_sync_company_fim "$slug"; then
        fail "'$cname': could not push FIM config. See $LOG_FILE."
        log "FIM-PUSH company=$cname slug=$slug result=failed"
        return 1
    fi
    ok "'$cname': FIM config pushed to manager (group: $slug)."

    if fim_restart_agent "$host" "$user" "$port"; then
        ok "'$cname': agent on $host restarted — FIM active now."
    else
        warn "'$cname': couldn't reach $host over SSH to restart the agent (fine if client-setup.sh hasn't run yet). It'll pick up FIM on its next scheduled config sync, or once client-setup.sh runs."
    fi
    log "FIM-PUSH company=$cname slug=$slug result=ok"
}

case "$ACTION" in
    push-all)
        [ $# -eq 1 ] || usage
        fail_count=0; total=0
        while IFS= read -r cname; do
            [ -z "$cname" ] && continue
            total=$((total + 1))
            echo "-- $cname --"
            push_one "$cname" || fail_count=$((fail_count + 1))
        done < <(db_company_names)
        echo
        if [ "$fail_count" -eq 0 ]; then
            ok "FIM pushed for $total compan$([ "$total" -eq 1 ] && echo y || echo ies)."
            exit 0
        else
            fail "$fail_count of $total compan$([ "$total" -eq 1 ] && echo y || echo ies) failed. See $LOG_FILE."
            exit 1
        fi
        ;;
    push)
        [ $# -eq 2 ] || usage
        COMPANY="$2"
        db_company_exists "$COMPANY" || { fail "No such company: $COMPANY"; exit 1; }
        push_one "$COMPANY"
        ;;
    remove)
        [ $# -eq 2 ] || usage
        COMPANY="$2"
        db_company_exists "$COMPANY" || { fail "No such company: $COMPANY"; exit 1; }
        SLUG="$(company_slug "$COMPANY")"
        if mgr_remove_company_fim "$SLUG"; then
            ok "Removed FIM config for '$COMPANY' (group: $SLUG)."
            log "FIM-REMOVE company=$COMPANY slug=$SLUG"
        else
            fail "Removal failed. See $LOG_FILE."
            exit 1
        fi
        ;;
    *)
        usage
        ;;
esac
