#!/bin/bash
# rollback.sh — manually restore a previous manager ossec.conf backup.
#
# Every edit made by lib/wazuh_integration.sh already backs up and
# auto-rolls-back on failure by itself. This script is for the case where
# you want to go back further than "the last edit" — e.g. undo several
# changes at once, or recover after something else touched ossec.conf.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/docker.sh"
source "$MANAGER_HOME/lib/wazuh_integration.sh"

LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [rollback] $1" >> "$LOG_FILE"; }

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

wazuh_ready || { fail "No Wazuh manager detected (Docker or native)."; exit 1; }
echo "$(wazuh_manager_summary)"

mkdir -p "$MGR_BACKUP_DIR"

mapfile -t BACKUPS < <(ls -1t "$MGR_BACKUP_DIR"/ossec.conf.*.bak 2>/dev/null || true)

if [ ${#BACKUPS[@]} -eq 0 ]; then
    fail "No backups found in $MGR_BACKUP_DIR."
    exit 1
fi

echo
echo "Available manager ossec.conf backups (newest first):"
i=1
for b in "${BACKUPS[@]}"; do
    printf "  %2d) %s\n" "$i" "$(basename "$b")"
    i=$((i + 1))
done
echo "   0) Cancel"
echo

read -r -p "Restore which backup? [1-${#BACKUPS[@]}, 0 to cancel]: " choice

if [[ ! "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -eq 0 ] || [ "$choice" -gt "${#BACKUPS[@]}" ]; then
    echo "Cancelled."
    exit 0
fi

SELECTED="${BACKUPS[$((choice - 1))]}"
echo
echo "Selected: $(basename "$SELECTED")"

if ! xmllint --noout "$SELECTED" 2>>"$LOG_FILE"; then
    fail "That backup is not valid XML — refusing to restore it. Check $LOG_FILE."
    exit 1
fi

read -r -p "This will overwrite the manager's live ossec.conf and restart it. Continue? [y/N]: " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { echo "Cancelled."; exit 0; }

# Back up the CURRENT (about to be overwritten) config too, so this
# action is itself reversible.
CURRENT_BACKUP="$(mgr_backup_ossec_conf)" || { fail "Could not back up current config before rollback."; exit 1; }
ok "Current config backed up to $(basename "$CURRENT_BACKUP") before proceeding."

if ! wazuh_copy_to "$SELECTED" "$MGR_OSSEC_CONF_REMOTE"; then
    fail "Could not push the selected backup to the manager."
    exit 1
fi

if ! wazuh_restart; then
    fail "Manager failed to restart after rollback. Restoring the pre-rollback config."
    wazuh_copy_to "$CURRENT_BACKUP" "$MGR_OSSEC_CONF_REMOTE"
    wazuh_restart 2>>"$LOG_FILE" || true
    exit 1
fi

sleep 3
if ! wazuh_is_active; then
    fail "Manager not healthy after rollback. Restoring the pre-rollback config."
    wazuh_copy_to "$CURRENT_BACKUP" "$MGR_OSSEC_CONF_REMOTE"
    wazuh_restart 2>>"$LOG_FILE" || true
    exit 1
fi

ok "Rollback to $(basename "$SELECTED") complete and manager is healthy."
log "ROLLBACK to $(basename "$SELECTED"), pre-rollback state saved as $(basename "$CURRENT_BACKUP")"
