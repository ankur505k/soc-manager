#!/bin/bash
# remove-all-slack.sh — deletes every <integration><name>slack</name>...
# block from the manager's live ossec.conf, whether or not it has a
# soc-manager marker. Per-company mgr_remove_company_integrations only
# targets that ONE company's marked block; this exists for the blocks that
# don't belong to any tracked company — e.g. ones added by hand before
# soc-manager existed, or a leftover "default" block — so you can go
# fully Telegram-only in one shot.
#
# Telegram blocks are never touched.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/lock.sh"
source "$MANAGER_HOME/lib/preflight.sh"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/config.sh"
source "$MANAGER_HOME/lib/docker.sh"
source "$MANAGER_HOME/lib/wazuh_integration.sh"

LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [remove-all-slack] $1" >> "$LOG_FILE"; }

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

CLEAR_DB=false
[ "${1:-}" = "--clear-db" ] && CLEAR_DB=true

preflight_check || exit 1
soc_acquire_lock || exit 1
db_init || exit 1
wazuh_ready || { fail "No Wazuh manager detected (Docker or native)."; exit 1; }

backup="$(mgr_backup_ossec_conf)" || { fail "Could not back up ossec.conf — aborting."; exit 1; }
ok "Backed up current ossec.conf to $backup"

local_conf="$(mgr_local_conf_copy)" || { fail "Could not read live ossec.conf."; exit 1; }
trap 'rm -f "$local_conf"' EXIT

before_count=$(grep -c "<name>slack</name>" "$local_conf" || true)
if [ "$before_count" -eq 0 ]; then
    ok "No Slack integration blocks found on the manager. Nothing to do."
    exit 0
fi
echo "Found $before_count Slack integration block(s) on the manager."

# Remove every <integration>...</integration> block whose body contains
# <name>slack</name>, plus its marker comment line immediately above it
# if one exists. Leaves everything else (including telegram blocks and
# unrelated comments) untouched.
python3 - "$local_conf" <<'PYEOF'
import re
import sys

path = sys.argv[1]
with open(path) as f:
    content = f.read()

# Match an optional marker comment line directly above an <integration>
# block, then the block itself, only when the block contains slack's <name>.
pattern = re.compile(
    r'(?:<!--[^\n]*-->\n)?<integration>(?:(?!</integration>).)*?<name>slack</name>(?:(?!</integration>).)*?</integration>\n?',
    re.S,
)
new_content, n = pattern.subn('', content)

with open(path, 'w') as f:
    f.write(new_content)

print(n)
PYEOF

after_count=$(grep -c "<name>slack</name>" "$local_conf" || true)
removed=$((before_count - after_count))
echo "Removed $removed Slack block(s); $after_count remain (should be 0)."

if [ "$after_count" -ne 0 ]; then
    fail "Not all Slack blocks could be removed automatically. Nothing was pushed. Inspect $local_conf manually."
    exit 1
fi

if ! mgr_commit_and_verify "$local_conf" "$backup"; then
    fail "Push/restart/verify failed — automatically rolled back to the pre-change config. See $LOG_FILE."
    exit 1
fi

ok "All Slack integration blocks removed and manager restarted healthy."
log "REMOVE-ALL-SLACK removed=$removed"

if $CLEAR_DB; then
    db_exec "UPDATE companies SET slack_webhook=NULL, last_updated=datetime('now');"
    ok "Cleared stored Slack webhooks in companies.db (so future Add/Update never re-adds them)."
    log "REMOVE-ALL-SLACK cleared companies.db slack_webhook column"
else
    warn "companies.db still has old Slack webhooks stored per-company. They won't create new blocks unless you edit that company again, but re-run with --clear-db to wipe them too."
fi

echo
echo "Verify Telegram is still the only thing left with: ./verify.sh"
