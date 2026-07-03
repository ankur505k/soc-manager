#!/bin/bash
# deploy.sh <company> — ensures a company's server is properly enrolled:
# reachable over SSH, has the agent installed, and is in the correct
# Wazuh group. If not yet set up, offers to push and run client-setup.sh
# remotely with this company's values pre-filled.
#
# This does NOT push any Slack/Telegram config to the client — that
# doesn't belong there. See lib/wazuh_integration.sh for how notification
# routing is actually configured (on the manager, via <integration>
# blocks scoped by agent group).
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/ssh.sh"
source "$MANAGER_HOME/lib/config.sh"

LOG_FILE="$MANAGER_HOME/logs/soc-manager.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') [deploy] $1" >> "$LOG_FILE"; }

usage() { echo "Usage: $0 <company_name>" >&2; exit 1; }
[ $# -eq 1 ] || usage
COMPANY="$1"

ssh_require || exit 1
db_init || exit 1

if ! db_company_exists "$COMPANY"; then
    echo "No such company: $COMPANY" >&2
    exit 1
fi

IFS='|' read -r id name server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$COMPANY")"
SLUG="$(company_slug "$COMPANY")"

echo "== Checking enrollment for $COMPANY ($host) =="

if ! ssh_test "$host" "$user" "$port"; then
    echo "SSH unreachable ($user@$host:$port)." >&2
    echo "This server hasn't been prepared yet, or the manager's SSH key isn't installed."
    echo "Run client-setup.sh manually on $host first (see below), then re-run this."
else
    echo "SSH reachable."
    if ssh_run "$host" "$user" "$port" "test -d /var/ossec" 2>/dev/null; then
        echo "Wazuh agent already installed on $host."
        db_set_status "$COMPANY" "active"
        log "OK $COMPANY already enrolled"
        echo "== $COMPANY looks good. Run ./verify.sh $COMPANY for a full health check. =="
        exit 0
    else
        echo "Wazuh agent not found on $host — client-setup.sh still needs to run there."
    fi
fi

# At this point the agent isn't installed/enrolled yet. Print the exact
# command to run on the client server — this is intentionally a manual,
# explicit step rather than something soc-manager runs unattended, since
# it installs a package and edits system files on a server we may not
# yet have verified access to.
PUBKEY=""
if [ -f "${SSH_KEY}.pub" ]; then
    PUBKEY="$(cat "${SSH_KEY}.pub")"
fi

echo
echo "== Run this on $host (as root) to complete enrollment =="
echo "----------------------------------------------------------"
echo "curl -fsSL <your-file-host>/client-setup.sh -o client-setup.sh   # or scp it over"
echo "chmod +x client-setup.sh"
cat <<EOF
WAZUH_MANAGER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')" \\
GROUP="$SLUG" \\
MANAGER_PUB_KEY="${PUBKEY:-<contents of $SSH_KEY.pub>}" \\
SSH_USER="root" \\
  ./client-setup.sh
EOF
echo "----------------------------------------------------------"
echo
echo "Note: the '$SLUG' Wazuh agent group must exist on this manager before"
echo "that script runs (company-manager.sh's 'Add Company' creates it automatically)."

db_set_status "$COMPANY" "pending"
log "PENDING $COMPANY needs client-setup.sh run manually on $host"
exit 1
