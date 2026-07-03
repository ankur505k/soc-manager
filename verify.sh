#!/bin/bash
# verify.sh <company> — connectivity + health checks before/after a deploy.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/ssh.sh"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

usage() { echo "Usage: $0 <company_name>" >&2; exit 1; }
[ $# -eq 1 ] || usage
COMPANY="$1"

ssh_require || exit 1
db_init || exit 1

if ! db_company_exists "$COMPANY"; then
    fail "No such company: $COMPANY"
    exit 1
fi

IFS='|' read -r id name server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$COMPANY")"

overall_ok=true

if ssh_test "$host" "$user" "$port"; then
    pass "SSH reachable ($user@$host:$port)"
else
    fail "SSH unreachable ($user@$host:$port)"
    overall_ok=false
    echo "0"   # machine-readable failure marker for callers
    exit 1
fi

if ssh_run "$host" "$user" "$port" "test -d /var/ossec" 2>/dev/null; then
    pass "Wazuh agent directory present"
else
    fail "Wazuh agent directory missing (/var/ossec)"
    overall_ok=false
fi

if ssh_run "$host" "$user" "$port" "systemctl is-active --quiet wazuh-agent" 2>/dev/null; then
    pass "wazuh-agent service active"
else
    warn "wazuh-agent service not active (may be expected pre-deploy)"
fi

if ssh_run "$host" "$user" "$port" "grep -q '<groups>' /var/ossec/etc/ossec.conf" 2>/dev/null; then
    pass "Enrollment group configured in agent's ossec.conf"
else
    warn "No <groups> enrollment entry found yet (expected before client-setup.sh runs)"
fi

free_kb="$(ssh_run "$host" "$user" "$port" "df --output=avail -k /var/ossec 2>/dev/null | tail -1" 2>/dev/null | tr -d '[:space:]')"
if [ -n "$free_kb" ] && [ "$free_kb" -gt 512000 ] 2>/dev/null; then
    pass "Disk space OK ($((free_kb / 1024)) MB free)"
elif [ -n "$free_kb" ]; then
    warn "Low disk space: $((free_kb / 1024)) MB free"
else
    warn "Could not determine disk space"
fi

if $overall_ok; then
    echo "1"
    exit 0
else
    echo "0"
    exit 1
fi
