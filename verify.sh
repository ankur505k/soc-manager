#!/bin/bash
# verify.sh <company> — connectivity + health checks before/after a deploy.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/database.sh"
source "$MANAGER_HOME/lib/ssh.sh"
source "$MANAGER_HOME/lib/docker.sh"
source "$MANAGER_HOME/lib/preflight.sh"

GREEN="\033[0;32m"; RED="\033[0;31m"; YELLOW="\033[1;33m"; NC="\033[0m"
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

usage() { echo "Usage: $0 <company_name>" >&2; exit 1; }
[ $# -eq 1 ] || usage
COMPANY="$1"

preflight_check || exit 1
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

if wazuh_ready 2>/dev/null; then
    # Fixed-string match on "Name: <exact>" / "IP: <exact>," rather than a
    # loose substring/OR grep — a plain `grep "$name\|$host"` would also
    # match e.g. company "Ac" against agent "Acme-01", or one octet of an
    # IP appearing inside a different agent's name/ID.
    #
    # Match on server_name FIRST, not the company display name: the agent
    # actually registers under whatever client-setup.sh set as
    # <enrollment><agent_name> (deploy.sh passes it as server_name) — that's
    # the deterministic identity, not the free-text company name, which can
    # differ arbitrarily from what the box enrolled as. Fall back to company
    # name / host IP for agents enrolled before this field was wired up.
    #
    # Retried rather than checked once: a freshly-enrolled agent can take
    # a few seconds to show up in agent_control -lc, and a single
    # immediate check right after client-setup.sh would false-negative on
    # a perfectly fine deploy.
    found=false
    for attempt in 1 2 3 4 5; do
        agent_list="$(wazuh_exec /var/ossec/bin/agent_control -lc 2>/dev/null || true)"
        if { [ -n "$server_name" ] && printf '%s\n' "$agent_list" | grep -qF "Name: ${server_name},"; } || \
           printf '%s\n' "$agent_list" | grep -qF "Name: ${name}," || \
           printf '%s\n' "$agent_list" | grep -qF "IP: ${host},"; then
            found=true
            break
        fi
        [ "$attempt" -lt 5 ] && sleep 3
    done
    if $found; then
        pass "Manager sees an agent matching '${server_name:-$name}'/'$host' in agent_control -lc"
    else
        warn "Manager's agent_control -lc doesn't show '${server_name:-$name}'/'$host' after 5 attempts (~15s) — may still be pending first connection"
    fi
else
    warn "Could not check manager-side agent list (no Wazuh manager detected here)"
fi

if $overall_ok; then
    echo "1"
    exit 0
else
    echo "0"
    exit 1
fi
