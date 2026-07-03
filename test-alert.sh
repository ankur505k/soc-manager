#!/bin/bash
# test-alert.sh <company> — sends a direct test message via the stored
# Slack webhook / Telegram bot for a company.
#
# Scope, honestly stated: this verifies the CREDENTIALS work (the webhook
# is live, the bot token/chat id are valid) by calling the APIs directly
# from the manager. It does NOT push a synthetic alert through Wazuh's
# rule engine and <integration> pipeline end-to-end — doing that requires
# either a real triggering event or wazuh-logtest plus a crafted alert
# JSON fed to the integrator, which is a separate, more involved test.
# If this script succeeds but real alerts still aren't arriving, check
# /var/ossec/logs/integrations.log on the manager next.
set -Eeuo pipefail

MANAGER_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$MANAGER_HOME/lib/database.sh"

usage() { echo "Usage: $0 <company_name>" >&2; exit 1; }
[ $# -eq 1 ] || usage
COMPANY="$1"

db_init || exit 1
if ! db_company_exists "$COMPANY"; then
    echo "No such company: $COMPANY" >&2
    exit 1
fi

IFS='|' read -r id name server_name host user port slack tgbot tgchat status last_updated <<< "$(db_get_company "$COMPANY")"

any=false

if [ -n "$slack" ]; then
    any=true
    echo "-- Testing Slack for $COMPANY --"
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        -X POST -H "Content-Type: application/json" \
        -d "{\"text\":\"soc-manager test alert for $COMPANY\"}" "$slack" || echo "000")
    if [ "$code" = "200" ]; then
        echo "OK: Slack accepted the test message (HTTP 200)."
    else
        echo "FAIL: Slack returned HTTP $code." >&2
    fi
fi

if [ -n "$tgbot" ] && [ -n "$tgchat" ]; then
    any=true
    echo "-- Testing Telegram for $COMPANY --"
    resp=$(curl -s --max-time 10 -X POST "https://api.telegram.org/bot${tgbot}/sendMessage" \
        --data-urlencode "chat_id=${tgchat}" \
        --data-urlencode "text=soc-manager test alert for $COMPANY" || echo '{"ok":false}')
    if echo "$resp" | grep -q '"ok":true'; then
        echo "OK: Telegram accepted the test message."
    else
        echo "FAIL: Telegram rejected it. Response: $resp" >&2
    fi
fi

if ! $any; then
    echo "No Slack webhook or Telegram bot/chat configured for $COMPANY — nothing to test." >&2
    exit 1
fi
