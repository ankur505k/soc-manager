#!/usr/bin/env python3
"""
custom-telegram.py — Wazuh manager-side custom integration.

Deployed by soc-manager to /var/ossec/integrations/custom-telegram.py.
Wazuh's integrator invokes this directly when an alert matches an
<integration><name>custom-telegram.py</name>...</integration> block.

Per Wazuh's documented integration script contract, this script receives:
  argv[1] = path to the JSON alert file
  argv[2] = the <api_key> value from the matching <integration> block
  argv[3] = the <hook_url> value from the matching <integration> block

Wazuh's integration schema has no native bot-token/chat-id fields for a
custom integration, so soc-manager repurposes the two generic fields:
  argv[2] (api_key)  -> Telegram bot token
  argv[3] (hook_url) -> Telegram chat id

This keeps the actual secret (bot token) out of ossec.conf's more casually
read <hook_url> tag and out of this script entirely — both values live
only in soc-manager's companies.db and are written into ossec.conf by
lib/wazuh_integration.sh, never hardcoded here.
"""
import json
import sys
import urllib.request
import urllib.parse

LOG_FILE = "/var/ossec/logs/integrations.log"


def log(msg):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{msg}\n")
    except OSError:
        pass


def main():
    if len(sys.argv) < 4:
        log("custom-telegram.py: missing arguments (need alert_file, bot_token, chat_id)")
        sys.exit(1)

    alert_file_path = sys.argv[1]
    bot_token = sys.argv[2]
    chat_id = sys.argv[3]

    if not bot_token or not chat_id:
        log("custom-telegram.py: bot_token or chat_id empty — skipping")
        sys.exit(0)

    try:
        with open(alert_file_path) as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log(f"custom-telegram.py: could not read/parse alert file: {e}")
        sys.exit(1)

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    text = (
        f"[Wazuh] {rule.get('description', 'alert')}\n"
        f"Level: {rule.get('level', '?')}  Rule ID: {rule.get('id', '?')}\n"
        f"Agent: {agent.get('name', '?')} ({agent.get('id', '?')})\n"
        f"Time: {alert.get('timestamp', '?')}"
    )

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()

    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                log(f"custom-telegram.py: Telegram API returned HTTP {resp.status}")
                sys.exit(1)
    except Exception as e:  # noqa: BLE001 — integration scripts must not crash the integrator
        log(f"custom-telegram.py: request failed: {e}")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
