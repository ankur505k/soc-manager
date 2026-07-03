#!/bin/bash
# lib/config.sh — validation helpers + company_slug().
# Sourced by other scripts; do not execute directly.

validate_company_name() {
    [[ "$1" =~ ^[A-Za-z0-9_-]{2,40}$ ]]
}

validate_host() {
    local h="$1"
    # IPv4
    if [[ "$h" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'; read -r -a o <<< "$h"
        for octet in "${o[@]}"; do [ "$octet" -le 255 ] || return 1; done
        return 0
    fi
    # hostname / FQDN
    [[ "$h" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]
}

validate_ssh_port() {
    [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

validate_ssh_user() {
    [[ "$1" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]
}

validate_slack_webhook() {
    [ -z "$1" ] && return 0   # optional field
    [[ "$1" =~ ^https://hooks\.slack\.com/services/.+ ]]
}

validate_telegram_bot() {
    [ -z "$1" ] && return 0   # optional field
    [[ "$1" =~ ^[0-9]+:[A-Za-z0-9_-]{20,}$ ]]
}

validate_telegram_chat() {
    [ -z "$1" ] && return 0   # optional field
    [[ "$1" =~ ^-?[0-9]+$ ]]
}

# company_slug: derive a Wazuh-agent-group-safe slug from a company name.
# Wazuh group names may only contain letters, numbers, dots, underscores,
# and hyphens — so we normalize rather than reject reasonable company names.
company_slug() {
    echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+|-+$//g'
}
