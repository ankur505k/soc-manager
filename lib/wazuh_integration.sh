#!/bin/bash
# lib/wazuh_integration.sh — manages the LOCAL Wazuh manager's own
# ossec.conf <integration> blocks and agent groups. This runs on the same
# box as the Wazuh manager (no SSH involved) — see README for the
# Docker-exec variant if your manager runs containerized.
#
# Sourced by other scripts; do not execute directly.

MGR_OSSEC_CONF="${MGR_OSSEC_CONF:-/var/ossec/etc/ossec.conf}"
MGR_INTEGRATIONS_DIR="${MGR_INTEGRATIONS_DIR:-/var/ossec/integrations}"
MGR_SHARED_DIR="${MGR_SHARED_DIR:-/var/ossec/etc/shared}"
MGR_BACKUP_DIR="${MGR_BACKUP_DIR:-$MANAGER_HOME/backup/manager-ossec-conf}"
AGENT_GROUPS_BIN="${AGENT_GROUPS_BIN:-/var/ossec/bin/agent_groups}"

mgr_backup_ossec_conf() {
    [ -f "$MGR_OSSEC_CONF" ] || { echo "manager ossec.conf not found at $MGR_OSSEC_CONF" >&2; return 1; }
    mkdir -p "$MGR_BACKUP_DIR"
    local dest="$MGR_BACKUP_DIR/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
    cp -p "$MGR_OSSEC_CONF" "$dest"
    chmod 600 "$dest"
    echo "$dest"
}

mgr_restore_ossec_conf() {
    cp -p "$1" "$MGR_OSSEC_CONF"
}

# mgr_insert_before_tag: same tag-aware insertion pattern used by the
# per-server install.sh — never blind-appends, always lands the new block
# before the given closing tag's LAST occurrence.
mgr_insert_before_tag() {
    local file="$1" content="$2" tag="$3"
    grep -q -F "$tag" "$file" || return 1
    local content_file
    content_file="$(mktemp)"
    printf '%s\n' "$content" > "$content_file"
    local line_no insert_at
    line_no=$(grep -n -F "$tag" "$file" | tail -1 | cut -d: -f1)
    insert_at=$((line_no - 1))
    sed -i "${insert_at}r ${content_file}" "$file"
    rm -f "$content_file"
}

# mgr_commit_and_verify: validate XML, restart wazuh-manager, roll back on
# failure. This restarts the whole manager (all companies' agents briefly
# reconnect) — Wazuh has no XML-config reload-only path for <integration>
# changes, so this is unavoidable and worth doing during a maintenance
# window on a multi-tenant manager.
mgr_commit_and_verify() {
    local backup="$1"
    if ! xmllint --noout "$MGR_OSSEC_CONF" 2>>"$LOG_FILE"; then
        echo "Resulting manager ossec.conf is not valid XML. Rolling back." >&2
        mgr_restore_ossec_conf "$backup"
        return 1
    fi
    if ! systemctl restart wazuh-manager 2>>"$LOG_FILE"; then
        echo "wazuh-manager failed to restart with new config. Rolling back." >&2
        mgr_restore_ossec_conf "$backup"
        systemctl restart wazuh-manager 2>>"$LOG_FILE" || true
        return 1
    fi
    sleep 2
    if ! systemctl is-active --quiet wazuh-manager; then
        echo "wazuh-manager not active after restart. Rolling back." >&2
        mgr_restore_ossec_conf "$backup"
        systemctl restart wazuh-manager 2>>"$LOG_FILE" || true
        return 1
    fi
    return 0
}

mgr_group_exists() {
    [ -d "$MGR_SHARED_DIR/$1" ]
}

# mgr_create_group: idempotent. Requires the group to exist BEFORE any
# agent enrolls into it (Wazuh rejects enrollment into a nonexistent
# group), so this must run as part of "Add Company", before client-setup.sh.
mgr_create_group() {
    local slug="$1"
    if [ ! -x "$AGENT_GROUPS_BIN" ]; then
        echo "agent_groups tool not found at $AGENT_GROUPS_BIN — is this the manager host?" >&2
        return 1
    fi
    if mgr_group_exists "$slug"; then
        return 0
    fi
    # agent_groups prompts for confirmation; auto-confirm since this is a
    # controlled, validated slug, not free-form user input at this point.
    # `yes` dies of SIGPIPE once agent_groups stops reading, which trips
    # `pipefail` — wrap in a subshell and verify actual state afterward
    # rather than trust the pipeline's exit code.
    { yes 2>/dev/null | "$AGENT_GROUPS_BIN" -a -g "$slug" >>"$LOG_FILE" 2>&1; } || true
    mgr_group_exists "$slug"
}

mgr_delete_group() {
    local slug="$1"
    [ -x "$AGENT_GROUPS_BIN" ] || return 1
    mgr_group_exists "$slug" || return 0
    { yes 2>/dev/null | "$AGENT_GROUPS_BIN" -r -g "$slug" >>"$LOG_FILE" 2>&1; } || true
    ! mgr_group_exists "$slug"
}

# Markers let us find/replace/remove a specific company's blocks without
# touching any other company's integration config.
_slack_marker() { echo "<!-- soc-manager:integration:slack:$1 -->"; }
_telegram_marker() { echo "<!-- soc-manager:integration:telegram:$1 -->"; }

mgr_integration_block_present() {
    grep -q -F "$1" "$MGR_OSSEC_CONF" 2>/dev/null
}

# mgr_remove_block: deletes the marker line through the matching
# </integration> that immediately follows it (our own blocks only —
# never touches blocks we didn't add).
mgr_remove_block() {
    local marker="$1"
    grep -q -F "$marker" "$MGR_OSSEC_CONF" || return 0
    local start
    start=$(grep -n -F "$marker" "$MGR_OSSEC_CONF" | head -1 | cut -d: -f1)
    local end
    end=$(awk -v s="$start" 'NR>=s && /<\/integration>/{print NR; exit}' "$MGR_OSSEC_CONF")
    if [ -z "$end" ]; then
        echo "Could not find matching </integration> for $marker — refusing to remove partial block." >&2
        return 1
    fi
    sed -i "${start},${end}d" "$MGR_OSSEC_CONF"
}

# mgr_deploy_telegram_script: idempotent copy of the custom Telegram
# integration script into the manager's integrations directory.
mgr_deploy_telegram_script() {
    local src="$MANAGER_HOME/templates/custom-telegram.py"
    local dest="$MGR_INTEGRATIONS_DIR/custom-telegram.py"
    [ -f "$src" ] || { echo "Missing template: $src" >&2; return 1; }
    mkdir -p "$MGR_INTEGRATIONS_DIR"
    cp "$src" "$dest"
    chmod 750 "$dest"
    # Wazuh has used both root:wazuh and root:ossec across versions —
    # try wazuh first, fall back to ossec, warn if neither group exists.
    if getent group wazuh >/dev/null 2>&1; then
        chown root:wazuh "$dest"
    elif getent group ossec >/dev/null 2>&1; then
        chown root:ossec "$dest"
    else
        echo "Warning: neither 'wazuh' nor 'ossec' group exists — leaving $dest owned by root:root. Verify manually." >&2
    fi
}

# mgr_sync_company_integrations: the single entry point called by
# company-manager.sh on Add/Update. Rebuilds this company's Slack and/or
# Telegram <integration> blocks from current DB values — removes stale
# blocks if a field was cleared, adds/updates otherwise. All-or-nothing:
# backs up first, rolls back the whole edit if validation or restart fails.
mgr_sync_company_integrations() {
    local slug="$1" slack="$2" tgbot="$3" tgchat="$4"

    local backup
    backup="$(mgr_backup_ossec_conf)" || return 1

    local slack_marker telegram_marker
    slack_marker="$(_slack_marker "$slug")"
    telegram_marker="$(_telegram_marker "$slug")"

    # Remove any existing blocks for this company first (clean rebuild).
    mgr_remove_block "$slack_marker" || { mgr_restore_ossec_conf "$backup"; return 1; }
    mgr_remove_block "$telegram_marker" || { mgr_restore_ossec_conf "$backup"; return 1; }

    if [ -n "$slack" ]; then
        local block
        block="$(printf '%s\n<integration>\n  <name>slack</name>\n  <hook_url>%s</hook_url>\n  <group>%s</group>\n  <alert_format>json</alert_format>\n</integration>' \
            "$slack_marker" "$slack" "$slug")"
        mgr_insert_before_tag "$MGR_OSSEC_CONF" "$block" "</ossec_config>" || { mgr_restore_ossec_conf "$backup"; return 1; }
    fi

    if [ -n "$tgbot" ] && [ -n "$tgchat" ]; then
        mgr_deploy_telegram_script || { mgr_restore_ossec_conf "$backup"; return 1; }
        # api_key carries the bot token, hook_url carries the chat id —
        # repurposed fields; see templates/custom-telegram.py header comment.
        local block
        block="$(printf '%s\n<integration>\n  <name>custom-telegram.py</name>\n  <hook_url>%s</hook_url>\n  <api_key>%s</api_key>\n  <group>%s</group>\n  <alert_format>json</alert_format>\n</integration>' \
            "$telegram_marker" "$tgchat" "$tgbot" "$slug")"
        mgr_insert_before_tag "$MGR_OSSEC_CONF" "$block" "</ossec_config>" || { mgr_restore_ossec_conf "$backup"; return 1; }
    fi

    mgr_commit_and_verify "$backup"
}

mgr_remove_company_integrations() {
    local slug="$1"
    local backup
    backup="$(mgr_backup_ossec_conf)" || return 1
    mgr_remove_block "$(_slack_marker "$slug")" || { mgr_restore_ossec_conf "$backup"; return 1; }
    mgr_remove_block "$(_telegram_marker "$slug")" || { mgr_restore_ossec_conf "$backup"; return 1; }
    mgr_commit_and_verify "$backup"
}
