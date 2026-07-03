#!/bin/bash
# lib/wazuh_integration.sh — manages the Wazuh manager's own ossec.conf
# <integration> blocks and agent groups, working identically whether the
# manager runs in Docker or natively. All manager-side file/exec access
# goes through lib/docker.sh (wazuh_exec / wazuh_copy_to / wazuh_copy_from)
# — nothing here assumes a local /var/ossec.
#
# Sourced by other scripts; do not execute directly.

MGR_OSSEC_CONF_REMOTE="${MGR_OSSEC_CONF_REMOTE:-/var/ossec/etc/ossec.conf}"
MGR_INTEGRATIONS_DIR_REMOTE="${MGR_INTEGRATIONS_DIR_REMOTE:-/var/ossec/integrations}"
MGR_SHARED_DIR_REMOTE="${MGR_SHARED_DIR_REMOTE:-/var/ossec/etc/shared}"
MGR_BACKUP_DIR="${MGR_BACKUP_DIR:-$MANAGER_HOME/backup/manager-ossec-conf}"
AGENT_GROUPS_BIN_REMOTE="${AGENT_GROUPS_BIN_REMOTE:-/var/ossec/bin/agent_groups}"

# mgr_local_conf_copy: pulls the manager's live ossec.conf down to a local
# temp file so we can edit/validate it with ordinary tools (grep/sed/
# xmllint) before pushing it back — same pattern for Docker or native.
mgr_local_conf_copy() {
    local tmp
    tmp="$(mktemp)"
    if ! wazuh_copy_from "$MGR_OSSEC_CONF_REMOTE" "$tmp"; then
        rm -f "$tmp"
        echo "Could not read $MGR_OSSEC_CONF_REMOTE from the manager." >&2
        return 1
    fi
    echo "$tmp"
}

mgr_backup_ossec_conf() {
    mkdir -p "$MGR_BACKUP_DIR"
    local dest="$MGR_BACKUP_DIR/ossec.conf.$(date +%Y%m%d-%H%M%S).bak"
    if ! wazuh_copy_from "$MGR_OSSEC_CONF_REMOTE" "$dest"; then
        echo "manager ossec.conf could not be read for backup" >&2
        return 1
    fi
    chmod 600 "$dest"
    echo "$dest"
}

mgr_restore_ossec_conf() {
    wazuh_copy_to "$1" "$MGR_OSSEC_CONF_REMOTE"
}

# mgr_insert_before_tag: same tag-aware insertion pattern used by the
# per-server install.sh — never blind-appends, always lands the new block
# before the given closing tag's LAST occurrence. Operates on a local file.
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

# mgr_commit_and_verify: given a LOCAL edited copy of ossec.conf and a
# backup path (also local), validate it, push it to the manager, restart,
# and roll back automatically if anything fails. Works identically for
# Docker (docker cp + docker restart) and native (cp + systemctl) because
# it only calls the abstracted wazuh_* functions from lib/docker.sh.
mgr_commit_and_verify() {
    local local_conf="$1" backup="$2"

    if ! xmllint --noout "$local_conf" 2>>"$LOG_FILE"; then
        echo "Resulting manager ossec.conf is not valid XML. Not pushing." >&2
        return 1
    fi

    if ! wazuh_copy_to "$local_conf" "$MGR_OSSEC_CONF_REMOTE"; then
        echo "Could not push updated ossec.conf to the manager." >&2
        return 1
    fi

    if ! wazuh_restart; then
        echo "Manager failed to restart with new config. Rolling back." >&2
        mgr_restore_ossec_conf "$backup"
        wazuh_restart 2>>"$LOG_FILE" || true
        return 1
    fi

    sleep 3
    if ! wazuh_is_active; then
        echo "Manager not healthy after restart. Rolling back." >&2
        mgr_restore_ossec_conf "$backup"
        wazuh_restart 2>>"$LOG_FILE" || true
        return 1
    fi

    return 0
}

mgr_group_exists() {
    wazuh_exec test -d "$MGR_SHARED_DIR_REMOTE/$1" 2>/dev/null
}

# mgr_create_group: idempotent. Requires the group to exist BEFORE any
# agent enrolls into it (Wazuh rejects enrollment into a nonexistent
# group), so this must run as part of "Add Company", before client-setup.sh.
mgr_create_group() {
    local slug="$1"
    if mgr_group_exists "$slug"; then
        return 0
    fi
    # agent_groups prompts for confirmation; auto-confirm since this is a
    # controlled, validated slug, not free-form user input at this point.
    # `yes` dies of SIGPIPE once agent_groups stops reading, which trips
    # `pipefail` if the shell has it set — wrap in a subshell and verify
    # actual state afterward rather than trust the pipeline's exit code.
    { yes 2>/dev/null | wazuh_exec "$AGENT_GROUPS_BIN_REMOTE" -a -g "$slug" >>"$LOG_FILE" 2>&1; } || true
    mgr_group_exists "$slug"
}

mgr_delete_group() {
    local slug="$1"
    mgr_group_exists "$slug" || return 0
    { yes 2>/dev/null | wazuh_exec "$AGENT_GROUPS_BIN_REMOTE" -r -g "$slug" >>"$LOG_FILE" 2>&1; } || true
    ! mgr_group_exists "$slug"
}

# Markers let us find/replace/remove a specific company's blocks without
# touching any other company's integration config.
_slack_marker() { echo "<!-- soc-manager:integration:slack:$1 -->"; }
_telegram_marker() { echo "<!-- soc-manager:integration:telegram:$1 -->"; }

mgr_integration_block_present() {
    local local_conf
    local_conf="$(mgr_local_conf_copy)" || return 1
    local result=1
    grep -q -F "$1" "$local_conf" && result=0
    rm -f "$local_conf"
    return $result
}

# mgr_remove_block: deletes the marker line through the matching
# </integration> that immediately follows it (our own blocks only —
# never touches blocks we didn't add). Operates on a local file.
mgr_remove_block() {
    local file="$1" marker="$2"
    grep -q -F "$marker" "$file" || return 0
    local start end
    start=$(grep -n -F "$marker" "$file" | head -1 | cut -d: -f1)
    end=$(awk -v s="$start" 'NR>=s && /<\/integration>/{print NR; exit}' "$file")
    if [ -z "$end" ]; then
        echo "Could not find matching </integration> for $marker — refusing to remove partial block." >&2
        return 1
    fi
    sed -i "${start},${end}d" "$file"
}

# mgr_deploy_telegram_script: idempotent copy of the custom Telegram
# integration script into the manager's integrations directory (inside
# the container, or on disk natively — same call either way).
mgr_deploy_telegram_script() {
    local src="$MANAGER_HOME/templates/custom-telegram.py"
    [ -f "$src" ] || { echo "Missing template: $src" >&2; return 1; }

    if ! wazuh_copy_to "$src" "$MGR_INTEGRATIONS_DIR_REMOTE/custom-telegram.py"; then
        echo "Could not copy custom-telegram.py to the manager." >&2
        return 1
    fi
    wazuh_exec chmod 750 "$MGR_INTEGRATIONS_DIR_REMOTE/custom-telegram.py"
    # Wazuh has used both root:wazuh and root:ossec across versions —
    # try wazuh first, fall back to ossec, warn if neither group exists.
    if wazuh_exec getent group wazuh >/dev/null 2>&1; then
        wazuh_exec chown root:wazuh "$MGR_INTEGRATIONS_DIR_REMOTE/custom-telegram.py"
    elif wazuh_exec getent group ossec >/dev/null 2>&1; then
        wazuh_exec chown root:ossec "$MGR_INTEGRATIONS_DIR_REMOTE/custom-telegram.py"
    else
        echo "Warning: neither 'wazuh' nor 'ossec' group exists on the manager — leaving the script owned by root:root. Verify manually." >&2
    fi
}

# mgr_sync_company_integrations: the single entry point called by
# company-manager.sh on Add/Update. Rebuilds this company's Slack and/or
# Telegram <integration> blocks from current DB values — removes stale
# blocks if a field was cleared, adds/updates otherwise. All-or-nothing:
# backs up first, rolls back the whole edit if validation or restart fails.
mgr_sync_company_integrations() {
    local slug="$1" slack="$2" tgbot="$3" tgchat="$4"

    wazuh_ready || { echo "No Wazuh manager detected (Docker or native)." >&2; return 1; }

    local backup local_conf
    backup="$(mgr_backup_ossec_conf)" || return 1
    local_conf="$(mgr_local_conf_copy)" || return 1

    local slack_marker telegram_marker
    slack_marker="$(_slack_marker "$slug")"
    telegram_marker="$(_telegram_marker "$slug")"

    # Remove any existing blocks for this company first (clean rebuild).
    mgr_remove_block "$local_conf" "$slack_marker" || { rm -f "$local_conf"; return 1; }
    mgr_remove_block "$local_conf" "$telegram_marker" || { rm -f "$local_conf"; return 1; }

    if [ -n "$slack" ]; then
        local block
        block="$(printf '%s\n<integration>\n  <name>slack</name>\n  <hook_url>%s</hook_url>\n  <group>%s</group>\n  <alert_format>json</alert_format>\n</integration>' \
            "$slack_marker" "$slack" "$slug")"
        mgr_insert_before_tag "$local_conf" "$block" "</ossec_config>" || { rm -f "$local_conf"; return 1; }
    fi

    if [ -n "$tgbot" ] && [ -n "$tgchat" ]; then
        mgr_deploy_telegram_script || { rm -f "$local_conf"; return 1; }
        # api_key carries the bot token, hook_url carries the chat id —
        # repurposed fields; see templates/custom-telegram.py header comment.
        local block
        block="$(printf '%s\n<integration>\n  <name>custom-telegram.py</name>\n  <hook_url>%s</hook_url>\n  <api_key>%s</api_key>\n  <group>%s</group>\n  <alert_format>json</alert_format>\n</integration>' \
            "$telegram_marker" "$tgchat" "$tgbot" "$slug")"
        mgr_insert_before_tag "$local_conf" "$block" "</ossec_config>" || { rm -f "$local_conf"; return 1; }
    fi

    local rc=0
    mgr_commit_and_verify "$local_conf" "$backup" || rc=1
    rm -f "$local_conf"
    return $rc
}

mgr_remove_company_integrations() {
    local slug="$1"

    wazuh_ready || { echo "No Wazuh manager detected (Docker or native)." >&2; return 1; }

    local backup local_conf
    backup="$(mgr_backup_ossec_conf)" || return 1
    local_conf="$(mgr_local_conf_copy)" || return 1

    mgr_remove_block "$local_conf" "$(_slack_marker "$slug")" || { rm -f "$local_conf"; return 1; }
    mgr_remove_block "$local_conf" "$(_telegram_marker "$slug")" || { rm -f "$local_conf"; return 1; }

    local rc=0
    mgr_commit_and_verify "$local_conf" "$backup" || rc=1
    rm -f "$local_conf"
    return $rc
}
