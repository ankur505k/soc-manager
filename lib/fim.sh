#!/bin/bash
# lib/fim.sh — manages File Integrity Monitoring (syscheck) config for each
# company, pushed as a per-group agent.conf under the manager's shared
# folder (/var/ossec/etc/shared/<slug>/agent.conf). Wazuh merges group
# config into every agent enrolled in that group automatically — this is
# additive to whatever <syscheck> already exists in the agent's own local
# ossec.conf, it does not replace it.
#
# "Automatic at both manager and server": pushing agent.conf here is the
# MANAGER side and needs no manager restart (the manager watches the
# shared folder and re-merges on change). The SERVER side picks it up
# on its own periodic config sync, but we also SSH in (using the deploy
# key client-setup.sh already installed) and restart the agent so it's
# active immediately instead of waiting on that cycle.
#
# Sourced by other scripts; do not execute directly.

FIM_MARKER() { echo "<!-- soc-manager:fim:$1 -->"; }

# fim_default_agent_conf <slug>: the VICIdial + AlmaLinux/RHEL FIM policy.
# Kept deliberately conservative on the "ignore" side — VICIdial's spool/
# recording/log directories change constantly and would otherwise flood
# alerts and bury real changes.
fim_default_agent_conf() {
    local slug="$1" marker
    marker="$(FIM_MARKER "$slug")"
    cat <<EOF
$marker
<agent_config>
  <syscheck>
    <!-- VICIdial: core config, admin/agent web GUI, and Perl/AGI scripts -->
    <directories realtime="yes" report_changes="yes" check_all="yes">/etc/asterisk,/etc/vicidial,/usr/share/astguiclient</directories>
    <directories realtime="yes" report_changes="yes" check_all="yes">/var/www/html/agc,/var/www/html/vicidial</directories>

    <!-- Scheduled tasks that commonly get tampered with for persistence -->
    <directories check_all="yes" report_changes="yes">/etc/cron.d,/etc/cron.daily,/etc/cron.hourly,/var/spool/cron</directories>

    <!-- AlmaLinux/RHEL base hardening (additive to Wazuh's built-in Linux defaults) -->
    <directories check_all="yes">/etc/yum.repos.d,/etc/selinux,/etc/sysconfig</directories>
    <directories check_all="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/group,/etc/sudoers,/etc/ssh/sshd_config</directories>

    <!-- Noisy VICIdial runtime data — exclude so alerts stay signal, not spool churn -->
    <ignore>/var/spool/asterisk</ignore>
    <ignore>/var/log/asterisk</ignore>
    <ignore type="sregex">\.log$|\.wav$|\.gsm$|\.call$</ignore>
  </syscheck>
</agent_config>
EOF
}

# mgr_sync_company_fim <slug>: idempotent push/replace of this company's
# FIM agent.conf. Requires the group to already exist (mgr_create_group).
mgr_sync_company_fim() {
    local slug="$1"

    wazuh_ready || { echo "No Wazuh manager detected (Docker or native)." >&2; return 1; }
    mgr_group_exists "$slug" || { echo "Group '$slug' does not exist on the manager yet." >&2; return 1; }

    local tmp
    tmp="$(mktemp)"
    fim_default_agent_conf "$slug" > "$tmp"

    if ! xmllint --noout "$tmp" 2>>"${LOG_FILE:-/dev/null}"; then
        echo "Generated FIM agent.conf for '$slug' is not valid XML — not pushing." >&2
        rm -f "$tmp"
        return 1
    fi

    wazuh_exec mkdir -p "$MGR_SHARED_DIR_REMOTE/$slug" 2>>"${LOG_FILE:-/dev/null}"

    if ! wazuh_copy_to "$tmp" "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf"; then
        echo "Could not push agent.conf for '$slug' to the manager." >&2
        rm -f "$tmp"
        return 1
    fi
    rm -f "$tmp"

    if wazuh_exec getent group wazuh >/dev/null 2>&1; then
        wazuh_exec chown root:wazuh "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf" 2>/dev/null || true
    elif wazuh_exec getent group ossec >/dev/null 2>&1; then
        wazuh_exec chown root:ossec "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf" 2>/dev/null || true
    fi
    wazuh_exec chmod 640 "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf" 2>/dev/null || true

    # Confirm it actually landed rather than trusting the copy's exit code alone.
    wazuh_exec grep -q -F "$(FIM_MARKER "$slug")" "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf" 2>/dev/null
}

# mgr_remove_company_fim <slug>: deletes the shared agent.conf entirely.
# (There's only ever one file per group and it's soc-manager-owned, so no
# marker-scoped partial removal is needed here — unlike ossec.conf.)
mgr_remove_company_fim() {
    local slug="$1"
    wazuh_ready || { echo "No Wazuh manager detected (Docker or native)." >&2; return 1; }
    wazuh_exec rm -f "$MGR_SHARED_DIR_REMOTE/$slug/agent.conf" 2>>"${LOG_FILE:-/dev/null}"
}

# fim_restart_agent host user port: SSH to the CLIENT box (using the same
# deploy key/helpers lib/ssh.sh already uses for verify.sh) and bounce the
# agent so the new group config is picked up now instead of on its next
# scheduled sync. Non-fatal if unreachable (e.g. client-setup.sh hasn't
# run yet) — the agent will still pick this up the first time it does.
fim_restart_agent() {
    local host="$1" user="$2" port="$3"
    ssh_test "$host" "$user" "$port" || return 1
    ssh_run "$host" "$user" "$port" \
        "systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart" \
        >/dev/null 2>&1
}
