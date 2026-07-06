#!/bin/bash
# lib/docker.sh — abstracts "the Wazuh manager" so nothing else in
# soc-manager needs to know whether it's a Docker container or a native
# systemd install. Auto-detects once per run, caches the result.
#
# Sourced by other scripts; do not execute directly.

WAZUH_CONTAINER_FILE="${WAZUH_CONTAINER_FILE:-$MANAGER_HOME/.wazuh_container}"
WAZUH_CONTAINER="${WAZUH_CONTAINER:-}"
MANAGER_MODE=""   # "docker" or "native", set by wazuh_detect_mode()

docker_available() {
    command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1
}

# _docker_find_container: scan `docker ps` for something that looks like
# a Wazuh manager. Returns the name on stdout if exactly one match;
# returns 2 (and lists candidates on stderr) if more than one — we never
# guess between ambiguous containers.
_docker_find_container() {
    local candidates count
    candidates="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -iE 'wazuh.*manager|manager.*wazuh' || true)"
    count="$(printf '%s\n' "$candidates" | grep -c . || true)"
    if [ "$count" -eq 1 ]; then
        printf '%s\n' "$candidates"
        return 0
    elif [ "$count" -gt 1 ]; then
        echo "Multiple candidate Wazuh manager containers are running:" >&2
        printf '%s\n' "$candidates" >&2
        return 2
    else
        return 1
    fi
}

# wazuh_detect_mode: figure out (once) whether to use `docker exec`/
# `docker cp` or talk to this host directly, and cache the container
# name in $WAZUH_CONTAINER_FILE so future runs don't re-scan.
wazuh_detect_mode() {
    [ -n "$MANAGER_MODE" ] && return 0

    if [ -z "$WAZUH_CONTAINER" ] && [ -f "$WAZUH_CONTAINER_FILE" ]; then
        WAZUH_CONTAINER="$(cat "$WAZUH_CONTAINER_FILE" 2>/dev/null || true)"
    fi

    if docker_available; then
        if [ -n "$WAZUH_CONTAINER" ] && docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$WAZUH_CONTAINER"; then
            MANAGER_MODE="docker"
            return 0
        fi

        local found rc
        found="$(_docker_find_container)"; rc=$?
        if [ "$rc" -eq 0 ]; then
            WAZUH_CONTAINER="$found"
            printf '%s\n' "$WAZUH_CONTAINER" > "$WAZUH_CONTAINER_FILE" 2>/dev/null || true
            MANAGER_MODE="docker"
            return 0
        elif [ "$rc" -eq 2 ]; then
            echo "Set WAZUH_CONTAINER=<name> and re-run, or write the name to $WAZUH_CONTAINER_FILE." >&2
            return 1
        fi
        # docker is available but nothing matched — fall through and
        # check for a native install before giving up entirely.
    fi

    if [ -d /var/ossec ] && [ -x /var/ossec/bin/agent_groups ]; then
        MANAGER_MODE="native"
        return 0
    fi

    return 1
}

# wazuh_remote_bin_exists <path> — used to probe for optional binaries
# (e.g. wazuh-analysisd) before relying on them, since exact paths/flags
# have shifted across Wazuh versions and we'd rather skip an extra check
# than hard-fail a deploy because of it.
wazuh_remote_bin_exists() {
    wazuh_exec test -x "$1" 2>/dev/null
}

docker_ok() {
    wazuh_detect_mode && [ "$MANAGER_MODE" = "docker" ]
}

# wazuh_ready: the manager-presence check every script should call before
# doing anything else. Prints nothing on success; caller decides how to
# report failure.
wazuh_ready() {
    wazuh_detect_mode
}

wazuh_manager_summary() {
    if wazuh_detect_mode; then
        local base
        if [ "$MANAGER_MODE" = "docker" ]; then
            base="Manager mode: Docker (container: $WAZUH_CONTAINER)"
        else
            base="Manager mode: native (systemd)"
        fi
        if wazuh_api_daemon_running; then
            echo "$base | API: up"
        else
            echo "$base | API: down or disabled"
        fi
    else
        echo "Manager mode: NOT DETECTED (no matching container, no native /var/ossec)"
    fi
}

# wazuh_exec <command> [args...] — run a command "on the manager".
# Always an argv array in both modes, never a single interpolated
# string, so arguments containing spaces/quotes pass through safely.
wazuh_exec() {
    wazuh_detect_mode || { echo "No Wazuh manager found (Docker or native)." >&2; return 1; }
    if [ "$MANAGER_MODE" = "docker" ]; then
        docker exec -i "$WAZUH_CONTAINER" "$@"
    else
        "$@"
    fi
}

# wazuh_copy_to <local_path> <remote_path>
# Atomic: lands the file at "<remote_path>.soc-manager.tmp" first, then
# renames it into place. A rename within the same directory is a single
# syscall, so a crash/interruption mid-copy can never leave the live file
# half-written — it either has the old content or the fully new content.
wazuh_copy_to() {
    wazuh_detect_mode || return 1
    local local_path="$1" remote_path="$2" remote_tmp="${2}.soc-manager.tmp"
    if [ "$MANAGER_MODE" = "docker" ]; then
        docker cp "$local_path" "$WAZUH_CONTAINER:$remote_tmp" || return 1
        docker exec -i "$WAZUH_CONTAINER" mv -f "$remote_tmp" "$remote_path"
    else
        cp -p "$local_path" "$remote_tmp" || return 1
        mv -f "$remote_tmp" "$remote_path"
    fi
}

# wazuh_copy_from <remote_path> <local_path>
wazuh_copy_from() {
    wazuh_detect_mode || return 1
    if [ "$MANAGER_MODE" = "docker" ]; then
        docker cp "$WAZUH_CONTAINER:$1" "$2"
    else
        cp -p "$1" "$2"
    fi
}

wazuh_restart() {
    wazuh_detect_mode || return 1
    if [ "$MANAGER_MODE" = "docker" ]; then
        docker restart "$WAZUH_CONTAINER" >/dev/null
    else
        systemctl restart wazuh-manager
    fi
}

# wazuh_is_active: container running (docker mode) or service active
# (native), AND the manager's core daemons report running — a restarted
# container that immediately crash-loops, or comes up with analysisd alive
# but remoted/wazuh-db dead, must not read back as healthy. We check the
# daemons that matter for "agents can connect and alerts get processed and
# routed", not just "the process table has one entry in it".
wazuh_is_active() {
    wazuh_detect_mode || return 1
    if [ "$MANAGER_MODE" = "docker" ]; then
        local running
        running="$(docker inspect -f '{{.State.Running}}' "$WAZUH_CONTAINER" 2>/dev/null)"
        [ "$running" = "true" ] || return 1
    else
        systemctl is-active --quiet wazuh-manager || return 1
    fi

    local status
    status="$(wazuh_exec /var/ossec/bin/wazuh-control status 2>/dev/null)" || return 1
    local d
    # wazuh-modulesd added alongside the original three: it drives
    # syscollector/vulnerability-detector/etc, and its absence is a real
    # "manager isn't fully up" signal, not a cosmetic one.
    # wazuh-apid (the REST API, which the Dashboard needs to log in) is
    # deliberately NOT in this hard-required list — some admins disable
    # the API intentionally, and that's a valid config, not a broken
    # manager. See wazuh_api_daemon_running() below for visibility into it
    # without making it a rollback trigger.
    for d in wazuh-analysisd wazuh-remoted wazuh-db wazuh-modulesd; do
        echo "$status" | grep -q "${d} is running" || return 1
    done
    return 0
}

# wazuh_api_daemon_running: best-effort visibility into whether the REST
# API process itself is up, per `wazuh-control status`. Informational only
# (see the comment in wazuh_is_active for why it isn't a hard requirement).
wazuh_api_daemon_running() {
    wazuh_detect_mode || return 1
    local status
    status="$(wazuh_exec /var/ossec/bin/wazuh-control status 2>/dev/null)" || return 1
    echo "$status" | grep -q "wazuh-apid is running"
}

# wazuh_wait_active <timeout_seconds> [poll_interval_seconds]
# Polls wazuh_is_active instead of a single fixed sleep, so a manager that
# genuinely just needs a few extra seconds to come up (normal on restart,
# especially with many agents/rules) isn't treated as a failed deploy and
# rolled back. Returns 0 as soon as it's healthy, 1 if it never becomes
# healthy within the timeout.
wazuh_wait_active() {
    local timeout="${1:-90}" interval="${2:-3}" waited=0
    while [ "$waited" -lt "$timeout" ]; do
        if wazuh_is_active; then
            return 0
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done
    wazuh_is_active
}
