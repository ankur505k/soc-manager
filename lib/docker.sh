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
        if [ "$MANAGER_MODE" = "docker" ]; then
            echo "Manager mode: Docker (container: $WAZUH_CONTAINER)"
        else
            echo "Manager mode: native (systemd)"
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
wazuh_copy_to() {
    wazuh_detect_mode || return 1
    if [ "$MANAGER_MODE" = "docker" ]; then
        docker cp "$1" "$WAZUH_CONTAINER:$2"
    else
        cp -p "$1" "$2"
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
# (native), AND wazuh-analysisd itself reports running — a restarted
# container that immediately crash-loops must not read back as healthy.
wazuh_is_active() {
    wazuh_detect_mode || return 1
    if [ "$MANAGER_MODE" = "docker" ]; then
        local running
        running="$(docker inspect -f '{{.State.Running}}' "$WAZUH_CONTAINER" 2>/dev/null)"
        [ "$running" = "true" ] || return 1
        wazuh_exec /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running"
    else
        systemctl is-active --quiet wazuh-manager
    fi
}
