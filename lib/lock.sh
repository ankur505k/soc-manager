#!/bin/bash
# lib/lock.sh — single shared lock so two soc-manager entry points (the
# interactive menu, integration.sh, rollback.sh) can't edit ossec.conf or
# companies.db at the same time and stomp on each other's changes.
# Sourced by other scripts; do not execute directly.

SOC_LOCK_FILE="${SOC_LOCK_FILE:-/var/run/soc-manager.lock}"

# soc_acquire_lock: fails fast (no waiting/queueing) if another soc-manager
# process is already running, rather than silently letting two invocations
# interleave their edits to the same config file.
soc_acquire_lock() {
    if [ -f "$SOC_LOCK_FILE" ]; then
        local pid
        pid="$(cat "$SOC_LOCK_FILE" 2>/dev/null || echo "")"
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            echo "Another soc-manager process is already running (PID $pid) — refusing to run concurrently." >&2
            return 1
        fi
    fi
    echo $$ > "$SOC_LOCK_FILE"
    trap 'rm -f "$SOC_LOCK_FILE"' EXIT
}
