#!/bin/bash
# lib/lock.sh — single shared lock so two soc-manager entry points (the
# interactive menu, integration.sh, rollback.sh) can't edit ossec.conf or
# companies.db at the same time and stomp on each other's changes.
#
# Uses flock(1) against a real file descriptor, NOT a PID file. A PID-file
# check ("does the file exist and is that PID alive?") is check-then-act:
# two processes starting in the same instant can both see "no lock" and
# both write their own PID before either has finished checking. flock's
# acquisition is a single atomic kernel call, so there's no such window.
#
# Sourced by other scripts; do not execute directly.

SOC_LOCK_FILE="${SOC_LOCK_FILE:-/var/run/soc-manager.lock}"
SOC_LOCK_FD=200

# soc_acquire_lock [wait_seconds]
# No argument (default 0): fails fast, same externally-visible behavior as
# before — refuses immediately if another soc-manager process holds the
# lock. Pass a positive wait_seconds to block up to that long instead.
#
# The lock is tied to $SOC_LOCK_FD staying open; it's released the instant
# that fd is closed, whether that's via the explicit trap below, or simply
# the process exiting (killed, crashed, or normal exit) — no stale lock
# file with a dead PID in it can ever cause a false "still running".
soc_acquire_lock() {
    local wait_seconds="${1:-0}"

    # company-manager.sh holds this lock for its entire interactive session
    # and then shells out to rollback.sh / integration.sh (Rollback Manager
    # Config, Repair Integrations) as separate processes. Without this
    # escape hatch, that child process's own soc_acquire_lock call contends
    # with the parent's still-open flock on the same file and fails
    # immediately every time — a guaranteed self-deadlock, not a real
    # concurrency conflict. The parent exports SOC_MANAGER_LOCK_HELD=1
    # right after acquiring the lock itself, so children spawned from
    # inside that session skip re-acquiring — a genuinely separate,
    # standalone invocation of rollback.sh/integration.sh (the normal case
    # this lock protects) never has that variable set and locks as before.
    if [ -n "${SOC_MANAGER_LOCK_HELD:-}" ]; then
        return 0
    fi

    eval "exec ${SOC_LOCK_FD}>\"\$SOC_LOCK_FILE\"" 2>/dev/null || {
        echo "Could not open lock file $SOC_LOCK_FILE" >&2
        return 1
    }

    if [ "$wait_seconds" -gt 0 ] 2>/dev/null; then
        if ! flock -w "$wait_seconds" -x "$SOC_LOCK_FD"; then
            echo "Timed out after ${wait_seconds}s waiting for another soc-manager process to finish." >&2
            return 1
        fi
    else
        if ! flock -n -x "$SOC_LOCK_FD"; then
            echo "Another soc-manager process is already running — refusing to run concurrently." >&2
            return 1
        fi
    fi

    # Release explicitly on exit (any reason) so the lock never outlives
    # this process for longer than it takes the trap to run.
    eval "trap 'flock -u ${SOC_LOCK_FD} 2>/dev/null; exec ${SOC_LOCK_FD}>&- 2>/dev/null' EXIT"
    return 0
}
