#!/bin/bash
# lib/preflight.sh — checks the tools soc-manager depends on are actually
# installed, up front, with an actionable message — instead of failing
# confusingly halfway through an Add/Update/Rollback because `xmllint`
# or `sqlite3` doesn't exist on this box.
# Sourced by other scripts; do not execute directly.

# preflight_check: docker is intentionally NOT required here — a native
# (non-Docker) Wazuh install is a supported mode (see lib/docker.sh), so
# we only fail on tools every mode needs.
preflight_check() {
    local missing=() cmd
    # openssl is needed for at-rest encryption of Slack/Telegram
    # credentials (lib/secrets.sh) — required here rather than left as a
    # silent plaintext fallback, since AlmaLinux/RHEL ship it by default
    # and a missing one usually means a stripped-down/container base image
    # worth flagging up front rather than discovering via a warning later.
    for cmd in xmllint sqlite3 ssh scp curl openssl; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        echo "Missing required tool(s): ${missing[*]}" >&2
        echo "Install with:" >&2
        echo "  dnf install -y libxml2 sqlite openssh-clients curl openssl   (RHEL/Fedora)" >&2
        echo "  apt install -y libxml2-utils sqlite3 openssh-client curl openssl   (Debian/Ubuntu)" >&2
        return 1
    fi
    return 0
}
