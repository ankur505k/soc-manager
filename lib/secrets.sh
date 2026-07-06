#!/bin/bash
# lib/secrets.sh — at-rest encryption for the Slack/Telegram credentials
# stored in companies.db.
#
# Threat model, stated honestly: this does NOT protect against a root
# compromise of the manager host — the key file lives on the same box and
# a root attacker can read both. What it DOES protect against is the much
# more common exposure path: companies.db (or one of its backups, or a
# copy made for debugging, or a misconfigured backup destination) leaking
# on its own, without the separate key file, and being directly readable.
#
# Encrypt-then-MAC, not plain CBC: `openssl enc` has no AEAD/GCM support
# (confirmed against OpenSSL's own docs — "This command does not support
# authenticated encryption modes like CCM and GCM, and will not support
# such modes in the future"). Plain AES-256-CBC with no MAC has a real,
# tested failure mode: decrypting with the WRONG key does not reliably
# error. PKCS7 padding validation passes on garbage roughly 1/256 of the
# time, so a wrong/rotated key can silently produce corrupted "plaintext"
# instead of a clean failure — confirmed empirically while hardening this
# file. We close that gap with our own HMAC-SHA256 over the ciphertext,
# verified before we ever attempt to decrypt.
#
# Sourced by lib/database.sh; do not execute directly.

SECRETS_KEY_FILE="${SECRETS_KEY_FILE:-$MANAGER_HOME/.secrets.key}"

secrets_available() {
    command -v openssl >/dev/null 2>&1
}

# secrets_init: generate the key file once, root-only-readable. Safe to
# call repeatedly — a no-op once the file exists.
secrets_init() {
    secrets_available || return 1
    if [ ! -f "$SECRETS_KEY_FILE" ]; then
        local tmp
        tmp="$(mktemp "${SECRETS_KEY_FILE}.XXXXXX")" || return 1
        chmod 600 "$tmp"
        if ! openssl rand -base64 32 > "$tmp" 2>/dev/null; then
            rm -f "$tmp"
            return 1
        fi
        mv -f "$tmp" "$SECRETS_KEY_FILE"
        chmod 600 "$SECRETS_KEY_FILE"
        echo "Generated new secrets key: $SECRETS_KEY_FILE (back this up separately from companies.db — losing it makes stored Slack/Telegram credentials unrecoverable)." >&2
    fi
}

_secrets_hmac() {
    # HMAC-SHA256 of $1, hex-encoded, keyed with the raw contents of the
    # key file (same file used as the CBC passphrase — one key file to
    # back up, two independent uses of it).
    openssl dgst -sha256 -hmac "$(cat "$SECRETS_KEY_FILE")" 2>/dev/null <<< "$1" | awk '{print $NF}'
}

# secrets_encrypt <plaintext> -> prints "enc:<ciphertext_b64>:<hmac_hex>"
# on stdout. Falls back to printing the plaintext unchanged (no "enc:"
# prefix) if openssl isn't installed or the key can't be created — a
# field that's already optional shouldn't become a hard failure for the
# whole "Add Company" flow just because encryption isn't available on
# this box; the absence of the prefix makes that fallback greppable.
secrets_encrypt() {
    local plaintext="$1"
    [ -z "$plaintext" ] && { printf '%s' ""; return 0; }
    if secrets_available && secrets_init; then
        local ct mac
        ct="$(printf '%s' "$plaintext" | openssl enc -aes-256-cbc -pbkdf2 -salt -base64 -A -pass "file:$SECRETS_KEY_FILE" 2>/dev/null)"
        if [ -n "$ct" ]; then
            mac="$(_secrets_hmac "$ct")"
            if [ -n "$mac" ]; then
                printf 'enc:%s:%s' "$ct" "$mac"
                return 0
            fi
        fi
        echo "Warning: encryption failed, storing this value in plaintext. Check openssl/$SECRETS_KEY_FILE." >&2
    fi
    printf '%s' "$plaintext"
}

# secrets_decrypt <value> -> prints plaintext on stdout.
# Values without the "enc:" prefix pass through unchanged — this is what
# lets rows written before this feature existed keep working with no
# manual migration/backfill step. Values in the old "enc:<ct>" form (no
# MAC, written before this HMAC hardening) are decrypted without
# integrity verification for backward compatibility — logged as such.
secrets_decrypt() {
    local value="$1"
    [ -z "$value" ] && { printf '%s' ""; return 0; }
    case "$value" in
        enc:*)
            local rest ct mac pt
            rest="${value#enc:}"
            if [[ "$rest" == *:* ]]; then
                ct="${rest%:*}"
                mac="${rest##*:}"
                local expected
                expected="$(_secrets_hmac "$ct")"
                if [ -z "$expected" ] || [ "$expected" != "$mac" ]; then
                    echo "Warning: integrity check failed on a stored credential (wrong/rotated key, or tampered data) — refusing to decrypt. Check $SECRETS_KEY_FILE." >&2
                    printf '%s' ""
                    return 0
                fi
            else
                # Legacy pre-HMAC format: no integrity tag to check.
                ct="$rest"
            fi
            pt="$(printf '%s' "$ct" | openssl enc -aes-256-cbc -pbkdf2 -d -base64 -A -pass "file:$SECRETS_KEY_FILE" 2>/dev/null)"
            if [ -n "$pt" ]; then
                printf '%s' "$pt"
            else
                echo "Warning: could not decrypt a stored credential — $SECRETS_KEY_FILE missing or changed since it was written." >&2
                printf '%s' ""
            fi
            ;;
        *)
            printf '%s' "$value"
            ;;
    esac
}
