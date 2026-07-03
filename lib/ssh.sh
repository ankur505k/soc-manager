#!/bin/bash
# lib/ssh.sh — SSH/SCP helpers for talking to CLIENT servers (always plain
# SSH, regardless of whether the manager itself runs in Docker or
# natively — see lib/docker.sh for the manager side).
# Sourced by other scripts; do not execute directly.

SSH_KEY="${SSH_KEY:-$HOME/.ssh/soc_deploy}"

ssh_require() {
    if ! command -v ssh >/dev/null 2>&1 || ! command -v scp >/dev/null 2>&1; then
        echo "ssh/scp not found. Install with: dnf install -y openssh-clients  (or apt install openssh-client)" >&2
        return 1
    fi
    if [ ! -f "$SSH_KEY" ]; then
        echo "Deploy key not found at $SSH_KEY. Generate it with:" >&2
        echo "  ssh-keygen -t ed25519 -f $SSH_KEY -N '' -C soc-manager-deploy" >&2
        return 1
    fi
    local perm
    perm="$(stat -c '%a' "$SSH_KEY" 2>/dev/null || echo '???')"
    if [ "$perm" != "600" ] && [ "$perm" != "400" ]; then
        echo "Warning: $SSH_KEY has permissions $perm — should be 600. Fixing." >&2
        chmod 600 "$SSH_KEY"
    fi
}

_ssh_opts() {
    local port="$1"
    SSH_OPTS_ARR=(-i "$SSH_KEY" -p "$port" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
}

_scp_opts() {
    local port="$1"
    SCP_OPTS_ARR=(-i "$SSH_KEY" -P "$port" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
}

# ssh_run host user port 'remote command'
ssh_run() {
    local host="$1" user="$2" port="$3" cmd="$4"
    local SSH_OPTS_ARR
    _ssh_opts "$port"
    ssh "${SSH_OPTS_ARR[@]}" "${user}@${host}" "$cmd"
}

# ssh_test host user port -> 0 if reachable and authenticates
ssh_test() {
    local host="$1" user="$2" port="$3"
    ssh_run "$host" "$user" "$port" "echo SOC_MANAGER_SSH_OK" 2>/dev/null | grep -q "SOC_MANAGER_SSH_OK"
}

# scp_push host user port local_path remote_path
scp_push() {
    local host="$1" user="$2" port="$3" local_path="$4" remote_path="$5"
    local SCP_OPTS_ARR
    _scp_opts "$port"
    scp "${SCP_OPTS_ARR[@]}" "$local_path" "${user}@${host}:${remote_path}"
}

# scp_pull host user port remote_path local_path
scp_pull() {
    local host="$1" user="$2" port="$3" remote_path="$4" local_path="$5"
    local SCP_OPTS_ARR
    _scp_opts "$port"
    scp "${SCP_OPTS_ARR[@]}" "${user}@${host}:${remote_path}" "$local_path"
}

# remote_sha256 host user port remote_path -> prints hash or empty on failure
remote_sha256() {
    local host="$1" user="$2" port="$3" remote_path="$4"
    ssh_run "$host" "$user" "$port" "sha256sum '$remote_path' 2>/dev/null | cut -d' ' -f1" 2>/dev/null
}
