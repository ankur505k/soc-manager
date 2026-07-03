#!/bin/bash
# ============================================================
# client-setup.sh — run ONCE on each company's Linux server, as root.
#
# IMPORTANT: the company group referenced by GROUP below must already
# exist on the Wazuh manager before you run this script. On the manager,
# that means "Add Company" in company-manager.sh must have run first
# (it calls mgr_create_group). Enrolling into a nonexistent group fails.
#
# This script deliberately does NOT:
#   - edit ossec.conf's <integration> or <localfile> sections — that
#     config lives on the MANAGER, not here (see lib/wazuh_integration.sh)
#   - create a company.conf with secrets on this server — Slack/Telegram
#     credentials live only in the manager's companies.db
#   - install python3/requests — nothing on this box sends notifications
# ============================================================
set -Eeuo pipefail

# ---- Fill these in before running (company-manager.sh prints a
#      ready-to-paste version of this header when you add a company) ----
WAZUH_MANAGER_IP="${WAZUH_MANAGER_IP:-CHANGE_ME}"
GROUP="${GROUP:-CHANGE_ME}"
MANAGER_PUB_KEY="${MANAGER_PUB_KEY:-CHANGE_ME}"
SSH_USER="${SSH_USER:-root}"
# --------------------------------------------------------------------

LOG_FILE="/var/log/vicisoc-client-setup.log"
log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"; }

trap 'log "FAILED at line $LINENO (exit $?)"; exit 1' ERR

if [ "$EUID" -ne 0 ]; then
    echo "Run as root." >&2
    exit 1
fi

for var_name in WAZUH_MANAGER_IP GROUP MANAGER_PUB_KEY; do
    val="${!var_name}"
    if [ "$val" = "CHANGE_ME" ] || [ -z "$val" ]; then
        echo "Set $var_name before running this script (edit the header, or export it)." >&2
        exit 1
    fi
done

OSSEC_CONF="/var/ossec/etc/ossec.conf"

# ---- 1. Install Wazuh agent if not already present ----
log "Checking / installing Wazuh agent..."
if ! command -v /var/ossec/bin/wazuh-agent >/dev/null 2>&1 && [ ! -d /var/ossec ]; then
    if [ -f /etc/debian_version ]; then
        apt-get update
        apt-get install -y curl gnupg2
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
        apt-get update
        apt-get install -y wazuh-agent
    elif [ -f /etc/redhat-release ]; then
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        cat > /etc/yum.repos.d/wazuh.repo <<'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF
        (command -v dnf >/dev/null 2>&1 && dnf install -y wazuh-agent) || yum install -y wazuh-agent
    else
        echo "Unsupported OS. Install the Wazuh agent manually, then re-run this script." >&2
        exit 1
    fi
    log "Wazuh agent installed."
else
    log "Wazuh agent already installed, skipping install step."
fi

# ---- 2. Point the agent at our manager and enroll into the company
#         group, safely (backup, validate, roll back on failure) ----
log "Configuring manager address and enrollment group..."

if [ ! -f "$OSSEC_CONF" ]; then
    echo "ossec.conf not found at $OSSEC_CONF after install — aborting." >&2
    exit 1
fi

ALREADY_ENROLLED=false
if [ -s /var/ossec/etc/client.keys ]; then
    ALREADY_ENROLLED=true
    log "WARNING: client.keys already has content — this agent has enrolled before."
    log "Setting <enrollment><groups> now will NOT change its group retroactively;"
    log "Wazuh only applies enrollment-time group assignment on a fresh enrollment."
    log "If this agent needs to move groups, do it on the manager with:"
    log "  agent_groups -a -i <AGENT_ID> -g $GROUP"
fi

BACKUP="/var/ossec/etc/ossec.conf.bak.$(date +%Y%m%d-%H%M%S)"
cp -p "$OSSEC_CONF" "$BACKUP"
log "Backed up ossec.conf to $BACKUP"

# Replace the manager address within <client><server><address>...</address>
# rather than a blind global sed, so we don't touch an unrelated <address>
# tag if one ever exists elsewhere in the file.
python3 - "$OSSEC_CONF" "$WAZUH_MANAGER_IP" "$GROUP" <<'PYEOF'
import re
import sys

conf_path, manager_ip, group = sys.argv[1], sys.argv[2], sys.argv[3]
with open(conf_path) as f:
    content = f.read()

# Replace the address inside the first <server>...</server> block only.
def replace_address(match):
    block = match.group(0)
    return re.sub(r"<address>.*?</address>", f"<address>{manager_ip}</address>", block, count=1)

new_content, n = re.subn(r"<server>.*?</server>", replace_address, content, count=1, flags=re.S)
if n == 0:
    print("Could not find <client><server>...</server> block — not modifying.", file=sys.stderr)
    sys.exit(1)
content = new_content

# Add/replace a <groups> entry inside <enrollment>, preserving any other
# settings already there (e.g. a non-default <port> or <agent_name>).
# Only create a whole new <enrollment> block if none exists.
enrollment_match = re.search(r"<enrollment>.*?</enrollment>", content, flags=re.S)
if enrollment_match:
    block = enrollment_match.group(0)
    if "<groups>" in block:
        new_block = re.sub(r"<groups>.*?</groups>", f"<groups>{group}</groups>", block, count=1, flags=re.S)
    else:
        new_block = block.replace("</enrollment>", f"  <groups>{group}</groups>\n  </enrollment>")
    content = content[:enrollment_match.start()] + new_block + content[enrollment_match.end():]
else:
    content = re.sub(
        r"(<client>.*?)(</client>)",
        rf"\1  <enrollment>\n    <groups>{group}</groups>\n  </enrollment>\n\2",
        content, count=1, flags=re.S,
    )

with open(conf_path, "w") as f:
    f.write(content)
PYEOF

if ! xmllint --noout "$OSSEC_CONF" 2>>"$LOG_FILE"; then
    log "Resulting ossec.conf is invalid XML — restoring backup."
    cp -p "$BACKUP" "$OSSEC_CONF"
    exit 1
fi
log "ossec.conf updated and validated."

# ---- 3. Install the manager's SSH public key for soc-manager's
#         SSH-based health checks and any future FIM/AR pushes ----
log "Installing manager SSH key for $SSH_USER..."
HOME_DIR="$(eval echo ~"${SSH_USER}")"
mkdir -p "${HOME_DIR}/.ssh"
touch "${HOME_DIR}/.ssh/authorized_keys"
grep -qxF "$MANAGER_PUB_KEY" "${HOME_DIR}/.ssh/authorized_keys" || echo "$MANAGER_PUB_KEY" >> "${HOME_DIR}/.ssh/authorized_keys"
chmod 700 "${HOME_DIR}/.ssh"
chmod 600 "${HOME_DIR}/.ssh/authorized_keys"
chown -R "${SSH_USER}:${SSH_USER}" "${HOME_DIR}/.ssh"
log "SSH key installed."

# ---- 4. Start / restart the agent ----
log "Restarting Wazuh agent..."
if command -v systemctl >/dev/null 2>&1; then
    systemctl restart wazuh-agent
    systemctl enable wazuh-agent >/dev/null 2>&1 || true
    sleep 2
    if ! systemctl is-active --quiet wazuh-agent; then
        log "wazuh-agent failed to become active after restart — restoring ossec.conf backup and retrying."
        cp -p "$BACKUP" "$OSSEC_CONF"
        systemctl restart wazuh-agent || true
        echo "Agent would not start with the new config; ossec.conf was rolled back. Check $LOG_FILE and /var/ossec/logs/ossec.log." >&2
        exit 1
    fi
else
    /var/ossec/bin/wazuh-control restart
fi

log "Client setup complete."
echo
echo "============================================="
echo " Client setup complete."
if $ALREADY_ENROLLED; then
    echo " This agent had already enrolled before — group assignment may"
    echo " need to be applied manually on the manager (see log above)."
else
    echo " Agent will enroll into group '$GROUP' on first connection."
fi
echo " Verify from the manager with: ./verify.sh <company_name>"
echo "============================================="
