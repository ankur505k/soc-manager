# soc-manager

Multi-tenant SOC deployment framework for a Wazuh manager handling
multiple companies' Linux servers.

## Architecture (verified against Wazuh's own docs, not guessed)

- **The manager owns all secrets.** Slack webhooks and Telegram bot
  tokens live only in `companies.db` on the manager, and are written
  into the manager's own `/var/ossec/etc/ossec.conf` as `<integration>`
  blocks. They are never copied to a client server.
- **Slack uses Wazuh's built-in integration** (`<name>slack</name>`) —
  no custom script needed.
- **Telegram needs a custom script** (`templates/custom-telegram.py`,
  deployed to `/var/ossec/integrations/` on the manager) because Wazuh
  has no built-in Telegram integration.
- **Multi-tenant routing works via agent groups.** Each company gets a
  Wazuh agent group (slugified company name). Each company's
  `<integration>` block is scoped with `<group>{slug}</group>`, so only
  that company's agents trigger their own Slack/Telegram destination.
  This is the actual mechanism Wazuh provides for this — not a
  workaround.
- **Client servers only run the agent.** `client-setup.sh` installs the
  agent, points it at the manager, and enrolls it into the correct group
  via `<client><enrollment><groups>`. It does not touch `<integration>`
  or `<localfile>` blocks, does not create a `company.conf`, and does
  not install Python — none of that belongs on the client with this
  architecture.

## Requirements on the manager host

```bash
# AlmaLinux/RHEL:
dnf install -y sqlite openssh-clients

# Debian/Ubuntu:
apt install -y sqlite3 openssh-client
```

If your manager runs in Docker, `docker` itself must be installed and
the manager container running — nothing else Docker-specific is needed
on the host.

Generate the deploy key once:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/soc_deploy -N '' -C soc-manager-deploy
```

`company-manager.sh` refuses to run unless it can find a Wazuh manager —
either a running Docker container matching `wazuh*manager`/
`manager*wazuh`, or a native install (`/var/ossec/bin/agent_groups`
present). See "Docker-based Wazuh managers" below.

## Order of operations for a new company

1. `sudo ./company-manager.sh` → **Add Company**. This creates the
   database row, the Wazuh agent group, and (if you supplied Slack/
   Telegram values) the `<integration>` blocks on the manager —
   restarting `wazuh-manager` once at the end.
2. Run **Check / Complete Enrollment** (or `./deploy.sh <company>`). If
   the client server isn't set up yet, it prints the exact
   `client-setup.sh` invocation with the manager IP, group slug, and
   this manager's SSH public key pre-filled.
3. Copy `client-setup.sh` to the client server and run it there as root.
4. Back on the manager, **Test Connection** (`verify.sh`) to confirm SSH
   reachability and agent status, and **Test Alert** (`test-alert.sh`) to
   confirm the Slack/Telegram credentials themselves work.

## What was tested in this sandbox, and what wasn't

This sandbox has no network access and no `sqlite3`/`ssh` installed, so
I could not run an end-to-end test against real infrastructure. What I
*did* verify here, with actual test runs (not just read-through):

- `lib/wazuh_integration.sh` against a mocked `ossec.conf`, mocked
  `systemctl`, and mocked `agent_groups`: group creation, adding Slack +
  Telegram blocks for one company, adding a second company without
  disturbing the first, updating a company (removing a stale Telegram
  block, replacing the Slack block in place, not duplicating), and full
  removal — all validated valid XML at every step via `xmllint`. Two
  real bugs were caught and fixed this way: a `yes | agent_groups`
  SIGPIPE/`pipefail` interaction that was silently swallowing group
  creation, and a hardcoded `/var/ossec/etc/shared` path that ignored
  the configurable directory.
- `client-setup.sh`'s embedded Python XML editor against three realistic
  agent `ossec.conf` fixtures: no `<enrollment>` block, an existing one
  without `<groups>`, and one that already had `<groups>` set. The third
  case caught a real data-loss bug (an existing `<enabled>`/`<port>` in
  the enrollment block was being clobbered) — fixed to merge only the
  `<groups>` tag.
- `sql_escape()`, `company_slug()`, and every input validator, directly.
- `templates/custom-telegram.py` — syntax-checked with `py_compile`, not
  run against the live Telegram API (no network here).
- `lib/docker.sh` against a mocked `docker` command: single matching
  container (detected + cached to `.wazuh_container`), cached-name reuse
  on a subsequent run, multiple ambiguous containers (correctly refuses
  to guess), and no-docker/no-native (correctly reports "not detected").
- The full Docker-routed `lib/wazuh_integration.sh` flow against a fake
  "container filesystem" (a local directory standing in for `docker cp`/
  `docker exec` targets): two companies added without cross-contamination,
  an update that replaces one company's Slack block and removes its
  stale Telegram block without touching the other company, full removal,
  and a forced restart failure correctly triggering rollback to the
  pre-edit config — valid XML confirmed via `xmllint` at every step.
- `rollback.sh`'s backup listing (newest-first), selection, and restore
  flow, including that it backs up the pre-rollback state before
  overwriting anything.
- `integration.sh sync|status|remove`, including a clean failure message
  for a company that doesn't exist.

What still needs verification on your actual manager + a real client
server, which I cannot do from here: an actual SSH round-trip through
`lib/ssh.sh`, `sqlite3` behavior in `lib/database.sh` (the SQL text is
correct but never executed against real SQLite in this sandbox), a real
`docker exec`/`docker cp`/`docker restart` against your actual
`single-node-wazuh.manager-1`-style container, a real `wazuh-manager`
restart picking up the `<integration>` blocks, and an actual alert
flowing through to Slack/Telegram end-to-end (as opposed to the direct
credential test `test-alert.sh` performs).

## Docker-based Wazuh managers

**Now implemented.** `lib/docker.sh` auto-detects, once per run, whether
the Wazuh manager is a running Docker container (any name matching
`wazuh*manager` or `manager*wazuh`) or a native systemd install, and
caches the container name in `.wazuh_container` so it doesn't re-scan
every invocation. Every other script talks to the manager only through
`wazuh_exec` / `wazuh_copy_to` / `wazuh_copy_from` / `wazuh_restart` /
`wazuh_is_active` — nothing else assumes `/var/ossec` is local.

- If more than one container matches, detection refuses to guess: set
  `WAZUH_CONTAINER=<name>` explicitly (env var, or write the name into
  `.wazuh_container`) and re-run.
- `ossec.conf` edits always follow the same pattern regardless of mode:
  pull a local temp copy (`docker cp` or plain `cp`), edit/validate it
  locally with `xmllint`, push it back, restart, verify, auto-rollback
  on any failure — see `mgr_commit_and_verify` in `lib/wazuh_integration.sh`.
- `rollback.sh` is a separate, on-demand tool for restoring an *older*
  backup than "the last edit" (which already auto-rolls-back by itself).
- `integration.sh sync|remove|status <company>` is a manual CLI into the
  same sync logic `company-manager.sh` calls automatically, for
  re-applying config by hand after something else touched the manager.
- Client servers are unaffected either way — they're always plain
  AlmaLinux/Ubuntu boxes reached over SSH; `client-setup.sh` has no
  Docker awareness and needs none.

## Files

```
company-manager.sh   Main interactive menu
client-setup.sh       Run once per new client server
deploy.sh             Checks/completes enrollment for a company
verify.sh             SSH + agent health check for a company, incl.
                       manager-side agent_control -lc cross-check
rollback.sh            Restore an older manager ossec.conf backup on demand
integration.sh         Manual sync/remove/status CLI for one company's
                        manager-side <integration> blocks
test-alert.sh         Direct Slack/Telegram credential test
schema.sql            SQLite schema
lib/database.sh        SQLite helpers (parameterized-style escaping)
lib/ssh.sh              SSH/SCP helpers — always talks to CLIENT servers
lib/docker.sh           Abstracts the MANAGER: Docker container vs native
lib/config.sh           Input validation, company_slug()
lib/wazuh_integration.sh  Agent group + <integration> block management,
                          routed through lib/docker.sh
templates/custom-telegram.py  Manager-side Telegram integration script
```
