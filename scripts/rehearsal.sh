#!/bin/ksh
# rehearsal.sh — quarterly full-dress restore rehearsal (spec §28/29).
#
# restore-test.sh proves the repo is restorable into a scratch dir. This proves a
# restored copy BECOMES A WORKING MAIL SERVER — the step that actually discharges
# "unforgivable mail loss"; everything else is detection (proposal §5.5).
#
# Run on a THROWAWAY box provisioned from the §6.1 snapshot (never the live box),
# with restic + jq installed and read-only storage credentials:
#   RESTIC_REPOSITORY          sftp:…
#   RESTIC_PASSWORD_FILE       mode-0600 password file
#   REHEARSAL_HEALTHCHECKS_URL Healthchecks ping URL for the ~90-day check (optional)
#
# The script restores /home into the box's live paths, then prints the manual
# checklist. Daemon start-up and the round-trip check stay manual on purpose
# (research §5): they need a real DNS/MX hand-off and a human watching.
#
# Reminder (the automation, since the run itself is manual): a Healthchecks check
# with a ~90-day grace. This script pings /fail if the scripted restore fails;
# after you confirm the manual steps below, ping the success URL (step 6) to mark
# the quarter done. A quarter skipped entirely leaves the check stale → alerts.

set -euo pipefail

# shellcheck disable=SC1091 # lib.sh resolves at runtime from this script's dir
. "$(dirname "$0")/lib.sh"

: "${RESTIC_REPOSITORY:?RESTIC_REPOSITORY is required}"
: "${RESTIC_PASSWORD_FILE:?RESTIC_PASSWORD_FILE is required}"

trap 'hc_fail "$REHEARSAL_HEALTHCHECKS_URL"' ERR

# --target / puts /home/... back under the box's real /home paths.
restic restore latest --target /

printf '\nrestore complete — now the manual full-dress steps:\n'
cat <<'EOF'
1. start daemons:  rcctl start smtpd dovecot httpd gmid
2. git repos:      ssh -T git@<box> and clone a test pass repo (git-shell path)
3. mail round-trip: send to you@example.invalid from an EXTERNAL mailbox, read it
   back over IMAP with a PGP client — ciphertext on disk, decrypt client-side
4. confirm MX/PTR still point at THIS box for the rehearsal window, then revert
5. record the run: date, snapshot id (restic snapshots latest), what passed/failed
6. mark the quarter done: curl the REHEARSAL_HEALTHCHECKS_URL (only after all
   of the above pass — this is what stops the ~90-day reminder)
EOF
