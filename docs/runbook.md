# Runbook

This is the public half of the operational runbook for kyriakon.net. Each section below is a procedure for something that happens on this platform, written in the order the steps run, or a record of what was decided or checked where there is no step to run. The procedures live here, beside the configuration they describe, so a reader can check them against it.

The other half stays off the repository. It holds who holds the second root credential, where the offline copy of the backup repository lives and what unlocks it, how to reach the operator when the operator is unreachable, and the dates the tokens were rotated. `docs/operations/private-half.md` lists the headings that half needs and what belongs under each.

## How to read this

Every command runs on the mail box as root unless the step says otherwise. `doas` is how an admin reaches root, because root over SSH is disabled (`openbsd/etc/sshd_config`, `PermitRootLogin no`) and each admin logs in with a personal key as an unprivileged user. Every root action then has a name on it.

Three paths appear throughout:

- `/usr/local/src/kyriakon-infra` is the box's checkout. It is owned by root and readable by everyone, so the operator can read it and run what is in it through `doas` without a root login, while root stays the only account that can change it. Update it with `doas git -C /usr/local/src/kyriakon-infra pull --ff-only`.

  A box whose checkout is still under `/root` cannot be read by the operator at all, because `/root` is mode 0700. Move it once:

		doas install -d -m 0755 -o root -g wheel /usr/local/src
		doas mv /root/src/kyriakon-infra /usr/local/src/kyriakon-infra
		doas chown -R root:wheel /usr/local/src/kyriakon-infra
		ls /usr/local/src/kyriakon-infra   # as the operator, this should list
- `/root/bin` holds the copies that cron runs. `scripts/deploy-mail.sh` installs `lib.sh`, `abuse-monitor.sh`, `backup.sh`, `renew-acme.sh` and `restore-standup.sh` there, and `scripts/cron-apply.sh` writes the crontab lines that call them.
- `/root/.kyriakon-env` holds the box's values, mode 0600, one `export VAR=value` per line. `scripts/setup-env.sh` installs and merges it, and every cron line sources it, so no value is typed twice.

Deploy the configuration with `doas ksh /usr/local/src/kyriakon-infra/scripts/deploy-mail.sh`. It is idempotent, it installs the mail and web configuration, it rebuilds the Dovecot plugin and the encryptor, it installs every `keys/*.asc` into the keyring, and it restarts the daemons. It prints the firewall and `sshd_config` steps instead of taking them, because both are propose-only changes that a human applies.

Run `doas ksh scripts/check-hygiene.sh` when you want the state of the box without changing anything. It reports permission drift against mtree, the blocklist verdict for the box's address, whether a cron job can still reach the tools it needs, whether the finger service is intact, and whether the terraform guard and the restore snapshot are still in place. It exits non-zero when something is wrong.

## What is not built yet

These procedures name the pieces that exist at this commit, and mark the ones that do not:

- The onboarding service, its drain and the `onboardctl` command are decided in #156 and not built. Provisioning a member is manual until they land.
- The per-member hosting configuration is merged into the repository and not applied: the chroot under `/home/www`, the generated vhost indexes, the port split that separates git from the chrooted sftp server. Applying it is a sequence of propose-only steps rather than a script, so it is done once, by hand, and the order is in the pull request that added it (#160).
- The quota is scripted and has been applied: `scripts/quota-apply.sh --enable` turns quotas on and `--all` applies the 5 GB allowance to the accounts that already exist. `scripts/add-user.sh` sets it at creation.

  `/home` carries user quotas only, since every account has its own group of the same name. The boot-time check in `/etc/rc` runs `quotaon -a` without that restriction, so it prints one line about the missing `/home/quota.group` on every boot before it reports user quotas turned on. That line is expected, and it is the only place it appears, because `--enable` passes `-u` and stays quiet.
- Per-member certificates and the queue that holds them against the Let's Encrypt refill rate are decided in #166 and not built. A member's own vhost has no certificate to serve yet.
- The offline copy of the backup repository is #109 and #116, both open.
- The keyring drift check, the drain health signal, the snapshot-recency signal and the root filesystem signal are built and deployed by `scripts/deploy-mail.sh` with the cron lines from `scripts/cron-apply.sh`.

## Provision a member

Provisioning is manual today. The service that will take it over is covered in the next section.

1. Create the account.

		doas ksh scripts/add-user.sh <username>
		doas passwd <username>

   `add-user.sh` creates the OS account with `/sbin/nologin` as its shell and an empty Maildir at `/home/<username>/Maildir`. The account starts with no password, which is why `passwd` follows.

   It also sets the account's 5 GB allowance, and joins it to the `members` group that the sshd configuration matches for sftp and git. `doas ksh scripts/quota-apply.sh --clear <username>` removes an account's allowance and leaves everything else about it alone, where an account without a limit is unlimited: that is the way to exempt one account from the 5 GB, not a way to stop it using disk. If either is missing on the box it prints a note instead of failing, because neither is needed for mail: `doas ksh scripts/quota-apply.sh --enable` turns quotas on, and `doas ksh scripts/deploy-mail.sh` creates the group. An account created before either ran needs `doas usermod -G members <username>` and `doas ksh scripts/quota-apply.sh <username>`.

2. Publish the member's public key. Put their ASCII-armored key at `keys/<localpart>.asc`, commit it, and deploy.

		doas git -C /usr/local/src/kyriakon-infra pull --ff-only
		doas ksh /usr/local/src/kyriakon-infra/scripts/deploy-mail.sh

   Delivery reads the keyring per message, so an account with no usable key bounces inbound mail immediately instead of queueing it.

3. Check the account.

		id <username>
		stat -f '%Su' /home/<username>/Maildir
		doas ksh scripts/check-hygiene.sh

   The first command must show `/sbin/nologin` as the shell, and the second must print the username. A Maildir owned by root lets the account authenticate while every IMAP session fails.

4. Check delivery with a message from an address outside the platform, then read the stored file.

		ls -t /home/<username>/Maildir/new/* | head -1
		doas gpg --list-packets /home/<username>/Maildir/new/<the file> | head

   The message must be PGP ciphertext in the Maildir. Plaintext, or a quoted copy of one, is a fault in the delivery path and not something to work around.

Do not give the account a shell. `chsh -s /bin/ksh <username>` undoes the platform's central safety property. The operator account is the one exception, and `deploy-mail.sh` flips it back to `/bin/ksh` on every run.

The per-member hosting design in #154 adds three things to this path: membership of the `members` group, the generated `httpd` and `gmid` include lines for the site, and the quota entry. Two of the three are scripted now, and `add-user.sh` does them. The third is the include line for a member's own vhost, which `scripts/cron-apply.sh --web` rewrites from `/etc/httpd.d` and `/etc/gmid.d` once member sites exist.

## Provision through the onboarding service

The service is decided in #156 and not built. This section records the shape an operator will work with, so that the decisions are findable beside the procedures they change.

Two halves run with different privilege. The handler listens on loopback behind `relayd`, holds no secrets, writes the raw Stripe body and its signature header, files applications, and writes account-page intents. The drain is a one-minute cron job, with a second hourly job for the sweeps, and it owns provisioning, manual payment credits, key publication pull requests, certificate requests, the lifecycle transitions and their notices, the 90-day application purge and the grace sweeps. Notices leave through the local `smtpd` enqueuer, so `filter-dkimsign` signs them the way it signs everything else.

The state is flat files, one directory per account. `account.json` holds the state, the contact and recovery addresses, the key fingerprints, the rail and token reference, the paid-until date and the approval decision. `notices.jsonl` appends each notice with its timestamp. `application.json` holds the application answers and the purge deletes it. A top level `intents/` directory holds pending work, one file per item, and `journal.jsonl` records transitions. The drain appends the journal entry before it carries the transition out, so a crash leaves a record it can rerun. The build fixes the store's path, and the drain adds that path to the payload of `scripts/backup.sh`, which today copies `/home`, `/etc/mail` and the capsule certificate pair.

Read a member's record by reading their `account.json`. The documents carry a version and the drain validates them on read, so a malformed file stops the drain with an error instead of being skipped.

When the drain is stuck, read in this order: the drain's log, the oldest file in `intents/`, then the last line of `journal.jsonl`. An intent that fails validation names its own file in the log, and a backlog of unapplied intents is what the monitoring signal in #173 alerts on. Rerunning the drain is safe. It verifies each event before acting, keys on the event id, and applies state through the repo-tracked scripts.

Do not edit `account.json` by hand. A hand edit that fails validation stops the transition rather than being repaired, and the journal then disagrees with the file.

## Replace a member's key

Rotation is self-service and never needs a signing key. The account page starts it; the new key applies after a confirmation from every address on the account and a 72-hour window in which any of them can cancel it, and a request signed by the current key skips the delay. Where the member gave no address outside the platform, the delay stands and the warning goes out encrypted to the old key, which only the holder can read. Decided in #155.

The service writes the key into `/etc/kyriakon/keys/<localpart>.asc` so delivery keeps working, and opens a pull request containing `keys/<localpart>.asc` for publication.

To replace a key by hand, before the service is built:

1. Put the new public key in `keys/<localpart>.asc` and deploy.

		doas git -C /usr/local/src/kyriakon-infra pull --ff-only
		doas ksh /usr/local/src/kyriakon-infra/scripts/deploy-mail.sh

2. Check the deployed key.

		doas gpg --list-packets /etc/kyriakon/keys/<localpart>.asc | grep -E 'tag=|features|pref-aead'

   A key that advertises AEAD makes GnuPG emit packet tag 20, which Thunderbird and RNP cannot read, so delivery would produce mail the member cannot open. The wanted shape is `features: 05` and no `pref-aead-algos` line.

3. Check the encrypt path the daemon uses.

		echo test | doas gpg --batch --no-tty --no-options --encrypt --armor \
			--no-encrypt-to --recipient-file /etc/kyriakon/keys/<localpart>.asc \
			--homedir /var/run/kyriakon/gpg | doas gpg --list-packets | grep -E 'tag=|mdc_method'

   `tag=18` with `mdc_method: 2` is the pass. `tag=20` or an `aead` line means the old key is still deployed.

4. Send a message from an address outside the platform and ask the member to open it. Their client failing to decrypt is the signal that the key on the box is not the key they hold, and it arrives within a day.

`scripts/rekey-mail-key.sh` is not a replacement. It re-signs the same key so GnuPG stops advertising AEAD and leaves the fingerprint unchanged, so it replaces no key material on the box and reaches no member's key.

Do not edit the keyring on the box by hand. The next deploy overwrites it from the repository, so the edit either disappears or leaves the published set disagreeing with what delivers, which is the drift the check in #171 exists to alert on.

The drift check in #171 runs on the box at 04:00 daily and compares the fingerprints in `/etc/kyriakon/keys` against the merged published set in `keys/`. It alerts when a published key is missing from the box, when a fingerprint differs between the two, or when a key has sat unpublished for more than seven days. A second run, off the box, compares the published set against a recorded copy in a repository the box's publish token cannot write, held through `KEYRING_STORE`, so a rewrite of a key that already reached `main` is seen even if the box made the commit. Delivery does not change when this alerts, since the box keyring is what delivers, so the repair is a human's: merge the pending publication, or put back the key the member expects. Both cron lines belong in `scripts/cron-apply.sh`. The check and its cron lines are not on main at this commit.

### A member who has lost their key

A member who still holds the recovery phrase restores the same key from it, so the public half does not change and nothing needs doing on the box. That is the path the signup flow is built around, and it is why rotation never requires a signing key.

A member who has lost the private key and the phrase cannot read what is stored for them. The platform holds no key that opens mail and no account recovery that restores content, which `docs/refusals.md` states as a refusal rather than a limit. The account can still be made to work again: set a new password, and take a new key through the rotation path above. Mail delivered before the new key existed stays unreadable, and mail delivered after it becomes readable.

	doas passwd <username>

Decide how the member proves the account is theirs before you set that password, and record the decision on the account. Where the member gave no address outside the platform, the notice that a new key is in place can only reach them in the mailbox the new key opens, so tell them by whatever channel they used to ask.

## A lifecycle notice that bounces

The lifecycle notices go to the member's platform address and to every other address on the account. The drain records each send. A hard bounce at the platform address means the mailbox cannot receive, which is one of the things a notice may be about. A hard bounce at the only address we hold means no channel reached the member, and the grace clock stops until a channel works. Decided in #153.

1. Find the bounce.

		doas grep <localpart> /var/log/maillog | tail -20
		mailq

   `/var/log/maillog` keeps seven days (`openbsd/etc/newsyslog.conf`), so read it before the record rotates away.

2. Read the addresses and the notice history in `account.json` and `notices.jsonl`.

3. Send the notice again over a channel that works and record the send. With the drain built, `onboardctl` re-sends and writes the record. Without it, append one object to `notices.jsonl` in the same shape as the objects already there, because a deletion has to be able to show what was sent and when.

4. Check the account's grace date. A bounce at every address extends the grace until a channel works, so the date moves out rather than the account being deleted unread.

Do not let a deletion proceed on an account whose only notice bounced. That is the case the automated deletion path carries safeguards for, and the safeguards are the notices and the extended clock.

## Suspend an account

The AUP ladder is detect, warn with 72 hours to respond, suspend, then delete after a 40-day grace (`docs/aup.md` section 5). Suspension follows the state contract in #153: outbound mail stops at once, the site and the Gemini capsule come down, the account page stays open so the member can read the reason and answer, and inbound mail keeps arriving. Refusing inbound mail is a case-by-case decision the operator records, not the default, so a third party's message is not lost during a suspension that may be the wrong call.

1. Stop outbound mail by moving the account into a login class that rejects submission. IMAP keeps working, no daemon restarts, and no second password store is needed (research in #168).

		doas usermod -L lapsed <username>

   The class file lives with the deploy rather than with the account.

2. Take the site down. The per-member vhosts come from generated include files that `httpd.conf` and `gmid.conf` each read, so the site comes down by removing the member's include line and reloading.

		doas httpd -n -f /etc/httpd.conf
		doas gmid -n -c /etc/gmid.conf
		doas rcctl reload httpd gmid

   Keep the `/.well-known/acme-challenge` path served, or the certificate renewal for that name fails.

3. Record the reason and the date on the account, and send the notice with the reason and how to answer.

4. Check afterwards that submission fails for the account, that IMAP still works, and that the site is down while the certificate is still valid.

The generated include files, the `members` group and the account page all arrive with #154 and #156, so steps 2 and 3 are the shape those tickets decided rather than something an operator can do today.

Do not refuse inbound mail as the default, and do not edit `pf.conf` or `sshd_config` on the box to enforce any of this. Both are propose-only changes; a pull request carries the diff and a human applies it.

## When a member has died

Nothing is released, and the ordinary paths apply. The rule in `docs/planning/specs/data-subject-requests.md` stands: a request from outside the account page is confirmed by the password or by a message from the account's own address signed with the member's key, and where neither can be produced the operator says so and does not answer as though identity were established. A bereaved family holds neither, so nothing can be handed over on their request.

The platform holds nothing readable to hand over in any case: the mail is ciphertext under a key only the member holds, and the written record is the member's own data, whose one route out is the export the account page runs. The reply says both, that nothing is released and that nothing readable exists to release.

The account then takes the ordinary sequence: the notices to every address held, the lapse for non-payment, the 40-day grace, and deletion, which is the section below. A monastery or a parish as the member is the same, its account lapsing and deleting like any other, and a domain on the own-domain tier lapses with it. A free account never lapses, so no lapse and no grace period run for it, and the account stays until the operator closes it under the rule for one that has been unreachable and unused for a year, or a breach of the acceptable use policy closes it sooner.

Decided in #276.

## Close an account and delete it

A member asks for closure from the account page, or a refund opens it. Closing is a seven-day window. The account works normally throughout so the member can retrieve everything, delivery continues, and the member can cancel the closure from the account page. Day seven ends the window, and the deletion is automated. Decided in #153, which supersedes the proposal's sentence about a human performing the final delete.

Deletion is a sequence, and the order stops access before anything is destroyed, so the window between the decision and the deletion is closed. The sequence is from the research in #168.

1. Close access.

		doas usermod -Z <username>
		doas usermod -S '' <username>

   The empty second argument empties the account's secondary groups.

2. Remove the account and its home, which takes the Maildir, the git repositories and the web and Gemini roots with it.

		doas userdel -r <username>

   `userdel` rebuilds the password database itself. Once the account is gone, mail for it meets a permanent failure instead of queueing.

3. Remove the primary group, then confirm nothing else lists the account.

		doas groupdel <username>
		grep -F <username> /etc/group

   No output from the `grep` is the expected result. `add-user.sh` creates each account with `-g =uid`, which makes a group whose id matches the uid, and `userdel` does not remove it.

4. Remove the keyring entry on the box and in the repository.

		doas rm /etc/kyriakon/keys/<localpart>.asc
		git rm keys/<localpart>.asc

   Both steps are needed. `deploy-mail.sh` installs each key it finds and never removes one that has left the set, so deleting the repository file alone leaves the on-box entry in place and delivery keeps working for a key that is supposed to be gone.

5. Remove the per-member vhost files and their include lines, then reload.

		doas rm /etc/httpd.d/<username>.conf /etc/gmid.d/<username>.kyriakon.net.conf
		doas vi /etc/httpd.d/index.conf
		doas vi /etc/gmid.d/index.conf
		doas httpd -n -f /etc/httpd.conf
		doas gmid -n -c /etc/gmid.conf
		doas rcctl reload httpd gmid

6. Revoke the certificate and remove its files. Removing the files alone does not un-issue anything, so the revocation is the step that matters.

		doas acme-client -r <username>.kyriakon.net
		doas rm /etc/ssl/<username>.kyriakon.net.fullchain.pem
		doas rm /etc/ssl/private/<username>.kyriakon.net.key

7. Clear the quota entry. `edquota` has no delete operation, and a limit of zero means no limit is imposed.

		doas ksh /usr/local/src/kyriakon-infra/scripts/quota-apply.sh --clear <username>
		doas repquota -u /home

   The allowance is read back before the command reports success, so a clear that did not take says so rather than passing quietly. Nothing about the account's files changes here: this removes the limit, and the deletion that follows removes the data.

8. Regenerate the finger page, which is derived from the httpd and gmid configuration.

		doas ksh scripts/gen-finger-page.sh > /tmp/finger.txt
		doas install -m 0644 /tmp/finger.txt /etc/kyriakon/finger.txt

DNS needs nothing. The zone answers every member subdomain from a wildcard, so there is no per-member record to remove.

Two things survive, and both are deliberate. The payment state dies with the account, while the financial ledger is keyed by the approval token and holds the amount, the date, the rail and the paid-until date with no username and no name (ADR 0009), so six years of records stop resolving to a person. The backup repository holds the home until the retention window ages it out, which is about six months, and it cannot delete a single file because it is content addressed (`restic forget --keep-daily 30 --keep-weekly 8 --keep-monthly 6`). The retention window is the mechanism, and `docs/planning/research/encrypted-backup-restore.md` records the reasoning.

The username is held for 90 days and then released. A returning member applies as a new applicant, because the mailbox is gone.

Do not delete an account before its window ends, and do not delete by hand anything this sequence covers. The sequence exists so that a deletion is complete rather than mostly complete.

## Restore from backup

`scripts/backup.sh` writes an encrypted restic snapshot of `/home`, `/etc/mail` and the capsule certificate pair to the storage box every night, with retention of 30 daily, 8 weekly and 6 monthly snapshots. `scripts/cron-apply.sh` installs its cron line.

The weekly test runs on a box that exists for the length of the run. From the mail box:

	doas ksh /root/bin/restore-standup.sh
	doas ksh /root/bin/restore-standup.sh --dry-run

The first form creates a throwaway box from the snapshot labelled `kind=restore`, runs `scripts/restore-test.sh` on it over ssh, and destroys it on every exit path. The second prints what it would run and touches nothing. The test restores with a read-only storage sub-account, so a fault on the throwaway box cannot damage the repository it is testing.

The test already runs these checks, in this order: the newest snapshot is less than 30 hours old, which catches a backup that silently stopped; `restic check` for repository structure and pack integrity; a full restore; the canary byte-identical, which catches a backup that stopped including `/home`; that `/etc/mail/dkim/private.rsa.key` and `/etc/mail/smtpd.conf` are in the snapshot while `/root/.kyriakon-env` and `/root/.restic-pass` are not; that every restored Maildir message is PGP ciphertext; `git fsck` on every restored repository; and that the restored node count matches the snapshot's. It pings its Healthchecks check on success and its failure URL on error, so a run that never happens alerts on its own.

To prove a restored copy becomes a working mail server, rather than merely restoring, run the rehearsal on a throwaway box provisioned from the template.

1. Restore the latest snapshot into the box's real paths. `doas` resets the environment, so the credentials go through `doas env`.

		doas env RESTIC_REPOSITORY=... RESTIC_PASSWORD_FILE=... ksh scripts/rehearsal.sh

2. Work through the checklist the script prints. Start the daemons, clone a test `pass` repository over ssh, send a message from an address outside the platform and read it back over IMAP with a PGP client, confirm MX and PTR point at this box for the window, record the date and the snapshot id, then ping the rehearsal check. The check carries a period of about 90 days, so a skipped quarter alerts on its own.

3. Put the configuration on a replacement box from the repository, in this order.

		doas ksh scripts/setup-env.sh
		doas ksh scripts/deploy-nsd.sh
		doas ksh scripts/deploy-mail.sh
		doas ksh scripts/pf-apply.sh --check
		doas ksh scripts/pf-apply.sh
		doas ksh scripts/cron-apply.sh --check
		doas ksh scripts/cron-apply.sh

   `pf-apply.sh` appends the firewall fragments and is the human step. It prints the diff first, checks the candidate with `pfctl -n` before touching the live file, keeps a timestamped copy of the file it replaces, and loads nothing that `pfctl` rejects.

The offline copy of the repository does not exist yet (#109 and #116). Until it does, the repository password is the only thing standing between a lost storage box and a lost archive, and the storage box sits with the same provider as the box itself. Keep the offline copy of the password where the private half says.

Do not restore over a live box's `/home` while the daemons are running, and do not give a test box write access to the repository. The weekly test holds a read-only sub-account for exactly that reason.

### Regenerate the capsule certificate pair

A capsule serves a long-lived self-signed certificate, generated once with a ten-year life and never renewed, so nothing mints its key again and the file is the only copy. Losing it changes every capsule's certificate at once and every reader's client trusts once more, because a gemini client pins the certificate on first use. The pair sits in the snapshot and a restore brings it back. When it is lost everywhere, generate it again, reload `gmid`, and update the fingerprint the help page publishes.

1. Generate the pair with `openssl req -x509`, driven from a configuration file that sets `subjectAltName = DNS:kyriakon.net, DNS:*.kyriakon.net` and `basicConstraints = critical, CA:FALSE`. The platform pair is `/etc/ssl/capsule-kyriakon.net.crt` and `/etc/ssl/private/capsule-kyriakon.net.key`; an own-domain pair is `/etc/ssl/capsule-<domain>.crt` with its key under `/etc/ssl/private`. The LibreSSL on this box carries a configuration file rather than command-line extension flags.

2. Check the result and reload `gmid`.

		doas gmid -n -c /etc/gmid.conf
		doas rcctl reload gmid

3. Update the fingerprint the help page publishes. Nothing regenerates the pair on a schedule, because the fingerprint only changes when a human runs this step.

## A failed certificate renewal

Renewal runs daily from cron.

	doas ksh /root/bin/renew-acme.sh

The script renews `mail.kyriakon.net` for Dovecot and smtpd, `kyriakon.net` for httpd, and `kyriakon.com` for httpd. It restarts only the daemons whose certificate changed, and it prints `still current` for a certificate that is not near expiry. It exits non-zero when a renewal fails, and cron mails that to root.

When it fails:

1. Read the reason.

		doas acme-client -v mail.kyriakon.net

2. Check that the web server is up and that the challenge directory exists.

		doas rcctl check httpd
		ls -d /var/www/acme

   `httpd.conf` serves the challenge from that directory, and `acme-client` writes the file there. `acme-client` implements the `http-01` challenge only, so a name that cannot be reached over port 80 cannot be validated.

3. Check that the name resolves here and that the port is open.

		doas dig +short @ns1.he.net mail.kyriakon.net A
		doas pfctl -sr | grep -E 'port (http|80)'

4. Check the daemons that hold the certificate, and read the expiry of what is installed.

		doas rcctl check dovecot smtpd httpd
		openssl x509 -enddate -noout -in /etc/ssl/mail.kyriakon.net.fullchain.pem

Issuance is limited by Let's Encrypt's refill rate of one new certificate every 202 minutes for a registered domain, and renewals are exempt because they carry the same identifier set. A per-member certificate queue that drains oldest first and respects `Retry-After` is decided in #166 and belongs to the hosting build (#154). Today the limit binds only the three names in `openbsd/etc/acme-client.conf`.

Do not rerun the client in a loop. Five certificates are allowed for one exact set of identifiers in seven days, and five authorization failures for one identifier in an hour block new orders for that identifier. Repeated installation of the client or deletion of `/etc/acme/letsencrypt-privkey.pem` is the documented way to reach the first of those limits. Do not force a renewal with `-F` unless the installed certificate is known to be wrong.

## A disk filling up

Read the filesystems first.

	df -h

Then find where the space went.

	doas du -sh /home/*
	doas quota -u <username>
	doas repquota -a
	doas du -sh /var/log /var/spool/smtpd /var/nsd /root/.cache/restic

Mail keeps arriving for an account whose password is locked, because delivery resolves the recipient from the user database and never from the password, and the account's allowance is what bounds that. The allowance is live: `/home` is mounted with quotas, `/home/quota.user` holds the records, and each account is written a soft 5 GB and a hard 5.5 GB limit. Mail arriving after a suspension therefore fills an account to its limit and no further, which is what keeps the suspension recoverable instead of filling the disk.

On the root filesystem the likely places are the log directory, which `openbsd/etc/newsyslog.conf` bounds at seven days, the mail queue, and the restic cache. The root filesystem alert is one of the signals in #173 and does not exist yet.

Check what is queued before removing anything from the queue.

	doas smtpctl show queue
	doas smtpctl show stats

An account's allowance is a 32-byte record in `/home/quota.user`, and `scripts/quota-apply.sh` writes it directly. The kernel reads that record the first time it accounts for a user and keeps its own copy after that, so an account it has already seen does not pick up a changed allowance, and `quotaoff` followed by `quotaon` does not help: the release drops the reference while leaving the record in the cache. Changing an existing account's limits therefore takes the order the script prints, write with quotas off and then reboot. An account being created needs none of it, because nothing has read its record yet.

Do not delete files under `/home` to free space. The account lifecycle is the path that removes member data, and a hand deletion leaves the account, the keyring entry and the vhosts behind. Do not remove the DKIM key at `/etc/mail/dkim/private.rsa.key`, the queue key at `/etc/mail/queue.key`, or anything under the restic repository. The first two exist nowhere else, and the third is the backup.

### How much the box carries

The box is a Hetzner `cx23` in `hel1`: 2 vCPU, 3.9 GiB of memory, and one 40 GB disk divided into partitions, of which `/home` is 8.2 GB. Every member is promised 5 GB, which is proposal 6.5 and is enforced: `/home` is mounted with quotas, `/home/quota.user` holds the records, and `scripts/quota-apply.sh` writes each account a soft 5 GB and a hard 5.5 GB limit. At that promise the partition carries one member and two would overrun it, and at the 1.9 MB of mail the account on it now uses, it would carry thousands.

The promise is the one that is sold, so the box's resource is grown when it becomes the wall rather than a member count being fixed in advance, and the choice between the two ways of growing it is made at the time: attaching a volume, or moving to a larger server type.

The trigger is the `/home` partition, looked at in the quarterly pass in `## Run the quarterly indirect-tax check`:

	df -h /home
	doas repquota -a

At the same time, look at the storage box's usage in its console, because it holds the nightly repository and it is the only place a deleted account outlives its retention window. Approval is what rations the box, since a person approves every application before a payment link is sent, so no other count is needed. Decided in #275.

## When mail is not flowing

Work inbound first, then outbound, and stop when you find it. `doas ksh scripts/check-hygiene.sh` reports the state of the box without changing anything.

1. Are the daemons up?

		doas rcctl check smtpd dovecot kyriakon_encrypt spamd spamlogd httpd gmid inetd

   `spamlogd` is easy to miss, and greylisting never releases a sender without it, because it is the daemon that writes the whitelist entries spamd reads.

2. What does the log say?

		doas tail -100 /var/log/maillog
		doas grep <localpart> /var/log/maillog | tail -20

   `/var/log/maillog` keeps seven days, so the record of an event from last week is gone.

3. What is queued, and where is it going?

		mailq
		doas smtpctl show queue
		doas smtpctl show stats

4. Is greylisting the cause? It stays off until the firewall fragments are applied, and the deploy reports which state the box is in.

		doas pfctl -sr | grep 'divert-to 127.0.0.1'
		doas spamdb | grep -c '^GREY|'
		doas spamdb | grep -c '^TRAP|'

5. Does the name still point here?

		doas dig +short @ns1.he.net kyriakon.net MX
		doas dig +short @ns1.he.net mail.kyriakon.net A

6. Is there a usable key for the recipient? Delivery fails closed, so a message with no key bounces at once rather than queueing.

		doas ls -l /etc/kyriakon/keys/<localpart>.asc
		doas gpg --list-packets /etc/kyriakon/keys/<localpart>.asc | grep -E 'tag=|features'

7. Is the encryptor running? Delivery depends on its socket.

		doas ls -l /var/run/kyriakon/encrypt.sock
		doas rcctl restart kyriakon_encrypt

8. Does authentication work?

		doas doveadm auth test <username>
		doas doveconf -n

9. If inbound is fine and outbound is not, check the outbound path. The submission listener holds the mail host's certificate, `filter-dkimsign` signs submission and local mail with the `mail` selector, and SPF and DKIM decide whether the message lands.

		doas smtpctl show stats
		openssl x509 -enddate -noout -in /etc/ssl/mail.kyriakon.net.fullchain.pem
		doas dig +short @ns1.he.net mail.kyriakon.net TXT
		doas dig +short @ns1.he.net mail._domainkey.kyriakon.net TXT

Do not restart every daemon at once. It hides which one was broken, and the log that would have named it rotates with the restart. Do not turn greylisting off by editing `/etc/pf.conf` in place, because that file is reviewed line by line and `scripts/pf-apply.sh` only appends. Test with an ordinary message from an address outside the platform.

## When the blocklist check stops answering

`abuse-monitor.sh` asks four blocklists about this box's address every fifteen minutes, strongest first, and takes the first verdict any of them gives. When the strongest, `zen.spamhaus.org`, stops giving one, the alert says the address is clean on a weaker list only. That is a coverage report rather than a listing: nothing needs delisting, but a listing on the strongest list would go unnoticed, so the alert is worth acting on rather than muting.

The reason is in the alert, and the two reasons need different responses.

1. `refused` or `servfail`: the zone is reachable and the query reached it, and the fault is in how it answered. Spamhaus's DNSBL zones answer NS and SOA queries in a way that does not match RFC 1034, and QNAME minimisation, on by default in unbound, needs those answers. That makes the asymmetry worth recognising: a lookup that ends in a record resolves, while a lookup that ends clean does not, so a listed address is found and a clean one is not. Spamhaus's own write-up is at `spamhaus.org/resource-hub/dnsbl/qname-minimization-and-spamhaus-dnsbls/` and ISC's analysis at `kb.isc.org/qname-minimization-and-spamhaus`.

	Spamhaus recommends turning the feature off for this, which in unbound is one line in the `server:` section of `/var/unbound/etc/unbound.conf`:

		qname-minimisation: no

	That line is in the tracked `openbsd/etc/unbound.conf`, which is the base system's file plus this setting, and `scripts/deploy-mail.sh` installs it, validates it with `unbound-checkconf`, and restarts the resolver. Fixing it on a running box without a deploy is the same three steps:

		doas cp /usr/local/src/kyriakon-infra/openbsd/etc/unbound.conf /var/unbound/etc/unbound.conf
		doas unbound-checkconf /var/unbound/etc/unbound.conf
		doas rcctl restart unbound
		doas ksh /usr/local/src/kyriakon-infra/scripts/check-hygiene.sh

	Validate before restarting, always: this resolver is DNS for everything else on the box, so a config that is wrong on disk while the old one is still loaded is recoverable, and the reverse is not.

	The setting is global, because unbound has no per-zone form of it: every query from this box stops using QNAME minimisation, not only the blocklist ones. Spamhaus's argument for accepting that is that all queries in a blocklist lookup go to the same nameserver, so the privacy gain there is nil, and their measurement is that a lookup costing five queries costs one without it. ISC disagrees, holding that the resolver should not give up a privacy feature for a server's non-compliance. Treat it as a workaround with a decision attached, and revisit it if Spamhaus fixes the zone or unbound grows a per-zone setting.

	That line is in place on this box, so a `servfail` here needs the other reading as well. The zone's answers carry a ten-second negative time to live, so the check is a cold lookup almost every time, and a walk that Spamhaus's authoritative servers do not answer inside unbound's timeouts can surface as `servfail` rather than as silence. Run the check by hand before changing anything:

		doas ksh /usr/local/src/kyriakon-infra/scripts/check-hygiene.sh

	One `servfail` that does not repeat was that timeout, and nothing needs doing. A `refused` is Spamhaus's policy rather than a local fault, but it still says something about this box: the control answer comes back only after the query has left on the system resolver, so a refusal means the box's own resolver was not the one asked. The hand run prints which resolver answered.

2. `no-answer` or `silent`: nothing came back at all, which means the look-up timed out rather than being answered. The zone's answers live ten seconds, so the check is a cold walk nearly every time, and Spamhaus's servers are occasionally slower than the query's patience. Run the check by hand and see whether the silence repeats.

	A refusal is not this case, and neither is an unbound that has stopped: a query that leaves on the system resolver is answered with Spamhaus's control answer and recorded as `refused` above, so silence here means nothing answered in time rather than that the wrong resolver was asked.

	The monitor counts a downgrade rather than mailing on each one, and reports it once it has held for three consecutive runs, three quarters of an hour apart. A single `no-answer` therefore passes quietly, and an alert means the condition has lasted.

A clean verdict names the zone it came from and what it skipped, and `scripts/check-hygiene.sh` prints the same verdict on demand, along with whether the resolver on this box was the one asked, since querying `127.0.0.1` and querying a public resolver get different answers from Spamhaus.

## Rotate or revoke the DKIM signing key

The signing key is `/etc/mail/dkim/private.rsa.key`, the published record is at selector `mail` in `openbsd/etc/nsd/kyriakon.net.zone`, and the proposal records rotation yearly or on compromise.

A rotation that keeps sending unbroken needs a second selector, because a message signed under `mail` and verified after the key underneath `mail` changed fails.

1. Generate the new key on the box and print its public half.

		doas openssl genrsa -out /etc/mail/dkim/private.rsa.next 2048
		doas openssl rsa -in /etc/mail/dkim/private.rsa.next -pubout -outform DER | openssl base64 -A

2. Publish that value at a new selector in `openbsd/etc/nsd/kyriakon.net.zone`, splitting it into two quoted strings at 255 bytes the way the existing record does, and bump the SOA serial. `nsd` rejects a single longer character string and then serves nothing for the zone.

3. Point the signing filter at the new selector in `openbsd/etc/smtpd.conf`, deploy both files, and wait for the new record to be served. The zone's default TTL is 3600 seconds.

		doas git -C /usr/local/src/kyriakon-infra pull --ff-only
		doas ksh /usr/local/src/kyriakon-infra/scripts/deploy-nsd.sh
		doas ksh scripts/deploy-mail.sh
		doas dig +short @ns1.he.net <newselector>._domainkey.kyriakon.net TXT

4. Confirm outbound mail still passes DKIM, then leave the old selector published until every message signed with it is older than the mail queue lifetime of four days, with a margin. A week is the practical figure.

5. Revoke the old selector by publishing an empty `p=` value at it, then bump the SOA serial and deploy the zone as in step 2.

		<oldselector>._domainkey	IN	TXT	"v=DKIM1; k=rsa; p="

   RFC 6376 section 3.6.1 says an empty `p=` means the key is revoked, and section 6.1.2 tells a verifier to treat a signature under it as a failed check and return `PERMFAIL (key revoked)`. The same standard records that there is no defined difference between a revoked key and a removed record, so leaving the record in place with an empty `p=` is the form that says the key is known and retired. The change takes effect when resolvers stop serving the old record, so it is bounded by the TTL and by any cache in the path, which is why step 4 waits before this one.

The `t=s` flag that the proposal names as the published revocation path is a flag on the same key record. RFC 6376 section 3.6.1 defines it: a signature whose `i=` domain does not match its `d=` domain exactly, with no subdomain, fails. The same section says to use the flag unless subdomain signing is needed, and this platform signs one domain.

The record published today carries no `t=` flag, so adding `t=s` is part of the next edit to that record rather than something the revocation depends on.

`scripts/deploy-mail.sh` compares the on-box public key with the published record on every run and prints the correct record when the two disagree, which is the check to run after either step.

## Keep the base system and the packages current

The base system and the packages move on different clocks. `syspatch` carries base system security fixes, `sysupgrade` moves between releases, and `pkg_add -u` updates the packages, which follow their own upstream releases. Track the two separately, and record the date of each, because a snapshot freezes both at once.

1. Read what is outstanding.

		doas syspatch -c
		doas pkg_add -u -n
		doas sysupgrade -n

   `syspatch -c` lists the patches that are missing and `syspatch -l` lists the ones installed. `pkg_add -u -n` prints what it would change. `sysupgrade -n` fetches and verifies the sets, writes `/bsd.upgrade`, and does not reboot; it downloads into `/home/_sysupgrade`, so check free space first.

2. Apply the base patches, then the packages.

		doas syspatch
		doas pkg_add -u

3. Reboot if the base patches or the upgrade require it, then check that every service came back.

		doas rcctl check smtpd dovecot kyriakon_encrypt spamd spamlogd httpd gmid inetd nsd

4. Re-snapshot after a patch cycle, because a stale provisioning image reintroduces what the patch removed. Do not snapshot the live mail box for this: its root disk holds member mail and the DKIM key, and a `kind=gold` image is the source of every future box. Build the new gold image on a throwaway box instead. The image carries its own root `authorized_keys`, so reach the new box with the key it holds.

		. /root/.kyriakon-env
		image_id=$(hcloud image list -t snapshot -l kind=gold -o noheader -o columns=id | tail -1)
		hcloud server create --name kyriakon-gold --type "${RESTORE_TEST_SERVER_TYPE:-cx23}" \
			--image "$image_id" --location "${RESTORE_TEST_LOCATION:-fsn1}" -o json | jq -r '.server.id'

   Match the type and the location to the live box in `terraform/terraform.tfvars` so the image is built on the same footing the box runs on.

   On that box, apply the patches and shut it down, because a snapshot of a running filesystem can capture a write in progress.

		doas syspatch && doas pkg_add -u && doas shutdown -h now

   Then snapshot it and delete it.

		hcloud server create-image --type snapshot --label kind=gold --description "kyriakon-openbsd-<rev>" <gold-server-id>
		hcloud server delete <gold-server-id>

   `terraform/variables.tf` fixes the label convention: provisioning images carry `kind=gold` and point-in-time copies of the live box carry `kind=dr`, so a copy of the live box can never be picked up for provisioning. The terraform data source reads the newest image matching `kind=gold` (`terraform/main.tf`), and the weekly restore test reads the snapshot labelled `kind=restore`. Each label must name exactly one snapshot, and the standup refuses to run when two snapshots carry its label, because which one boots the test would otherwise be decided by the order of an API reply. Remove or relabel the snapshot that a newer one replaces.

5. Audit the snapshot's age against both clocks.

		hcloud image list -t snapshot -o columns=id,description,created,labels
		doas syspatch -l
		uname -a

   Compare the `created` value of the newest `kind=gold` image with the date of the last `syspatch` and `pkg_add -u` run on the box. A snapshot older than the last patch run reprovisions a box without that patch, which is the failure the re-snapshot in step 4 prevents.

## Operator actions before the first payment

These are operator actions, not code. They are tracked as a checklist in #175, and the dates and the rotation records belong in the private half rather than here.

1. Register with the ICO and pay the tier 1 fee as a data controller. The duty comes from the Data Protection (Charges and Information) Regulations 2018, and the fee is £52 a year, or £47 by direct debit, at tier 1. Decided in #152, and the privacy policy names the registration.

2. Rotate the repository publish token and the Stripe signing secret yearly, and on any change of operator. The publish token is fine-grained and scoped to `kyriakon-infra` alone (#155), never organisation-wide. Stripe rotates an endpoint signing secret with an overlap of up to 24 hours, during which it signs with both, so rotate the secret on the box inside that window. Record both dates off the repository.

3. Put the second root credential in the second operator's hands at release, under the admin model already decided: root over SSH disabled, the second operator's own key as an unprivileged user, and escalation through `doas`. `openbsd/etc/sshd_config` already carries `PermitRootLogin no` and `PasswordAuthentication no`, and the file is applied by hand because it is a propose-only change. Decided in #157.

4. Create the Stripe objects and set the dashboard items listed in `docs/planning/research/stripe-rail-set.md`, section 6, and confirm the account verification before signup opens. The load-bearing ones are the live Product and yearly Price, the webhook endpoint with the named event list and its signing secret on the box, the restricted API key, the Payment Link, automatic receipts, the revenue recovery emails and the retry policy. The note records fifteen items and which of them are optional until a VAT registration exists.

5. Confirm the payment state store is inside the backup set and that the restore test's canary comes back. `scripts/backup.sh` copies `/home`, `/etc/mail` and the capsule certificate pair today, and the store's path is fixed by the build in #156, so this item is checked again once the service lands. The canary is `/home/.kyriakon-backup-canary`, and the weekly test asserts it returns byte-identical.

## Run the quarterly indirect-tax check

A worldwide release has to notice when a country's registration begins to bind. Eight jurisdictions outside the UK and the Union were examined, and each either sets a figure to watch or, like India, charges from the first sale. The figures are monitored numbers rather than things looked up once a member count starts to look large (decided in #249, from the research in #248). The card rail supplies the country evidence: Stripe reports a billing country for every card sale, so a member is attributed to the country they were billed in. The prepaid rail carries no country at all, so a prepaid sale cannot be attributed to any jurisdiction below and a prepaid member counts toward no country's figure. It still counts toward the two worldwide figures, because those are read on the whole business. That is a stated limit, left as it stands by the EU consumer decision in #163.

| jurisdiction | threshold | roughly | source |
| --- | --- | --- | --- |
| Norway | NOK 50,000 over twelve months | about 190 members | Norwegian VAT Act, section 2-1 (#248) |
| Canada | CAD 30,000 over twelve months | about 800 members | Excise Tax Act, section 211.12 (#248) |
| New Zealand | NZD 60,000 over twelve months | about 1,350 members | Inland Revenue, supplying remote services (#248) |
| Australia | AUD 75,000 of Australian-connected turnover | about 1,900 members | ATO, how Australian GST works (#248) |
| Japan | JPY 10,000,000 in the base period | about 2,600 members | National Tax Agency, cross-border supplies of services (#248) |
| Switzerland | CHF 100,000 | about 4,600, and measured against worldwide turnover rather than Swiss members | Swiss VAT Act, Article 10(2) (#248) |
| Singapore | SGD 1,000,000 global turnover and SGD 100,000 of Singapore sales | no member count in #249, and both limbs have to be exceeded | IRAS, overseas businesses (#248) |

The member counts are the rough distance at £20 a member, rounded. They count members in the country concerned except Switzerland, which counts the business and not the country, and Singapore, whose global-turnover limb also moves with the whole business. Japan counts business-to-consumer sales only, Australia leaves out sales to GST-registered businesses, and Canada counts only Canadian-facing supplies.

The check runs quarterly.

1. Read the card rail's billing countries over the last twelve months and count the members in each jurisdiction in the table, on the evidence the section opens with.

2. Read the whole business's turnover over the last twelve months for the two worldwide figures, Switzerland's CHF 100,000 and Singapore's SGD 1,000,000. Both limbs include prepaid sales and sales outside those countries, so neither is a count of members.

3. Compare each count, and each worldwide figure, against its threshold. Crossing one is a decision rather than an accident, and registration in that jurisdiction happens on crossing and not before. Norway adds filings only, because section 2-1(6) disapplies its representative duty for a business resident in the United Kingdom.

4. Look for a billing country outside the UK and the Union. India is the trigger line, because it sets no threshold: a single Indian card sale starts the registration. Rule 10(2) of the CGST Rules allows the application in FORM GST REG-10 within thirty days of the date online services begin in India, and backdates the registration to that date when the application reference number issues inside the window, so registering after the first Indian sale is on time and no pre-registration is needed. The registration is taken from the Indian portal, not by the operator, and the filings are done by an accountant or a compliance agent. Returns are monthly in FORM GSTR-5A by the 20th of the following month, and rule 64 states no nil exemption, so a month with no Indian sales still files. A supplier PAN is optional; an Indian authorised signatory holding a valid PAN is not. The registration is decided in #249 and the steps are researched in #264.

The list is a floor and not a ceiling. Only the eight jurisdictions named were examined, so a country outside them may charge from the first sale without appearing here at all, and absence from the table is not a statement that a country charges nothing. A billing country outside the UK, the Union and the table is unexamined, and nothing is claimed about it. The prepaid rail widens that gap, for the reason given above.

## Answer a data-protection breach

One sentence is the rule: notify the ICO and every authority whose country had affected members. The ICO comes first, on the 72-hour clock that Articles 33 and 34 of the UK GDPR set and the notice already states; then every authority below whose country had a member affected by the same breach. The operator sends each one, by hand.

The country evidence is the card rail's billing country, the same evidence the tax check reads, because the account holds no country. A member with no card sale cannot be placed in a country, so the rule reaches the members it can place and the notice's own breach paragraph covers the rest.

| authority | trigger | where it goes | who sends it | status |
| --- | --- | --- | --- | --- |
| Information Commissioner's Office | a breach of security that risks the rights of a member, within 72 hours of becoming aware, from Articles 33 and 34 of the UK GDPR | https://ico.org.uk/for-organisations/data-protection-fee/ | the operator sends it | settled |
| Office of the Privacy Commissioner of Canada | a breach of security safeguards that creates a real risk of significant harm, from section 10.1 of PIPEDA | not settled | the operator sends it | to verify |
| Swiss Federal Data Protection and Information Commissioner | the FADP breach duty, which has the shape of the UK GDPR duty; the research settled neither its article nor its risk test | not settled | the operator sends it | to verify |
| Brazil's Autoridade Nacional de Proteção de Dados | the LGPD breach duty, which the research did not settle | not settled | the operator sends it | to verify |
| Japan's Personal Information Protection Commission | a leak affecting more than 1,000 data subjects, which this release does not approach | www.ppc.go.jp/personalinfo/legal/leakAction/ | the operator sends it | settled |
| India's Data Protection Board | the DPDP breach duty, from commencement on 13 May 2027, which the research did not settle | not settled | the operator sends it | to verify |

A row marked to verify has no trigger or no address that the research settled, so confirm both with the authority before relying on the row. Until then the one-sentence rule above is what to act on. The research is in #248 and the decision is in #250.

## Revisit the notice on 13 May 2027

The DPDP's section 3 commences on or about 13 May 2027, under the commencement notification cited in #248, and it is the provision that reaches a UK business offering services to people in India. What is revisited then is the notice's consent and notice wording. The notice stays in English, which section 5(3) permits, with a support line offering help in another language on request. Decided in #250.

## What the data-protection review checked

The regimes below were read on 5 October 2026 and found not to reach this release, and each stays here with its reason so that a later reader meets the decision rather than repeating the reading (#248, decided in #250).

- The Swiss representative duty in FADP Article 14 fails, because it applies only where processing is on a large scale and tens of members fails that limb.
- The LGPD's small-agent relief is keyed to Brazilian legal forms, microempresas, empresas de pequeno porte and startups registered in Brazil, so a UK sole trader cannot use it and it relieves nothing here.
- The CCPA's three limbs are all out of reach, at USD 26,625,000 of revenue, 100,000 consumers or households, or 50 percent of revenue from selling or sharing, and the platform sells no personal information.
- The Australian section 6D exemption applies, because annual turnover is far below AUD 3,000,000 and none of the section 6D(4) carve-outs is known to apply. The section 6D(4)(c) question, whether routine disclosure to a processor counts as disclosing personal information "for a benefit, service or advantage", is flagged as a lawyer's read: if it does, the exemption falls away and the Australian Privacy Principles bind.
- The APPI's report above 1,000 data subjects is out of reach at this size.

## Sources

Read on 2026-10-01, unless the entry says otherwise.

- RFC 6376, DomainKeys Identified Mail (DKIM) Signatures, sections 3.6.1, 6.1.2 and 8.7. https://www.rfc-editor.org/rfc/rfc6376. The `p=` revocation rule, the `t=s` flag, and the limit on revoking a key that signs many addresses.
- Let's Encrypt, Rate Limits, last updated 5 August 2026. https://letsencrypt.org/docs/rate-limits/. The 50 certificates per registered domain per 7 days with a refill of one every 202 minutes, the 5 per exact set of identifiers with a refill of one every 34 hours, the 5 authorization failures per identifier per hour, and the 1,152 consecutive failures that pause an identifier.
- ICO, Data protection fee, https://ico.org.uk/for-organisations/data-protection-fee/. The duty under the Data Protection (Charges and Information) Regulations 2018. The tier 1 amount of £52, or £47 by direct debit, is quoted in `docs/planning/research/sole-trader-obligations.md` from the Regulations, Schedule, regulation 3(1).
- `docs/planning/research/worldwide-obligations.md`, the regimes that reach a worldwide seller, read 5 October 2026. Every threshold in the tax table, every breach trigger outside the UK and the Union, the 13 May 2027 commencement date and the checked list come from it, and each figure there cites the statute or the regulator's page it was read from. The note does not restate the UK and EU positions, so the ICO row's trigger is from Articles 33 and 34 of the UK GDPR instead.
- The Indian OIDAR registration steps: the CGST Rules, rules 10, 14 and 64, and the GST portal's OIDAR manual and FAQ, read on 7 October 2026. Recorded in #264, with the decision to register on the first Indian sale in #249.
- The box's own manual pages, read over ssh on 2026-10-01: `acme-client(1)` for the `http-01` challenge and the `-r` revocation flag, `syspatch(8)` for `-c` and `-l`, `sysupgrade(8)` for `-n`, and the `hcloud` command help for `server create-image` and `image list`.
- Repository documents that carry the decisions these procedures follow: `docs/planning/specs/phase-1-foundations.md`, `docs/planning/research/encrypted-backup-restore.md`, `docs/planning/research/per-account-enforcement.md`, `docs/planning/research/cert-issuance-ceiling.md`, `docs/planning/research/stripe-rail-set.md`, `docs/planning/research/sole-trader-obligations.md`, `docs/aup.md`, and `docs/refusals.md`.
- GitHub issues #148, #153, #154, #155, #156, #157, #158, #163, #166, #168, #171, #173, #175, #248, #249, #250 and #264 in this repository.
