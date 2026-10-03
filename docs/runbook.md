# Runbook

This is the public half of the operational runbook for kyriakon.net. Each section below is a procedure for something that happens on this platform, written in the order the steps run. The procedures live here, beside the configuration they describe, so a reader can check them against it.

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
- The per-member hosting configuration is merged into the repository and not applied: the chroot under `/home/www`, the generated vhost indexes, the port split that separates git from the chrooted sftp server, and the quota on `/home`. Applying it is a sequence of propose-only steps rather than a script, so it is done once, by hand, and the order is in the pull request that added it (#160).
- The quota itself is scripted: `scripts/quota-apply.sh --enable` turns quotas on and `--all` applies the 5 GB allowance to the accounts that already exist. `scripts/add-user.sh` sets it at creation.

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

The state is flat files, one directory per account. `account.json` holds the state, the contact and recovery addresses, the key fingerprints, the rail and token reference, the paid-until date and the approval decision. `notices.jsonl` appends each notice with its timestamp. `application.json` holds the application answers and the purge deletes it. A top level `intents/` directory holds pending work, one file per item, and `journal.jsonl` records transitions. The drain appends the journal entry before it carries the transition out, so a crash leaves a record it can rerun. The build fixes the store's path, and the drain adds that path to the payload of `scripts/backup.sh`, which today copies `/home` and `/etc/mail`.

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

`scripts/backup.sh` writes an encrypted restic snapshot of `/home` and `/etc/mail` to the storage box every night, with retention of 30 daily, 8 weekly and 6 monthly snapshots. `scripts/cron-apply.sh` installs its cron line.

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

Mail keeps arriving for an account whose password is locked, because delivery resolves the recipient from the user database and never from the password, and no account carries a quota today. That combination fills `/home` after a suspension, and the storage design in #154 is what puts a soft 5 GB and a hard 5.5 GB limit on it. The monitor's quota signal has never run for the same reason, and it starts running when that quota lands (#173).

On the root filesystem the likely places are the log directory, which `openbsd/etc/newsyslog.conf` bounds at seven days, the mail queue, and the restic cache. The root filesystem alert is one of the signals in #173 and does not exist yet.

Check what is queued before removing anything from the queue.

	doas smtpctl show queue
	doas smtpctl show stats

Do not delete files under `/home` to free space. The account lifecycle is the path that removes member data, and a hand deletion leaves the account, the keyring entry and the vhosts behind. Do not remove the DKIM key at `/etc/mail/dkim/private.rsa.key`, the queue key at `/etc/mail/queue.key`, or anything under the restic repository. The first two exist nowhere else, and the third is the backup.

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

5. Confirm the payment state store is inside the backup set and that the restore test's canary comes back. `scripts/backup.sh` copies `/home` and `/etc/mail` today, and the store's path is fixed by the build in #156, so this item is checked again once the service lands. The canary is `/home/.kyriakon-backup-canary`, and the weekly test asserts it returns byte-identical.

## Sources

Read on 2026-10-01, unless the entry says otherwise.

- RFC 6376, DomainKeys Identified Mail (DKIM) Signatures, sections 3.6.1, 6.1.2 and 8.7. https://www.rfc-editor.org/rfc/rfc6376. The `p=` revocation rule, the `t=s` flag, and the limit on revoking a key that signs many addresses.
- Let's Encrypt, Rate Limits, last updated 5 August 2026. https://letsencrypt.org/docs/rate-limits/. The 50 certificates per registered domain per 7 days with a refill of one every 202 minutes, the 5 per exact set of identifiers with a refill of one every 34 hours, the 5 authorization failures per identifier per hour, and the 1,152 consecutive failures that pause an identifier.
- ICO, Data protection fee, https://ico.org.uk/for-organisations/data-protection-fee/. The duty under the Data Protection (Charges and Information) Regulations 2018. The tier 1 amount of £52, or £47 by direct debit, is quoted in `docs/planning/research/sole-trader-obligations.md` from the Regulations, Schedule, regulation 3(1).
- The box's own manual pages, read over ssh on 2026-10-01: `acme-client(1)` for the `http-01` challenge and the `-r` revocation flag, `syspatch(8)` for `-c` and `-l`, `sysupgrade(8)` for `-n`, and the `hcloud` command help for `server create-image` and `image list`.
- Repository documents that carry the decisions these procedures follow: `docs/planning/specs/phase-1-foundations.md`, `docs/planning/research/encrypted-backup-restore.md`, `docs/planning/research/per-account-enforcement.md`, `docs/planning/research/cert-issuance-ceiling.md`, `docs/planning/research/stripe-rail-set.md`, `docs/planning/research/sole-trader-obligations.md`, `docs/aup.md`, and `docs/refusals.md`.
- GitHub issues #148, #153, #154, #155, #156, #157, #158, #166, #168, #171, #173 and #175 in this repository.
