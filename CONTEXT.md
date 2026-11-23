# kyriakon-infra

Repo-local vocabulary for `kyriakon-infra` only. **Read `../kyriakon/docs/CONTEXT.md`
first** — that's the shared glossary across all `kyriakon-*` repos (shell-less user,
pricing tiers, dogfooding, audit us). This file adds only the terms specific to
infra work that don't mean anything outside this repo.

## Language

**Propose-only change**:
Any change touching `pf.conf`, `sshd_config`, or that would run `terraform
apply`/`terraform destroy` against the live box. Drafted as a PR diff only; the actual
live-affecting command is a documented manual step, run by a human, never by an agent.
_Avoid_: direct change, auto-apply

**Snapshot approach**:
The recommended OpenBSD install-automation path: install and configure the box
manually once, snapshot it via the Hetzner API, then use that snapshot as the
Terraform image source for all future provisioning. Contrasted with the
autoinstall-response-file approach, which is unproven against Hetzner's rescue
environment.
_Avoid_: golden image (implies a broader image-management practice than exists here)

**Log minimization**:
The posture that bounds, rather than eliminates, user-identifiable logs: a 7-day
`newsyslog.conf` retention window on `maillog`/`authlog`/`nsd.log`, with abuse
monitoring running on aggregate counts only. Raw IPs are discarded at rotation, and
hashing them for longer retention was rejected — a retained hash is a pseudonymous
identifier, not data minimization. See `docs/threat-model.md` "Log minimization".
_Avoid_: no logs (unachievable — correspondence metadata is a routing necessity).

**Capsule certificate**:
The long-lived self-signed TLS pair a capsule presents, distinct from the site
certificate the same hostname's HTTPS side serves, never CA-issued and never renewed
because a gemini client pins what it first saw. One pair covers `kyriakon.net` and
`*.kyriakon.net` for every capsule the platform runs and every member's capsule
hostname, generated once with a ten-year life; an own-domain capsule gets its own. The
key is held in the backup set because nothing reissues a self-signed pair.
_Avoid_: gemini certificate, TOFU certificate

**Atomic write**:
A file change that creates a sibling candidate under `umask 077`, checks it
(an optional daemon parse, and a `cmp` against the installed file), sets its
mode and owner, then renames it into place. A reader sees the old file or the
whole new one, never a truncated file. `scripts/lib/atomic-fs.sh` holds the one
`write_atomic`; a symlinked or hard-linked destination is refused.
_Avoid_: staged write (the helper's old name), temp-file copy

**Lock directory**:
The shell-side exclusion on this box: `mkdir` a directory, write the owner's pid
inside, and remove it when done. OpenBSD has no `flock(1)` or `lockf(1)`, so
`scripts/lib/atomic-fs.sh`'s `lock_dir` is the one scheme. A stale lock is
reaped by renaming it to a unique sibling and comparing the pid it held, so two
reapers cannot delete each other's fresh lock.
_Avoid_: file lock, flock

**Member account**:
An OS account that passes `require_member`: uid above 0, a Maildir in its home,
`accounts/<user>/account.json` under the store, and a `$home/.ssh` that is not a
symlink. The localpart charset is checked first, but it cannot tell a member
from root or the operator's account, so a destructive lane reads the full
predicate.
_Avoid_: valid user, localpart (the name shape alone)

**The control plane**:
The subsystem under `control/`: the handler that serves the web form and the capsule,
the member content responder both front-ends hand a member's site to, the ssh portal,
the root drain that settles intents, and the operator console, built as five programs
and installed in `/usr/local/sbin`. It is the layer between a public front-end and a
privileged change on the box: a front-end files one intent and the drain carries it
out. The name says what the layer does, because only one of its five programs is
onboarding; the applicant journey keeps that word.
_Avoid_: onboarding service (names the signup form and misdescribes the drain and the console)

**The console**:
The operator's CLI, `/usr/local/sbin/kyriakon-admin`, built from
`control/crates/admin/`. It reviews an application, records money, refunds, exports and
data-subject requests, and suspends or deletes an account. It is the smallest possible
writer: a change that belongs to a transition is filed as an intent and applied by the
drain on its next pass, so a console command and a click on a signed link cannot take
different paths.
_Avoid_: onboardctl (the name the console had before the control-plane rename, #633)

**The portal**:
The onboarding session over ssh: the second sshd instance, the login class naming
`/usr/local/sbin/kyriakon-control-tui` as its shell, and the Rust program that path
holds, built from `control/crates/tui/src/lib.rs`. It is the third front-end beside the web
form and the capsule, and it reads the same catalogue and asks the same questions
from the same files. It chooses between its two modes, the drawing and the plain
one, from the session's own terminal rather than from a flag, so a session with no
terminal and a screen reader both get the plain one.
_Avoid_: terminal wizard (the ksh program it replaced, gone from the repository in #373)

**Line-ending rule**:
The rule the shared message parsers use: a line ends at LF, CRLF, or a bare CR.
A bare CR is a real line end, so the header split, the header spans, and the
multipart walk cannot disagree about where the body starts. It lives in
`mailparse/`, and the encryptor reads every message through it.
_Avoid_: LF-only split, normalise then parse

## Conventions that have already bitten

**The shell is pdksh.** Every script here runs under the box's `/bin/ksh`, which is
pdksh-derived: no arrays, no `+=`, no `[[ ]]` pattern matching, no `<<<` here-strings,
no process substitution. A script written against ksh93 passes its self-test on a
developer's machine and fails on the box at the first `typeset -a`, which is what
happened to the onboarding TUI: the session died on `typeset: -a: unknown option`
before it drew anything. The other scripts in `scripts/` are the idiom reference, and
a self-test only counts if it has been run under the box's own ksh.
_Avoid_: ksh93, bash.

**A scheduled script prints nothing when it has nothing to do.** cron mails a job's
output, so a line on a quiet run is a line in the operator's inbox every time it runs,
which is how the certificate queue mailed every fifteen minutes. What the operator
must see is a health signal or a `--status` reading, not a running commentary.
_Avoid_: verbose cron jobs, "just one line".
