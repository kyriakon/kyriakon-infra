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

**The portal**:
The onboarding session over ssh: the second sshd instance, the login class naming
`/usr/local/sbin/kyriakon-onboard-tui` as its shell, and the Rust program that path
holds, built from `onboard/src/portal.rs`. It is the third front-end beside the web
form and the capsule, and it reads the same catalogue and asks the same questions
from the same files. It chooses between its two modes, the drawing and the plain
one, from the session's own terminal rather than from a flag, so a session with no
terminal and a screen reader both get the plain one.
_Avoid_: terminal wizard (the ksh program it replaced, gone from the repository in #373)

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
