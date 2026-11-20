# Coding standards

What a review enforces beyond what the tooling can. Mechanical rules live in `.githooks/` and the CI workflow: the commit shape, `shellcheck`, `ksh -n`, `cargo fmt --check`, `clippy -D warnings`, the crate tests and the terraform checks. This file is the judgement calls, and the review agent reads it, not the implementation agent.

## Tests

An assertion tests a behaviour or a value. Never the text of the code. A `grep` of a script for a phrase it used to contain passes for the wrong reason and then breaks on a comment that kept the word. The same holds for a count of lines, a file's length, or a string that only appears in a source file.

A new branch, a parser, money, a security decision or a bug fix carries a test that fails when it breaks. One is enough, and it should fail on the plausible mistake rather than restate the implementation.

A test that stubs or hand-builds an identifier takes it from the production path (the approval's output, the filed intent, the store record), never a plausible string typed by the test. A hand-built join proves the test, not the join.

A front-end flow test covers every answer kind in `questions.toml` and at least one branch with more than one generated page, such as a body with two mailboxes.

A check that cannot see what it is checking is a finding, not a pass. A health check that reads a missing file, a mail that was not sent, a stale table: each must say so rather than exit 0.

## The drain's transitions

Every transition that settles an intent removes its own file and journals its outcome. A pass that fails leaves the intent in place for the backoff, and a failure journal line is the reason to retry, never a settlement.

A file under the store that the drain writes is handed back to the directory's owner. The handler renders pages from those files and runs unprivileged, so a root-owned record reads as missing to it.

The handler holds no key. Anything it cannot prove is proved by the drain: a link's signature travels through the form, and the drain is the half that verifies it.

## Records

A store file ending `.jsonl` is a record and stays append-only. It is reached
through `Store::log`, which has no write, and `Store::write_record` refuses the
name. Four writes complete a line that has to be completed later rather than
appended again: a refund's settlement, a held payment's attribution, a
request's close, and a notice's delivery status when a DSN reports a permanent
failure. The notice completion is `mail::bounce`, and it calls
`Store::rewrite_log_mode` rather than `Store::rewrite_log` because
`notices.jsonl` is 0640 for the handler to read and the rewrite must keep that
mode and the accounts directory's group. A retention prune removes whole lines
once their window has run, as `lifecycle::holds_sweep` does for a released
username. Each takes `Store::log(...).lock()` across its read and its write and
calls the one named API, `Store::rewrite_log` or `Store::rewrite_log_mode`.
Appends take the same lock, and the code says why: a rewrite without it can drop
a line another process appended between the read and the rename.

## Errors and outcomes

An outcome a caller branches on is an enum whose variants are the outcomes:
`Settlement`, `Resolution`, `Refusal`, `Reply`. The names are the decision, and a
new outcome adds a variant rather than a fourth `if` on a string.

`Error` is the other case: a failure that ends the request, carried to one place
that decides the answer. It holds a message and its context, not a taxonomy. A
variant earns its place only when some caller acts differently on it: the
handler's `Refused`/`Line` arms are unreachable in production because nothing
constructs them on a served path, and the handler's 12 variants collapse into
one 500/40 mapper for nine of them. Add a variant when the reply, the retry or
the journal line changes; otherwise add the sentence to the message.

A client-visible reply is built from a constant or a value that passed its
validation, never from an internal error's `to_string()`. A `59` that carries
`cannot read the titan request: <os error>` tells a stranger what the socket
did.

Error text that reaches a log goes through `util::clean`, like every other line a
member can influence.

## Docs

Cite the command, path or symbol that makes a claim checkable. A line number is
a timestamp: the next edit above it moves it, and the review cannot tell a stale
one from a correct one.

## Shell scripts

A failure that matters prints the message it exists to print. A `die` whose function is not defined exits 127 and says nothing, so a new failure path is checked against the script's own error idiom, not copied from another script's.

A candidate file is staged in its destination's directory and renamed, never redirected over the installed file. A partial config is a service that will not start.

## Review findings

A finding that changes behaviour lands with its test on the branch that will merge.
A reviewer who says the tooling fails runs it and quotes the exit status: a `shellcheck` or `clippy` finding the repository's own command does not reproduce is a finding about the review, and it costs a round trip with the implementation agent. A
fix moved between branches by checking out whole directories from another branch
carries whatever that branch held: five verified fixes were lost that way, and the
squash merged code that had never been tested.

## When the tooling and this file disagree

The tooling wins. If a rule here can be checked mechanically, move it into `.githooks/` or the CI workflow and delete it from this file.
