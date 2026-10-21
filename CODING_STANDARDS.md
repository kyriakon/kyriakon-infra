# Coding standards

What a review enforces beyond what the tooling can. Mechanical rules live in `.githooks/` and the CI workflow: the commit shape, `shellcheck`, `ksh -n`, `cargo fmt --check`, `clippy -D warnings`, the crate tests and the terraform checks. This file is the judgement calls, and the review agent reads it, not the implementation agent.

## Tests

An assertion tests a behaviour or a value. Never the text of the code. A `grep` of a script for a phrase it used to contain passes for the wrong reason and then breaks on a comment that kept the word. The same holds for a count of lines, a file's length, or a string that only appears in a source file.

A new branch, a parser, money, a security decision or a bug fix carries a test that fails when it breaks. One is enough, and it should fail on the plausible mistake rather than restate the implementation.

A check that cannot see what it is checking is a finding, not a pass. A health check that reads a missing file, a mail that was not sent, a stale table: each must say so rather than exit 0.

## The drain's transitions

Every transition that settles an intent removes its own file and journals its outcome. A pass that fails leaves the intent in place for the backoff, and a failure journal line is the reason to retry, never a settlement.

A file under the store that the drain writes is handed back to the directory's owner. The handler renders pages from those files and runs unprivileged, so a root-owned record reads as missing to it.

The handler holds no key. Anything it cannot prove is proved by the drain: a link's signature travels through the form, and the drain is the half that verifies it.

## Shell scripts

A failure that matters prints the message it exists to print. A `die` whose function is not defined exits 127 and says nothing, so a new failure path is checked against the script's own error idiom, not copied from another script's.

A candidate file is staged in its destination's directory and renamed, never redirected over the installed file. A partial config is a service that will not start.

## When the tooling and this file disagree

The tooling wins. If a rule here can be checked mechanically, move it into `.githooks/` or the CI workflow and delete it from this file.
