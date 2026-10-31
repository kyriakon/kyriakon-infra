# Issue tracker: GitHub

Issues and specs for this repo live as GitHub issues. Use the `gh` CLI for all operations.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`. Use a heredoc for multi-line bodies.
- **Read an issue**: `gh issue view <number> --json number,title,body,labels,comments --jq '{number, title, body, labels: [.labels[].name], comments: [.comments[].body]}'`. `--comments` and `--json` are mutually exclusive.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with appropriate `--label` and `--state` filters.
- **Comment on an issue**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`

Infer the repo from `git remote -v` — `gh` does this automatically when run inside a clone.

## Gotchas

- `gh pr list --json ... --jq ...` takes jq's *expression* but not its flags: `--arg`
  is rejected with "unknown arguments". Interpolate the value into the expression, and
  check it first when it comes from an event payload.
- A PR or issue body with backticks or `$` in it: write the body to a file and pass
  `--body-file`. An inline heredoc inside a command substitution expands them, which
  is how a PR body has been published as a list of shell errors.

## Parallel ticket work

Several tickets can run at once, one worktree and one subagent each. The rules that
keep the merges from costing more than the parallelism saves:

- `git worktree add /tmp/<ticket> -b feat/<slug> origin/main`; the main checkout stays clean.
- A ticket whose branch needs another ticket's code is **stacked**: branch from the
  parent branch and set the child PR's base to it, not `main`.
- Merge the parent first. Then `git rebase --onto origin/main <old-parent-tip>`,
  force-push the child, and set its PR base to `main` before merging. A squash merge
  rewrites the parent commit, so retargeting alone leaves the child carrying the
  parent's commits.
- `gh pr merge --delete-branch` deletes the base branch, and GitHub **closes** any
  open PR still based on it instead of retargeting it. Keep a base branch until
  every child has been rebased and retargeted.

## Ready queue

When the user asks you to pick the next task, this query returns the unblocked
`ready-for-agent` queue. Without that request, work only on the issue you were
given.

```sh
gh api graphql -f query='
{
  repository(owner: "kyriakon", name: "kyriakon-infra") {
    issues(first: 100, states: OPEN, labels: ["ready-for-agent"]) {
      nodes {
        number
        title
        assignees(first: 1) { nodes { login } }
        issueDependenciesSummary { blockedBy }
        timelineItems(first: 50, itemTypes: [CROSS_REFERENCED_EVENT]) {
          nodes {
            ... on CrossReferencedEvent {
              source { ... on PullRequest { number state merged } }
            }
          }
        }
      }
    }
  }
}' --jq '
  .data.repository.issues.nodes[]
  | select(.issueDependenciesSummary.blockedBy == 0)
  | select((.assignees.nodes | length) == 0)
  | select([.timelineItems.nodes[]?.source? | select(.merged == true)] | length == 0)
  | "\(.number)\t\(.title)"
'
```

`blockedBy` is the GraphQL count of open blockers; `totalBlockedBy` also counts
the closed ones. The Wayfinding section below uses the REST spelling,
`issue_dependencies_summary.blocked_by`. `assignees` is non-empty when the issue
is claimed; `timelineItems` carries the cross-referenced pull requests. The queue
drops claimed issues and issues with a merged pull request: the first is being
worked, and the second is waiting for a deploy, not work. Check that pull
request's deploy step before closing the issue.

The query drops an issue with a merged cross-referenced PR, but a change that
merged without a cross-reference leaves its issue in the queue. Before starting,
check the issue's acceptance criteria against the current tree. If every
criterion is already met, close the issue with the evidence in a comment rather
than reimplementing it.

The queue has no priority order of its own, so read the titles and choose.

## Pull requests as a triage surface

**PRs as a request surface: no.** _(Set to `yes` if this repo treats external PRs as feature requests; `/triage` reads this flag.)_

When set to `yes`, PRs run through the same labels and states as issues, using the `gh pr` equivalents:

- **Read a PR**: `gh pr view <number> --comments` and `gh pr diff <number>` for the diff.
- **List external PRs for triage**: `gh pr list --state open --json number,title,body,labels,author,authorAssociation,comments` then keep only `authorAssociation` of `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR`, or `NONE` (drop `OWNER`/`MEMBER`/`COLLABORATOR`).
- **Comment / label / close**: `gh pr comment`, `gh pr edit --add-label`/`--remove-label`, `gh pr close`.

GitHub shares one number space across issues and PRs, so a bare `#42` may be either — resolve with `gh pr view 42` and fall back to `gh issue view 42`.

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.

A ticket carrying a `Spec:` line reads the spec and `../kyriakon/docs/CONTEXT.md`
before coding. That line is the concrete trigger; without one, `AGENTS.md` leaves
the meta-repo read to judgement.

## Wayfinding operations

Used by `/wayfinder`. The **map** is a single issue with **child** issues as tickets.

- **Map**: a single issue labelled `wayfinder:map`, holding the Notes / Decisions-so-far / Fog body. `gh issue create --label wayfinder:map`.
- **Child ticket**: an issue linked to the map as a GitHub sub-issue (`gh api` on the sub-issues endpoint). Where sub-issues aren't enabled, add the child to a task list in the map body and put `Part of #<map>` at the top of the child body. Labels: `wayfinder:<type>` (`research`/`prototype`/`grilling`/`task`). Once claimed, the ticket is assigned to the driving dev.
- **Blocking**: GitHub's **native issue dependencies** — the canonical, UI-visible representation. Add an edge with `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`, where `<blocker-db-id>` is the blocker's numeric **database id** (`gh api repos/<owner>/<repo>/issues/<n> --jq .id`, _not_ the `#number` or `node_id`). GitHub reports `issue_dependencies_summary.blocked_by` (open blockers only — the live gate). Where dependencies aren't available, fall back to a `Blocked by: #<n>, #<n>` line at the top of the child body. A ticket is unblocked when every blocker is closed.
- **Frontier query**: list the map's open children (`gh issue list --state open`, scoped to the map's sub-issues / task list), drop any with an open blocker (`issue_dependencies_summary.blocked_by > 0`, or an open issue in the `Blocked by` line) or an assignee; first in map order wins.
- **Claim**: `gh issue edit <n> --add-assignee @me` — the session's first write.
- **Resolve** (close-checklist — do all of these before ending the session):
  1. Post the answer as a resolution comment, then close the issue.
  2. Append the one-line gist to the map's Decisions-so-far (gist + link).
  3. Graduate any fog the answer made specifiable; clear it from the map's Not yet specified. Capture any newly-resolved domain terms in `CONTEXT.md`.
  4. Verify placement: a resolved ticket that walked the route belongs in Decisions-so-far, not Out of scope (Out of scope is for scope boundaries, not route steps).
  5. Open a PR for the ticket's asset branch (research findings, spike, ADR) — deliverables must reach `main`, not die on branches.
- **Spike/research branches**: use `git worktree add` so the main checkout stays clean across sessions — no untracked artifacts leaking between branches.
