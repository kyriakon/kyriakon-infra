# Agent setup guide (omp + skills + extensions)

How to stand up this repo's agentic workflow on a new machine — or onboard a new contributor. Reference setup in use by Oliver; install steps are the contract.

## 1. Install the harness

- [omp](https://github.com/can1357/oh-my-pi) via Homebrew: `brew install omp`
- [Bun](https://bun.sh) — required for extension loading: `curl -fsSL https://bun.sh/install | bash`

## 2. Model configuration

### `~/.omp/agent/models.yml`

```yaml
providers:
  deepseek:
    baseUrl: "https://api.deepseek.com/v1"
    api: "openai-completions"
    models:
      - id: "deepseek-v4-flash"
        name: "DeepSeek v4 Flash"
        reasoningEffort: "auto"
      - id: "deepseek-v4-pro"
        name: "DeepSeek v4 Pro"
        reasoningEffort: "auto"
```

**No `apiKey` line.** omp resolves `DEEPSEEK_API_KEY` from the environment natively — export it in `~/.zshrc` (or `~/.omp/agent/.env`). Never put a key in a config file.

### `~/.omp/agent/config.yml`

```yaml
setupWizard: false

startup:
  setupWizard: false

modelRoles:
  default: "deepseek/deepseek-v4-flash"
  smol: "deepseek/deepseek-v4-flash"
  commit: "deepseek/deepseek-v4-flash"
  slow: "deepseek/deepseek-v4-pro"
  plan: "deepseek/deepseek-v4-pro"
```

- `default` is the everyday model; `smol`/`commit` are the cheap quick jobs; `slow`/`plan` are the deep-reasoning roles (wayfinder grilling, ADR drafting, code review) on the pro tier.
- DeepSeek's supported ids are `deepseek-v4-pro` and `deepseek-v4-flash` — probe with the chat-completions endpoint; `/v1/models` is gated.

## 3. Extensions (marketplace)

Both personal extensions install from the marketplace repo — no manual file placement:

```sh
omp plugin marketplace add oliverbrotchie/omp-extensions
omp plugin install ponytail@omp-extensions caveman@omp-extensions guardrails@omp-extensions
# after upstream/catalog changes:
omp plugin marketplace update omp-extensions
omp plugin upgrade ponytail@omp-extensions caveman@omp-extensions guardrails@omp-extensions
```

- **ponytail** — lazy-senior-dev mode; sourced from upstream [DietrichGebert/ponytail](https://github.com/DietrichGebert/ponytail) (the catalog points at it, nothing vendored).
- **caveman** — terse-prose mode; vendored in the marketplace repo (`plugins/caveman/`).
- **guardrails** — blocks agent edits to `AGENTS.md` (write/edit tools *and* bash write-intents); the file is human-owned, so agents must ask you and you edit it directly.

Marketplace layout: `.omp-plugin/marketplace.json` catalog; a plugin ships `package.json` with `"omp": { "extensions": [...] }` for extension modules, or `skills/` for skills. Extensions are TS/JS loaded with Bun; sources must stay in the marketplace repo, never loose files in `~/.omp/agent/extensions/`.

## 4. Skills

The matt-pocock skill set (ask-matt, wayfinder, grilling, domain-modeling, code-review, …) installs from its marketplace:

```sh
omp plugin marketplace add mattpocock/skills
# install the skills you need; the skill set is listed in ~/.agents/skills/
```

## 5. Repo conventions

Once omp is running in the kleio repo, the workflow is documented in:

- `AGENTS.md` — build/test commands, code style, tickets, git rules
- `docs/agents/issue-tracker.md` — tracker ops incl. the wayfinder close-checklist
- `docs/agents/domain.md` — where vocabulary/ADRs live (`CONTEXT.md`, `docs/decisions/`)
- `docs/decisions/` — ADRs (read before assuming missing context)

The repo's pre-commit hook (betterleaks + cargo check) runs on every commit — no extra agent-side setup needed.
