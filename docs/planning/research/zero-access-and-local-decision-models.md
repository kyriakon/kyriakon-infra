# Triage model on the operator host (Phase 1, §5.9/§6.11)

**Question:** a local model that reads message content would remove most of the manual triage
in account applications and in the operator's mail. Where may such a model run, what may it
read, and what is the smallest build that is actually safe?

**Answer, in three parts.**

*Where:* on the **operator host**, an always-on machine of Oliver's own (a Mac mini is one
candidate), holding **his own key**,
reading **Oliver's own mailbox**. Never on the mail box, and the platform never holds a mail
private key for it. That is not a preference about hardware. Zero-access is a promise about
*the platform*, and the platform is the mail box and everything it controls. Oliver reading
his own mail is not the platform reading it, which is the same trust position as his
Thunderbird profile today, just always on. The moment the triage model serves a second user's
mail, it has become the platform and the promise is false again.

*What is allowed:* nothing on this path may be sent to a third-party inference service, ever,
and the model must be open-weight. Both are recorded as cross-cutting decisions (ADR 0003 and
ADR 0004 in `../kyriakon/docs/decisions/`).

*How much to trust it:* less than it appears. The safety mechanism one reaches for first,
routing low-confidence decisions to a human, **does not work on this model family and fails
silently for exactly the languages this community writes in**. See §4, which is the part of
this document that changes the build. The rest is the boundary and the component.

---

## 1. What zero-access actually constrains

Four documents carry the promise, and all four bind the *server*:

| Source | Claim |
|---|---|
| `docs/threat-model.md` | "The server holds only public keys … it never holds a private key or anything that can derive one." |
| `docs/threat-model.md` | Protected scope is `content — subject, body, headers`; unprotected is `ciphertext; envelope metadata (who/when/size)`. |
| `docs/aup.md` | "the platform cannot read it. Mail content is therefore not and cannot be policed." |
| `CONTEXT.md` (zero-access mail) | "it holds only the user's public key and encrypts on ingress, so a disclosure order yields ciphertext and no key." |
| `CONTEXT.md` (recovery phrase) | The key backup is "Never held by the platform". |

The threat model has already traced this to its conclusions: "abuse monitoring runs on
metadata only; spam classification still runs at the relay", and "No server-side body/header
search or threading … they are client-side". A triage model reading content on the mail box would
falsify every claim above, and would convert the documented *honest ceiling* ("does not stop a
compelled admin from modifying the delivery pipeline to capture mail in plaintext") into the
guaranteed steady state. Locality does not rescue that: a locally-run model on the mail box
fixes *disclosure to a third party* but not *zero-access* (the platform still
reads every message, and now holds the key as well). Those are two different properties and
only one of them is a published promise.

## 2. What the operator-host position restores

Running on the operator host is not a compromise, it is the better engineering position for anything
content-dependent. Two mechanisms compose, and today's `admin@` change is already half of it:

| Layer | Runs on | Reads | Cost | Covers |
|---|---|---|---|---|
| Alias and plus-addressing | mail box | envelope only (recipient address) | free, deterministic | routing by *address*, on every device |
| Triage model | operator host | content, locally, with Oliver's key | free per call, private | routing by *content*, on every device |

The operator host is also the only place server-side body search and threading can exist at all
(`THREAD=REFERENCES` and full-text search are impossible over ciphertext). Moving intelligence
to where the key already is gives back everything zero-access had to give up, with no sentence
in the AUP changing.

## 3. Model, runtime and hardware choice

`convaiinnovations/laya` is the open-weight typed-decision family: `choice`/`score`/`noul`,
one bidirectional forward pass, Apache-2.0 weights, with published papers and open training
data behind it (author-cited: arXiv:2503.23303, March 2025; arXiv:2510.01237, late 2025). It
is the same class of model as Jev and predates it, which matters here for a reason beyond
timing: an auditable project can depend on a model whose weights and benchmark harnesses are
inspectable, and cannot depend on a closed endpoint for a decision it will act on.

| Checkpoint | Encoder | Params | Context | Primary strength (vendor) |
|---|---|---:|---:|---|
| `convaiinnovations/laya` | ModernBERT-large | 421M | 512 | English classification, guardrails, email triage |
| `convaiinnovations/laya-multilingual` | mmBERT-base, 256k vocab | 322M | 1024 (up to 8k) | 100+ languages, cross-lingual NLI |
| `convaiinnovations/laya-typed-decisions` | ModernBERT-large | 421M | 1024 | agent observability, customer service, security alerts |

The main repository bundles all three and the SDK downloads one subfolder at a time.

Two runtimes are viable, and which one applies depends on the box. The official `pip install laya` is torch-based. The
independent MLX port `mizorewww/laya-mlx` is native Apple Silicon and is the one whose numbers
are measured below, on an M3 Max, FP16, model load excluded, covering prompt preparation,
tokenization, inference, calibration and formatting:

| | Laya 421M | Multilingual 322M |
|---|---:|---:|
| One short question, P50 | 13.42 ms | 7.39 ms |
| One short question, P95 | 13.92 ms | 7.79 ms |
| 50 questions, throughput | 146.8 q/s | 395.0 q/s |
| Peak MLX allocation, one short question | 943.6 MiB | 687.6 MiB |

Note the port is independent, not an official release, and retains upstream weights, question
formatting, calibration and output schema.

One architecture property is easy to get wrong: **questions do not share a single pass over
the state.** Each question row is encoded against the state, so `n` questions cost roughly `n`
encoder passes batched together. Jev's "ingest the state once, evaluate every question in
parallel" does not hold here. Compute is local and free, so this is a latency note, but a
40-question fan-out over a long state is 40 encoder passes, not one.

### What this actually requires of the machine

Worth stating plainly, because the answer is that the hardware decision is not driven by this
design:

| Requirement | What the triage design needs |
|---|---|
| Memory | 687 MiB for the 322M multilingual checkpoint at FP16, 944 MiB for the 421M English one, less again at INT8. Both resident only if routing is used. |
| Latency | Nothing tight. Mail is asynchronous and applications are not interactive, so 200 ms and two seconds are equally acceptable. The 13 ms figure is an M3 Max GPU result, not a requirement. |
| Throughput | A handful of decisions per day at dogfooding volume, with the application form the only unbounded surface. |
| Accelerator | None. Encoders of this size are CPU-viable, and a third-party INT8 ONNX export reports 15.6 ms per question on a four-core CPU. |

So a low-power always-on device is sufficient for everything in this document. The one
portability constraint is that MLX is Apple Silicon only, so a non-Apple box uses the official
torch package or an INT8 ONNX export, and gives up the measured 13 ms figure without giving up
the design.

### The simplification worth taking on a small machine

Section 4's failure mode exists only because two checkpoints are deployed and one of them
cannot read non-Latin scripts. Deploying the multilingual checkpoint alone removes the failure
mode by construction, and it is cheaper on every axis that matters to a small box: 322M rather
than 421M, 687 MiB rather than 944 MiB, 1024 context rather than 512, and 2.2x faster on the
authors' own measurement. The cost is whatever accuracy the specialised English checkpoint adds
on English text, which the authors do not publish separately. On a low-power device, one
checkpoint and no router is both the simpler and the safer configuration.

### Where a 27B-class model changes the answer

Reply drafting and thread summarisation are a different requirement, and that is the one that
drives hardware. A 27B model at four-bit precision is on the order of 15 to 17 GB of weights,
so realistically a 32 GB machine, while a low-power device instead caps out around a 3B to 8B
model with a corresponding drop in drafting quality. Generation is not latency-critical, since
drafts are read later, so the binding constraint is memory rather than speed.

The consequence for the purchase decision is one line. The triage model described here does
not justify a Mac mini, because it runs on almost anything. A Mac mini bought for other work
justifies it, and it rides along as one more process at no extra cost. Buying the box for the
triage model would be buying it for the cheaper half of the job.

### The model is a placeholder, not the decision

The model named above is a current candidate, not the choice. This class is moving quickly and
its quality will improve well before the hardware exists, so pinning a specific model in a
decision record would be wrong twice over: ignored later, or treated as binding by someone who
read the name rather than the property.

What is durable is the list any replacement has to satisfy:

- typed `choice`/`score`/`noul` output with calibrated probabilities, not free text to parse;
- runs on the operator host, with no network inference (ADR 0003);
- open weights, so the claim is checkable (ADR 0004);
- handles non-Latin scripts, or refuses to send them to a checkpoint that cannot read them;
- encoder-scale rather than frontier-scale, so it fits a small always-on box;
- no third-party dependency for serving or calibration.

The fitting requirement in §6 and the measured ceilings in §4 and §5 are the evaluation criteria
for whatever replaces it.

## 4. Routing must happen before the forward pass, not after it

This is the finding that decides the build, and it comes from the model authors' own
limitations section rather than from a competitor.

The English checkpoint's tokenizer has a 50k English BPE vocabulary, which fragments non-Latin
scripts. From a 51-language sweep on MASSIVE (20 options, random baseline 0.050), with the
reported mean confidence beside each score:

| Language | Accuracy | Mean confidence |
|---|---:|---:|
| Khmer | 0.000 | 0.952 |
| Armenian | 0.050 | 0.885 |
| Hebrew | 0.060 | 0.964 |
| Bengali | 0.080 | 0.945 |
| Hindi | 0.100 | 0.941 |

Their conclusion, and it is correct: "the model's own confidence gives no warning when it
cannot read the input script … confidence gating cannot protect you."

This lands directly on this platform. An Orthodox community writes in Greek and Cyrillic, and
the application form and `hello@` will receive both. The design that says "act when confidence
is high, escalate when it is not" would therefore act confidently and wrongly on exactly the
applicants it is least acceptable to mishandle, and it would *file them away silently*, which
is worse than doing nothing.

The mitigation is upstream and mandatory, not an optimisation: use the `Router`, which
inspects Unicode scripts across 22 alphabets and Latin stopword distributions and selects the
checkpoint before inference. Detection overhead is 0.09 ms for English, 0.54 ms for Indic, and
0.73 ms for large nested JSON, against a 33 ms forward pass. `Router(preload=True)` keeps the
needed checkpoints resident and avoids a 7 to 10 second cold swap when input alternates
between languages, which on a single small box is the difference between usable and not.

Where a triage model is genuinely safe, the routing step is not the only guard.
Anything acting on a non-Latin input must also be validated against the multilingual
checkpoint specifically, because the English checkpoint's numbers for those languages are not
merely weak but anti-correlated with its own confidence.

The cheaper alternative is to skip routing entirely and deploy only the multilingual
checkpoint, which makes this failure mode unreachable rather than mitigated. Section 3 covers
when that trade is the right one.

## 5. Expect the base model to be weak on a custom taxonomy

The second finding that changes the build, again from the authors: "Out-of-the-box base models
score ~0.35 on the typed-decisions benchmark (near random). The 0.766 score is achieved by
fine-tuning on the benchmark's train split. Treat Laya as a fast foundation model to
specialize, not as an omniscient zero-shot oracle."

The measured per-workflow numbers say the same thing in more useful detail:

| Workflow (vendor-measured) | Accuracy |
|---|---:|
| Email spam filtering (Enron) | 0.993 |
| Phishing detection | 0.980 |
| LLM guardrails / jailbreak, held-out ToxicChat | 0.755 – 0.762 (0.931 at 50% selective coverage) |
| RAG passage relevance | 0.657 |
| Support ticket queue routing, 10-way | 0.522 |

Read against the two jobs here: the *built-in* workhorse categories (spam, phishing, and
binary safety questions) are near-solved out of the box, which is exactly what the "is this
noise or a genuine application" question needs. Arbitrary custom taxonomies are not. A 6-way
category set with 0.522-class accuracy is wrong about half the time, which is fine as a
*suggestion* attached to a message and unacceptable as an *action*.

So the build splits:

- **Ship as actions, zero-shot:** binary and near-binary questions the base model is measured
  good at. `is_application`, `abuse_signals`, `needs_reply`, and spam/phishing style
  questions.
- **Ship as suggestions only, until fine-tuned:** the multi-way `category` taxonomies. Fine
  tuning is a real option and not a research project, the upstream repository ships a Kaggle
  notebook that trains a custom model in roughly four hours on free 2xT4 GPUs.

Two further constraints on question design, both from the authors' ceilings section. Choice
questions degrade past about 20 options, because the option block shares a 192 to 256 token
budget, so 77 options leaves three tokens each and scores 0.425 against Jev's 0.870. Keep
criteria under 20, keep each option description short, and prefer two coarse-to-fine steps
over one wide choice.

## 6. Calibration has to be fitted, not assumed

Fitted confidence is the entire reason to use this family over a general model, and the raw
state is not usable: "Base weights ship with raw temperature logits. Fitting a single scalar
temperature per question type on your domain distribution cuts expected calibration error from
0.466 to 0.081."

An ECE of 0.466 means the numbers are not merely uncalibrated but actively misleading at the
shipped state, and the independent MLX port surfaces the same defect from the other direction,
warning at load that upstream's `choice:11+` bucket is 0.1006 and would sharpen logits about
10x, reporting a coin flip as near-certainty. It clamps that bucket to 0.5. The question sets
here use four to six options, so they do not exercise the `11+` bucket, but the general point
does not depend on the bucket: no threshold in §7 means anything until a temperature is fitted
per question type on real inputs and the resulting buckets are checked against outcomes.

## 7. The two jobs

Both are the same shape: a text state, a handful of frozen labels, an action that must be
cheap to reverse.

**Account applications** (`kyriakon-onboard`, §5.9.1) are the stronger of the two. They are
structured data submitted to the platform deliberately, so no zero-access question arises at
all. The form is internet-facing before any vet, so it is the unbounded-volume surface, and
the proposal already notes a floodable application form is a DoS on Oliver. It also already
collects the free text that makes classification worth doing: "how did you find us / what do
you plan to do".

```python
questions = {
    "is_application": {"type": "noul", "instructions":
        "Is this a genuine request for a kyriakon.net account, rather than spam, "
        "an unrelated sales pitch, or automated output?"},
    "abuse_signals": {"type": "noul", "instructions":
        "Does the text contain credential harvesting, bulk-mail intent, or other "
        "signals of intended platform abuse?"},
    "category": {"type": "choice", "instructions": "What kind of submission is this?",
        "criteria": {
            "individual": "a person asking for their own mailbox",
            "parish": "a parish or organisation asking for an account or domain",
            "abuse": "a complaint about mail or content from this platform",
            "noise": "spam, marketing, or automated submission",
        }},
}
```

**The operator's mail** is the weaker job and should be scoped as such. Volume is one mailbox,
so the value is prioritisation, not throughput. This is the mail alias routing has already
filed into `.Admin` by envelope, and content decides only *within* the folder. Note that mail
has one advantage over the application form: the spam and phishing questions, where the base
model is at 0.98 to 0.99, are the ones that matter most here.

```python
questions = {
    "needs_reply": {"type": "noul", "instructions":
        "Does this message expect a reply from the operator?"},
    "is_noise": {"type": "noul", "instructions":
        "Is this machine output, a bounce, or a report that needs no action?"},
    "category": {"type": "choice", "instructions": "What is this message about?",
        "criteria": {
            "account": "account creation, credentials, password reset",
            "abuse": "spam, phishing, or complaint about mail from this platform",
            "deliverability": "mail delivery, DNS, DKIM/SPF/DMARC, blocklists",
            "hosting": "static site, Gemini capsule, git repository",
            "billing": "payment or the annual fee",
            "noise": "machine output, bounces, reports needing no action",
        }},
}
```

A general local model server remains the right tool for the *generation* side: drafting
replies, summarising a thread. The triage model handles frozen-label triage. Two roles on one
box, not two implementations of one role. Asking a triage model to write prose is a category
error, it cannot, by construction.

## 8. Pre-processing is mandatory

512 tokens on the English checkpoint is consumed almost entirely by quoted history in a real
reply. Classifying a full message classifies the *quoted* conversation rather than the new
text, confidently and wrongly.

Strip, in order: quoted lines, signature blocks, a leading `Re:` chain. Truncate the remainder
to fit the question set. Anything unparsed falls back to a bounded window rather than failing,
and the log records that it did.

## 9. Action policy

Thresholds are per-action, sized by what a mistake costs, and each is set only after the
calibration in §6 has been fitted and the bucket it lives in has been checked against real
outcomes.

| Confidence | Action |
|---|---|
| high | act: move to the folder, set the keyword |
| medium | leave in place, mark for review |
| low | do nothing; the message stays in the INBOX |

Low confidence routes to the human for free, so Oliver becomes the fallback rather than the
filter. That is the whole workload reduction, and §4 is the reason it cannot be the only
defence: confidence is informative on Latin-script English after temperature fitting, and
uninformative on anything the routed checkpoint was not chosen for.

Three hard rules, load-bearing rather than stylistic:

1. **Never send, never delete.** Move, flag, keyword, and draft only. A mis-filed message is a
   nuisance; an outgoing mail is not retractable.
2. **Never act on a second user's mailbox.** This is the boundary from §1. Anything serving
   another user belongs on the mail box and breaks the promise.
3. **Idempotent on message id.** A restart must not re-file or double-act. Message id, chosen
   folder, action taken and deciding scores are appended to a log, which is both the audit
   trail and the input to §10.

Account creation stays manual and this design deliberately does not touch it. The proposal
keeps approval as Oliver's call ("fast-tracks approval but is not required"), and `add-user.sh`
plus credential issuance are outward-facing and irreversible. Classify into a queue; never
approve from a triage model.

## 10. Rollout: shadow mode first

Given §5 and §6, shadow mode is not caution, it is the only way to get the artefacts the
design depends on. Run the model, log everything, act on nothing. That produces:

- the labelled examples to fit a temperature per question type (§6);
- per-class accuracy against a real taxonomy rather than a vendor benchmark (§5), which is
  the evidence for deciding whether a category set ships as an action or stays a suggestion;
- per-language coverage, to confirm the `Router` is actually catching the Greek and Cyrillic
  inputs rather than quietly handing them to the English checkpoint (§4).

Then enable one action at a time, starting with the highest-confidence noise filing, once its
bucket is measured. Compilation and prefix-cache options (`compile`, `pad_to_multiple`,
`cache_prompts`) default to disabled and nothing here is latency-critical, so they can stay
off.

One sequencing note: shadow mode is also how the hardware question gets answered, so do not buy
a machine in order to find out. Its input is one mailbox and a handful of applications, which
any available box can process, and its output is the evidence that decides whether a 322M
encoder is sufficient, whether the multilingual checkpoint is enough on its own, and whether a
27B model is needed at all. Measuring first is cheaper than guessing in either direction.

## 11. Key, machine and data hygiene

The operator host holds the key to Oliver's mail, in addition to whatever model server it runs.

- Full-disk encryption, treating it as a machine holding mail private keys, because it is.
- The decrypting path is a local IPC endpoint, not a TCP port. If the model server is exposed
  for other uses, it must not be able to reach the key or the mailbox.
- The key lives in an encrypted local store, not a config file, not an environment variable,
  and not this repository.

### What is retained

Only decisions, scores and outcome labels are kept (ADR 0005). Message and application text is
purged on the 90-day window that proposal §5.9.1 already applies to applications, and that window
also governs anything resting on the triage model or its runtime here.

This costs something real. Calibration has to be fitted inside the window, and purged text cannot
be refitted against, so a change to a question set cannot be validated against older mail. What
persists is the fitted temperature and the measured accuracy, both scalars: enough for the
thresholds in §9, and not enough to reconstruct anyone's mail.

## 12. Status, and what this does not do

Tracked as `kyriakon` issue #5, and not buildable yet. `kyriakon-onboard` is fast-follow per the
proposal and MVP is dogfooding with one mailbox, so there is no application volume to triage and
no support queue to drain. This document fixes the boundary and records the model's measured
ceilings before anything is built against either, in the same spirit as the ingress docs: the
decision to keep this off the mail box is the durable part, and the component is small enough to
write when the service it reads from exists.

The decisions this note argues for are recorded as ADRs 0002 to 0005 in
`../kyriakon/docs/decisions/`, which is what a reader should treat as settled. This note is
working material, and can be pruned.

It also does not cover spam on the mail box. Spam classification stays at the relay, on the
envelope, where the platform already put it. Deliberate, deterministic and auditable beats
probabilistic there, and the `nospamd` table derived from senders' own SPF records is the
existing example of that choice.

Open questions:

- Whether the mail job earns its place at all, or prioritisation by content is better done by
  a general local model over the already-filed `.Admin` folder.
- Whether fine-tuning for the custom taxonomies is worth four hours of free GPU time, or the
  category questions stay suggestions indefinitely.
- Whether generation is in scope, which is what decides between a low-power always-on device
  and a 32 GB machine. The triage model does not decide it: everything in this document runs on
  a small box. That answer also settles the runtime, since MLX needs Apple Silicon and anything
  else falls back to the official torch path or an INT8 ONNX export.

## 13. Primary sources

- Laya research writeup (author-published, and the source of every Laya number and ceiling
  quoted above, including the language sweep, the workflow table, the zero-shot and
  fine-tuning caveat, and the temperature-fitting result).
  https://laya.convaiinnovations.com/
- Official package and router: `pip install laya`, `github.com/NandhaKishorM/laya` (code,
  router, reproducible benchmark harnesses on the `research` branch), weights at
  `convaiinnovations/laya` (bundles all three checkpoints, Apache-2.0), plus a Kaggle 2xT4
  fine-tuning notebook. https://pypi.org/project/laya/
- Independent MLX port with measured Apple Silicon latency, memory and numerical parity, the
  supported checkpoints and context limits, and the calibration-clamping warning.
  https://github.com/mizorewww/laya-mlx
- TypeSafe AI, "Models" and "Confidence" — the framing being reproduced, and the origin of the
  confidence-threshold-by-consequence pattern.
  https://docs.typesafe.ai/models , https://docs.typesafe.ai/confidence
- `docs/threat-model.md` (Zero-access mail, Consequences, Honest ceiling) and `docs/aup.md`
  (Zero-access boundary) in this repo — the promises §1 must not falsify.
- `../kyriakon/docs/CONTEXT.md` — the zero-access mail and recovery phrase definitions.
- Project proposal §5.1 (ingress encryption), §5.9.1 (account applications, approval not
  automatic), §6.11 (monitoring), §6.14 (password reset paths).
- ADRs 0002 to 0005 in `../kyriakon/docs/decisions/`, and `kyriakon` issue #5 — the decisions
  this note argues for, and the deferred build.
- `docs/planning/research/zero-access-mail-smtp-ingress.md` — sibling decision; establishes
  that plus-addressing is already part of the ingress design and that the envelope is outside
  the protected set.

Benchmark provenance: the head-to-head comparisons against Jev are published by Laya's
authors. The Jev figures are theirs as cited from third-party studies, and the Laya figures
are self-measured. The ceilings in §4 and §5 are the more useful evidence precisely because
they are the authors' own admissions, and they are the parts of this document most likely to
have been omitted from a vendor summary.
