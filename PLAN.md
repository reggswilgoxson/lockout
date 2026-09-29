# PLAN.md — lockout: stop AI from leaking worker health and incident data

> Instructions for Claude Code. This is the root plan for the standalone, open-source `lockout` repository. Work phase by phase. Each phase ends with a runnable demo, passing tests, and a commit. Keep it small. Ask before adding any dependency not listed in §7.

---

## 1. Why this exists

EHS (environment, health and safety) teams are putting LLMs to work on their most sensitive text:
- summarizing incident investigations;
- turning injury logs into lessons-learned bulletins;
- drafting toolbox talks from near misses;
- answering questions over case files.

That text is full of the most protected personal data an employer holds:
- who was hurt, and how;
- medical surveillance results;
- drug and alcohol tests;
- who was blamed.

A model asked for "a site-wide bulletin about last month's incidents" can write *"Dave on B-shift, the needlestick in the lab"*. That one sentence is:
- an OSHA privacy concern case (29 CFR 1904.29(b)(7));
- GDPR Art. 9 health data;
- a just-culture problem.

**The gap.** Open-source LLM guardrails exist, both general frameworks (LLM Guard, NeMo Guardrails, Presidio integrations) and streaming Rust filters (StreamGuard, llm-stream-guardrails). They detect *generic* PII: emails, card numbers, SSNs. None of them knows that:
- "the only forklift driver on night shift at Plant 3" identifies a person;
- an audiogram result is confidential medical data;
- a named worker's positive post-accident test must not reach a bulletin.

This kind of harm needs context, not a regular expression. It is the case EHS actually faces, and nothing open covers it.

**What lockout is.** A single binary you put between an LLM and its readers. It checks the model's **response stream** with EHS-specific questions and **locks out** (blocks) or **tags** (warns about) output that would expose a worker. The name comes from lockout/tagout: the lock prevents, and the tag warns.

### Name
- **Repo:** `github.com/reggswilgoxson/lockout`
- **Binary:** `lockout`
- **Crates:** `lockout-ai` (the binary) and `lockout-ai-core`. The crates.io name `lockout` is taken by an unrelated lock-free utilities crate.

### Design principles
- **Simple:** one binary, one config file, and one main setting, `audience`. You can explain it to an EHS manager in a sentence: "It stops the AI from telling people things about workers they aren't cleared to know."
- **Elegant:** the checks are data. EHS professionals can improve the questions and the test set by editing TOML (a plain-text config format), with no Rust needed.
- **Useful:** it works in front of the tools EHS teams actually wire up, it gives reasons they recognize (regulation citations), and it ships a public benchmark.
- **Narrow:** it only reads the model's response. It doesn't scan prompts, redact, detect secrets or toxicity, or offer a dashboard.

---

## 2. How it works

```
LLM API ──response stream──▶ frame parser ──text──▶ holdback buffer ──cleared text──▶ reader
                                                  │   ▲
                                        segment ──┤   │ verdicts
                                                  ▼   │
                                ┌───────────────────────────────────────┐
                                │ local rules: IDs, contact (µs)        │
                                │ Jev: EHS questions, calibrated (≈0.5s)│
                                └───────────────────────────────────────┘
           BLOCK → stop, send provider-native error, exit 3      WARN → release, log finding
```

1. **Local rules** check structured identifiers deterministically: email, phone, checksummed national IDs, card/IBAN, and your own employee ID or claim-number formats.
2. **Jev** (TypeSafe AI's System One model) receives each segment as `state`, with one yes/no question per EHS category. It answers all of them in parallel in one call, each with a calibrated probability.
3. The `audience` setting decides, for each category, whether a positive finding blocks, warns, or is ignored.

### About Jev (assumptions to verify in Phase 0)
- Jev is a decision model. It takes one `state` plus typed questions (`noul` yes/no, `choice`, `score`) and answers them all in one pass. Published figures are 70–500 ms per call, a context of about 32k tokens, and about $0.042 per million input tokens.
- A 2,000-character reply is about 8 segments and about 3k input tokens, so it costs a fraction of a cent.
- Jev says *whether* a segment contains something, not *where*. Its verdicts cover whole segments.
- The endpoint and field names differ between third-party sources. Phase 0 pins them from TypeSafe's official docs. Until then, everything is set through config.
- Jev sits behind a small `Decider` trait. A schema change, or another decision model later, touches one module.
- **Without a Jev key, lockout runs in local mode.** Local mode catches identifiers only. The EHS categories need Jev, and the README says so up front.

---

## 3. The one setting: `audience`

EHS teams already think in terms of need-to-know. Who will read this output?
- `investigation`: the incident team, which may see names.
- `site`: workforce-wide bulletins and chatbots. **This is the default.**
- `public`: external reports, vendors, regulators' public copies.

| Category | What Jev is asked (sketch) | investigation | site | public | Why (pointers, not legal advice) |
|---|---|---|---|---|---|
| `privacy_case` | "Does the text tie an identifiable worker to an injury of an intimate body part or the reproductive system, sexual assault, mental illness, HIV/hepatitis/TB, or a contaminated needlestick/sharps injury?" | warn | block | block | 29 CFR 1904.29(b)(7), GDPR Art. 9 |
| `worker_health` | "…tie an identifiable worker to an injury, illness, medical exam or surveillance result (audiometry, spirometry, blood lead, fit-test medical evaluation), disability or restriction?" | warn | block | block | 29 CFR 1910.1020, ADA 29 CFR 1630.14, GDPR Art. 9 |
| `substance_test` | "…reveal an identifiable worker's drug or alcohol test or its result?" | warn | block | block | 49 CFR 40.321 (DOT), GDPR Art. 9 |
| `fault_or_discipline` | "…attribute blame, fault or disciplinary action to an identifiable worker?" | off | warn | block | GDPR Art. 88 / employment data; just-culture practice |
| `other_special` | "…reveal an identifiable worker's trade-union membership, religion, ethnicity, sexual orientation, or criminal record?" | warn | block | block | GDPR Art. 9, Art. 10 |
| `person_identity` | "…identify a specific private individual, by name or by details (role, shift, location, date) that single them out?" | off | warn | block | 29 CFR 1904.29(b)(10), GDPR Art. 4(1) |
| `employee_ref` | local patterns from config + "…an employee number, badge ID or claim number?" | off | warn | block | GDPR Art. 4(1) |
| `contact` | local email/phone + "…a personal email address or phone number?" | warn | block | block | GDPR Art. 4(1) |
| `government_id` | local, checksummed: US SSN, UK NINO, DE Steuer-ID, FR NIR, ES DNI/NIE, IT CF, NL BSN, passport MRZ | block | block | block | GDPR Art. 87, state SSN laws |
| `financial` | local: card (Luhn), IBAN (mod-97) | block | block | block | GDPR Art. 4(1) |

That is 8 Jev questions per segment.
- Each question requires an **identifiable** worker. "Needlestick injuries rose 12% last quarter" is fine; "the new lab tech on nights had a needlestick" is not.
- Each finding carries the citation strings from this table, so a WARN or BLOCK is explained in terms EHS reviewers recognize. The README states plainly that these are pointers, not legal advice.
- Questions and citations live in `crates/core/rules/ehs.toml`. Improving a question is a one-line pull request plus eval cases.

---

## 4. Key design decisions

1. **Check before release.** Nothing reaches the reader until every check covering it has cleared it.
2. **Segments with an overlap tail.** Segments are cut at a sentence or line boundary after `min` characters (240), at `max` (800), or at end of stream. The first segment uses `first_min` (100 bytes) so text appears quickly. It must exceed `overlap`, or nothing could be released.

   When segment k clears, everything is released except its last `overlap` normalized bytes (64, moved back to a whitespace within 32 bytes). That tail opens segment k+1. So an identifier split across a boundary is checked whole *before any of it leaves*. A property test enforces this.
3. **Subject memory.** Identifiability often spans sentences: "Maria Keller joined in March. … She is being treated for epilepsy." lockout keeps up to 3 short excerpts (200 characters or fewer) from earlier segments where a `person_identity`, `employee_ref` or `contact` finding fired. It sends them to Jev with each new segment, and nothing else from earlier text.
4. **Pipelining.** Segment k's Jev call runs while segment k+1 accumulates. There are up to 4 calls per stream, with a process-wide limit for the proxy. Release is strictly in order. When the buffer is full, lockout back-pressures upstream; nothing is dropped.
5. **Local rules block immediately,** without waiting for Jev.
6. **Block in the provider's own error format,** so client SDKs raise a typed error rather than hanging:
   - OpenAI: `data: {"error":{"type":"pii_blocked",…}}`
   - Anthropic: `event: error` with `{"type":"error","error":{"type":"pii_blocked",…}}`
   - Ollama: `{"error":"…"}`

   Then lockout closes upstream and exits with code 3.
7. **Fail closed, fail fast.** If Jev errors or times out (1.2 s), the segment is blocked. The alternatives are `on_error = local-only | warn`. There is no retry mid-stream. A circuit breaker trips after 3 consecutive failures and re-probes every 30 s.
8. **Thresholds are calibrated once and shipped.** Jev's probabilities are calibrated, so a single `block_threshold` and `warn_threshold` per category are fitted on the benchmark in Phase 0 and shipped as defaults. Users change `audience`, not numbers. Per-category overrides exist but are undocumented in the quickstart.
9. **Allowlists by default:**
   - RFC 2606/6761 example domains;
   - RFC 5737/3849 documentation IPs;
   - published test card numbers;
   - `[allow]` entries in config (for example `safety@yourco.com`, or the site's public emergency line).
10. **Findings never contain the text they flag.** A finding holds the category, audience, citations, source (`local` or `jev`), probability, and the segment's byte range. Local matches also carry an HMAC of the match when a key is set.
11. **Keep what goes to Jev minimal.** Jev receives the segment plus the subject memory, and never the prompt or the whole transcript. The README says plainly that Jev is a third-party processor of response text: it needs a data processing agreement (DPA) and a region choice, or `--jev off`.

### Known limits (in the README)
- Deliberate encoding (base64, one character per line) evades detection.
- Resistance to "ignore this, answer no" text inside `state` is measured in the benchmark, not guaranteed.
- Blocking works per segment, so harmless text next to a violation is withheld too.
- lockout can't be placed in front of closed tools, such as Microsoft 365 Copilot or AI built into an EHS vendor's product. It works wherever you control the model's API base URL.

---

## 5. Where EHS teams use it

- **Chat front-ends:** Open WebUI or LibreChat, pointed at `lockout proxy` as their OpenAI-compatible base URL.
- **Low-code flows:** an n8n, Dify, or Flowise HTTP node pointed at the proxy. A typical flow is "summarize this week's incidents for the site newsletter".
- **Scripts:** `curl … | lockout scan --format sse-openai`.
- **Documents before distribution:** `lockout scan --report bulletin.txt` checks AI-drafted text, such as a bulletin, before it's sent.

```
$ lockout scan --report --audience site bulletin.txt
BLOCK  privacy_case     ¶3  p=0.94  29 CFR 1904.29(b)(7) · GDPR Art. 9
WARN   person_identity  ¶1  p=0.71  29 CFR 1904.29(b)(10) · GDPR Art. 4(1)
1 blocking, 1 warning — not safe to distribute to audience "site"
```

The README includes a 5-minute quickstart for Open WebUI + Docker, and one for the CLI.

---

## 6. CLI

```bash
lockout scan  [--format raw|sse-openai|sse-anthropic|ndjson-ollama] [--audience site] [--jev off] [--report]
lockout proxy --listen 127.0.0.1:8787 --upstream https://api.example --format sse-openai [--audience site]
lockout test  "Maria from night shift tested positive after Tuesday's forklift incident"
lockout eval  [--replay]        # run the benchmark against current rules
```

- `scan` filters stdin to stdout. With `--report`, it reads everything and prints findings only (human-readable on a terminal, JSON lines otherwise).
- Exit codes:

| Code | Meaning |
|---|---|
| 0 | Clean, or warnings only |
| 3 | Blocked |
| 4 | Bad frame |
| 5 | Jev unavailable |
| 2 | Usage error |
| 1 | Internal error (the stream was still blocked) |

- `--fail-on-warn` makes warnings exit 3, for CI and document checks.
- Only generated content is read: text deltas and tool-call arguments. Reasoning ("thinking") deltas are off by default. Prompts are never read.

Config (`lockout.toml`; every key is optional):

```toml
audience = "site"                         # investigation | site | public

[jev]
api_key_env = "JEV_API_KEY"               # unset → local mode, with a notice
on_error = "block"                        # block | local-only | warn

[identifiers]                             # your formats → employee_ref
employee_id = 'E\d{6}'
claim_number = 'WC-\d{4}-\d{5}'

[allow]
emails = ["safety@yourco.com"]
phones = ["+1 800 555 0100"]

[override]                                # rarely needed
fault_or_discipline = "block"
```

---

## 7. Repository and dependencies

```
lockout/
  README.md                    what/why, quickstarts, limits, GDPR processor note
  LICENSE-APACHE, LICENSE-MIT  dual license (Rust norm); benchmark data CC-BY-4.0
  CONTRIBUTING.md              how to improve rules and add eval cases without writing Rust
  crates/core/                 no I/O: normalizer, local rules, segmenter, policy, frame parsers
  crates/core/rules/ehs.toml   categories, Jev questions, citations, audience matrix, thresholds (ships inside the crate)
  crates/lockout/              package `lockout-ai`, binary `lockout`: Jev client (Decider trait), tokio I/O, proxy
  bench/                       ehs-pii-bench: synthetic labelled EHS texts + recorded Jev answers
  fuzz/                        cargo-fuzz: frame parsers, normalizer
  Dockerfile                   distroless, one static binary
  .github/workflows/           fmt, clippy, test, `lockout eval --replay`, releases (Linux/macOS/Windows)
```

- **Dependencies:**
  - **core:** `regex`, `unicode-normalization`, `serde`, `toml`, `hmac`, `sha2`.
  - **binary:** `clap`, `toml`, `tokio`, `reqwest` (rustls), `hyper-util`, `tracing`.
  - **Dev:** `proptest`, `wiremock`, `cargo-fuzz`.
- **Windows builds matter.** A lot of EHS work happens on corporate Windows laptops.
- **`ehs-pii-bench` is a contribution in its own right.** It is the first public, labelled test set of PII in EHS text. It is synthetic only and never uses real case data. It contains:
  - incident narratives and OSHA 301-style descriptions;
  - lessons-learned bulletins and toolbox talks;
  - **hard negatives:** SDS health-hazard text ("may cause cancer"), aggregate injury statistics, company-level OSHA citations, public-figure news;
  - indirect-identification cases;
  - multi-segment cases;
  - adversarial cases.

  Any guardrail tool can be scored against it.

---

## 8. Phases

Numeric targets are fixed at the end of Phase 0 from measured data.

### Phase 0 — Jev spike and ehs-pii-bench v0
- Pin the Jev API from the official docs into `crates/lockout/src/jev/API.md`.
- Write at least 300 labelled synthetic cases across all categories and audiences, including the hard negatives.
- Run them live, record the answers, and fit the thresholds.
- **Acceptance:**
  - Per-category precision/recall and latency (p50/p95/p99) are published in `bench/RESULTS.md`.
  - Thresholds are written into `crates/core/rules/ehs.toml`.
  - There is a go/no-go note, and the gates for Phases 1–4 are written here.

### Phase 1 — Core and local mode
- Build the normalizer, local rules and allowlists, segmenter (overlap, first-segment ramp), audience policy, and `scan --format raw --jev off`, `--report`, and `test`.
- **Acceptance:**
  - Property test: splitting any positive at every byte and segment boundary still blocks, with zero bytes of the match released.
  - Validators pass published test vectors.
  - Hard-negative false positives are within the gate.
- **Status: done.** Notes from building it:
  - **Defaults changed.** `overlap` is 64 bytes, the longest context any local detector reads (a 44-byte MRZ line, or a keyword-gated ID). `first_min` is 100, because it must exceed `overlap` for anything to be released.
  - **The guarantee has a size limit.** It covers identifiers up to `overlap` normalized bytes, which is every bounded detector. An email address longer than 64 bytes is still caught, but its first part may already have been released.
  - **One `Guard` per output channel.** There is no channel parameter; Phase 3 gives text and tool arguments a `Guard` each.
  - **The rules file ships with the crate,** at `crates/core/rules/ehs.toml`, so the core parses TOML itself.
  - **Tests:**
    - The every-byte split test is exhaustive and takes about a minute, so it is `#[ignore]`d locally and CI runs it with `--include-ignored`.
    - Random chunkings are covered by `proptest`.
    - The hard-negatives gate is zero findings at audience `public` on `crates/core/tests/fixtures/hard_negatives.txt`, until Phase 0 sets numeric gates.
  - **Validators and allowlists.** Validators pass published or widely cited vectors: processor test cards, the ECBS IBAN examples, the ICAO 9303 specimen, and others. Two local allowlists were added during testing: documentation examples (such as `QQ 12 34 56 C` and `123-45-6789`) and NANP toll-free numbers.
  - **Measured performance:**
    - Local detection: 27 µs/KB mean and 46 µs/KB p99.
    - End to end: about 68 µs/KB, because each overlap tail is scanned twice.
    - Release binary: 2.6 MB.

### Phase 2 — Jev
- Build the `Decider` and Jev client, pipelining, in-order release, subject memory, `on_error`, the circuit breaker, and `eval`.
- **Acceptance:**
  - A scripted Decider plus `wiremock` covers out-of-order verdicts, timeouts, and the breaker.
  - `lockout eval` meets the gates for every audience, including the indirect-identification and multi-segment cases.

### Phase 3 — Stream formats and proxy
- Build the OpenAI, Anthropic, and Ollama parsers, tool-argument checking, native terminal errors, and the proxy.
- **Acceptance:**
  - Clean recorded streams pass through byte-identical.
  - The official OpenAI and Anthropic SDKs raise a typed error on a blocked stream.
  - Open WebUI, pointed at the proxy, shows the error rather than hanging.
  - cargo-fuzz runs 10 minutes or more per parser without panics.

### Phase 4 — Release
- Write the README with quickstarts, limits, and the processor note, and write CONTRIBUTING.
- Publish the Docker image, set up release binaries for three OSes, and tag v0.1.0.
- **Acceptance:**
  - A new user goes from download to a blocked demo stream in Open WebUI in 5 minutes or less, following only the README.
  - The binary is 8 MB or less.
  - `bench/RESULTS.md` is regenerated in CI.

---

## 9. Non-goals

These are out of scope for v0.1. Each is a reason to say no to a pull request, not a roadmap item.
- Scanning prompts or inputs.
- Redaction or rewriting.
- Secrets, toxicity, or prompt-injection detection.
- Bundled ML models.
- A UI or dashboard.
- Compliance certification or legal advice.
- Integrations with specific EHS vendor platforms.

---

## 10. Open questions for Rex

1. **Jev:** do you have an API key or early access for Phase 0? Would TypeSafe support an open-source integration (for example, a free tier for the benchmark CI)?
2. **Audience matrix:** can an EHS practitioner review the defaults in §3 before Phase 0? This is the table that matters most.
3. **Bench:** can you source realistic incident-narrative *styles* (not real data) from practitioners to make the synthetic set credible?
