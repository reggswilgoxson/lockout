# lockout

**Lockout/tagout for AI output.** lockout sits between a large language model and the people reading its output. It stops the model from exposing worker health and incident data: it **blocks** a response that would expose a worker, and **flags** borderline cases.

It is built for EHS (environment, health and safety) teams that use AI on their most sensitive material:
- incident investigations;
- injury logs;
- medical surveillance;
- drug and alcohol testing;
- lessons-learned bulletins.

> **Status: Phase 1 of 4.** The local rules work: identifiers such as emails, phone numbers, card numbers, IBANs, national IDs, passport lines and your own employee-ID formats. They run on plain-text streams. The EHS categories, such as worker health and privacy cases, need Jev and arrive in Phase 2. Provider stream formats and the proxy arrive in Phase 3. See [PLAN.md](PLAN.md).

## Why

General-purpose PII filters catch emails and Social Security numbers. They don't catch *"the new lab tech on nights had a needlestick"*. That sentence is:
- an OSHA privacy concern case;
- GDPR Art. 9 health data;
- a just-culture problem.

Catching it takes context, not a regular expression.

lockout reads the model's response as it streams. It combines two checks:
- fast local rules for identifiers such as emails, phone numbers and ID numbers;
- EHS-specific questions answered by [Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev), a decision model.

Nothing is shown to the reader until it has been checked.

## One setting

`audience` sets who will read the output:
- `investigation`: the incident team.
- `site`: workforce-wide bulletins and chatbots. This is the default.
- `public`: external reports, vendors, public copies.

lockout blocks or flags each category of finding according to that audience. Each finding points to the rule behind it, such as 29 CFR 1904.29(b)(7) or GDPR Art. 9. These are pointers, not legal advice.

## Try it

```bash
cargo install --git https://github.com/reggswilgoxson/lockout lockout-ai

# Check a string
lockout test --jev off "For questions call Dave on +44 20 7946 0958."
# BLOCK  contact          line 1    local:phone            GDPR Art. 4(1)
# 1 blocking finding, 0 warnings — not safe to distribute to audience "site"

# Filter a response as it streams: only checked text reaches stdout
some-llm-cli "summarise this week's incidents" | lockout scan --jev off

# Check an AI-drafted bulletin before sending it (JSON lines when piped)
lockout scan --report --audience site bulletin.txt
```

What the exit code means:

| Code | Meaning |
|---|---|
| 0 | Clean, or warnings only |
| 3 | Blocked (`--fail-on-warn` counts warnings too) |
| 4 | Input is not valid UTF-8 |
| 2 | Usage or config error |
| 1 | Internal error |

Findings go to stderr as JSON lines (in `--report` mode, to stdout). They give the category, the rule behind it and a byte range. They never contain the flagged text.

## Configure

Every key in `lockout.toml` is optional. lockout reads `./lockout.toml`, or the file given with `--config`.

```toml
audience = "site"                         # investigation | site | public

[identifiers]                             # your formats; matches are employee_ref
employee_id = 'E\d{6}'
claim_number = 'WC-\d{4}-\d{5}'

[allow]
emails = ["safety@yourco.com"]
domains = ["yourco-public.com"]
phones = ["+1 800 555 0100"]

[override]                                # rarely needed
fault_or_discipline = "block"
```

Set `LOCKOUT_HMAC_KEY` to add a keyed fingerprint to each local finding. You can then correlate repeat leaks without storing the data.

## How it avoids leaking a partial identifier

lockout holds back a short tail of the stream: the last 64 normalized bytes. A card number split across two chunks is therefore always checked whole before any of it is released. Tests cover every split point around each identifier, at every position relative to a segment boundary. The reasoning is in [`crates/core/src/guard.rs`](crates/core/src/guard.rs).

## Contributing rules

The categories, the questions Jev will be asked, the citations, and the block/warn table for each audience all live in [`crates/core/rules/ehs.toml`](crates/core/rules/ehs.toml). EHS practitioners can improve them without writing Rust.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The benchmark data in `bench/` (once added) is CC-BY-4.0.
