# lockout

**Lockout/tagout for AI output.** lockout sits between a large language model and the people reading its output. It stops the model from exposing worker health and incident data: it **blocks** a response that would expose a worker, and **flags** borderline cases.

It is built for EHS (environment, health and safety) teams that use AI on their most sensitive material:
- incident investigations;
- injury logs;
- medical surveillance;
- drug and alcohol testing;
- lessons-learned bulletins.

> **Status: planning.** Nothing is built yet. See [PLAN.md](PLAN.md) for the design and phases.

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

## Planned usage

```bash
# Put lockout in front of an LLM API that speaks the OpenAI format (Open WebUI, LibreChat, n8n, Dify, …)
lockout proxy --listen 127.0.0.1:8787 --upstream https://api.example --audience site

# Filter a model's response stream in a script
curl -sN … | lockout scan --format sse-openai

# Check an AI-drafted bulletin before sending it
lockout scan --report --audience site bulletin.txt
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option. The benchmark data in `bench/` (once added) is CC-BY-4.0.
