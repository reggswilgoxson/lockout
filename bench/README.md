# ehs-pii-bench (seed, v0)

Labelled synthetic EHS text for scoring guardrails, starting with lockout:

```bash
lockout eval --cases bench/cases.jsonl                           # live (needs JEV_API_KEY and JEV_URL)
lockout eval --cases bench/cases.jsonl --record bench/recordings.jsonl   # live, saving Jev's answers
lockout eval --cases bench/cases.jsonl --replay bench/recordings.jsonl   # offline, from saved answers
```

**Status:** a seed of 30 cases. Phase 0 grows it to 300 or more. The labels have **not yet been reviewed by an EHS practitioner**; please do that before treating the numbers as meaningful.

## Format

One JSON object per line:

```json
{"id": "pos-health-audiogram", "text": "...", "labels": ["worker_health", "person_identity"]}
```

- **`labels`** lists every category a careful reviewer would flag at audience `public`, where no category is off. The category names are the ones in `audience.toml`. An empty list is a hard negative: text that looks sensitive but identifies no one, such as statistics, SDS hazard text, programme descriptions or company-level citations.
- **`id` prefixes:**
  - `pos-`: a positive case;
  - `neg-`: a hard negative;
  - `adv-`: an evasion attempt. These are expected to show limits; the spelled-out SSN is one that local rules cannot catch.

## Rules for contributions

- **Synthetic only.** Never real case data, real names from your records, or real phone numbers. Use the reserved ranges: `@example.com`, UK drama numbers `07700 900xxx`, US `555-01xx`.
- Add one case per idea, with a descriptive `id`.
- When you change a question in `crates/core/rules/ehs.toml`, add the cases that motivated the change.

Data in this directory is licensed CC-BY-4.0.
