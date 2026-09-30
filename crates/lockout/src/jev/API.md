# Jev API: what lockout assumes

**Status: unverified.** TypeSafe's official API reference could not be reached while this was written. Third-party write-ups disagree on the endpoint (`/v1/decide` vs `/v1/systemone`). Phase 0 pins this against the official docs and updates this file.

## Why there is no default URL

lockout sends response text to Jev, and that text may contain worker health data. A guessed default endpoint could send that data to the wrong party. So lockout calls Jev only when **both** of these are set:

| Variable | Meaning |
|---|---|
| `JEV_API_KEY` | API key. The name can be changed with `[jev] api_key_env`. |
| `JEV_URL` | Full endpoint URL, e.g. `https://…/v1/decide`. Set it in `[jev] url` or change the variable name with `[jev] url_env`. The URL must be `https` (or localhost, for tests). |

If the key is set but the URL isn't, lockout refuses to start (exit 2) rather than falling back.

## Request

`POST $JEV_URL`, with the header `Authorization: Bearer $JEV_API_KEY`. For a different header, set `[jev] api_key_header`; the key is then sent bare.

```json
{
  "model": "jev",
  "state": "Earlier in this response:\n- …\n\nText:\n<segment>",
  "questions": {
    "privacy_case":  { "type": "noul", "instructions": "Does the text tie an identifiable worker to …?" },
    "worker_health": { "type": "noul", "instructions": "…" }
  }
}
```

- There is one `noul` (yes/no probability) question per category that has a question and isn't `off` for the current audience.
- `state` is the segment. When earlier segments identified someone, it is prefixed with up to three short excerpts (at most 200 bytes each), so Jev can judge whether the person is identifiable.

## Response

The parser accepts any of these shapes, per asked category:

```json
{ "answers": { "privacy_case": 0.93 } }
{ "answers": { "privacy_case": { "probability": 0.93 } } }
{ "privacy_case": { "p": 0.93 } }
```

- A missing answer, a non-numeric value, or a value outside 0–1 is an **error**, never "clean". It is handled by `on_error`.
- A non-2xx status, a timeout (`timeout_ms`, default 1200) or a network error is also an error.

## Error handling

| `[jev] on_error` | Effect |
|---|---|
| `block` (default) | The stream stops, and lockout exits with code 5. |
| `local-only` | The segment is released on the strength of the local rules, and a notice goes to stderr. |

After 3 consecutive failures, the circuit breaker fails calls immediately for 30 s, then lets one call through to probe.
