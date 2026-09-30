//! The decider: who answers the EHS questions about a segment.
//!
//! [`Jev`] calls TypeSafe's Jev over HTTPS. [`Breaker`] wraps any decider so a
//! failing service is not waited on segment after segment. [`Recorder`] and
//! [`Replay`] let `lockout eval` run offline from saved answers. The request
//! and response shapes are unverified; see `API.md` next to this file.

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use lockout_ai_core::Category;
use lockout_ai_core::guard::{DeciderInput, Verdict};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::config::JevSettings;

/// Answers the questions in a [`DeciderInput`].
pub trait Decider: Send + Sync + 'static {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send;
}

impl<D: Decider> Decider for Arc<D> {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send {
        (**self).decide(input)
    }
}

pub struct Jev {
    http: reqwest::Client,
    settings: JevSettings,
}

impl Jev {
    pub fn new(settings: JevSettings) -> Result<Jev, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(settings.timeout_ms))
            .user_agent(concat!("lockout/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| format!("cannot build HTTP client: {e}"))?;
        Ok(Jev { http, settings })
    }
}

/// The request body. One `noul` (yes/no probability) question per category.
pub fn request_body(model: &str, input: &DeciderInput) -> Value {
    let questions: Map<String, Value> = input
        .questions
        .iter()
        .map(|(c, q)| (c.as_str().to_string(), json!({ "type": "noul", "instructions": q })))
        .collect();
    json!({ "model": model, "state": input.state, "questions": questions })
}

/// Reads a probability per asked category from a response. Accepts the answer
/// under `answers` (or the top level), as a bare number or as an object with
/// `probability`, `p` or `value`. Anything missing or out of range is an error:
/// an unreadable answer must never read as "clean".
pub fn parse_response(body: &Value, input: &DeciderInput) -> Result<Verdict, String> {
    let answers = body.get("answers").unwrap_or(body);
    let mut out = Vec::with_capacity(input.questions.len());
    for (category, _) in &input.questions {
        let a = answers.get(category.as_str()).ok_or_else(|| format!("response has no answer for `{category}`"))?;
        let p = a
            .as_f64()
            .or_else(|| ["probability", "p", "value"].iter().find_map(|k| a.get(*k).and_then(Value::as_f64)))
            .ok_or_else(|| format!("answer for `{category}` has no probability"))?;
        if !(0.0..=1.0).contains(&p) {
            return Err(format!("answer for `{category}` is out of range: {p}"));
        }
        out.push((*category, p as f32));
    }
    Ok(Verdict(out))
}

impl Decider for Jev {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send {
        let s = &self.settings;
        let key = if s.api_key_header.eq_ignore_ascii_case("authorization") {
            format!("Bearer {}", s.api_key)
        } else {
            s.api_key.clone()
        };
        let request =
            self.http.post(&s.url).header(s.api_key_header.as_str(), key).json(&request_body(&s.model, &input));
        let timeout_ms = s.timeout_ms;
        async move {
            let response = request.send().await.map_err(|e| {
                if e.is_timeout() {
                    format!("no answer within {timeout_ms} ms")
                } else {
                    format!("Jev request failed: {}", without_url(&e))
                }
            })?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("Jev answered HTTP {status}"));
            }
            let body: Value =
                response.json().await.map_err(|e| format!("Jev response is not JSON: {}", without_url(&e)))?;
            parse_response(&body, &input)
        }
    }
}

/// reqwest errors include the URL; keep messages short and free of query strings.
fn without_url(e: &reqwest::Error) -> String {
    let mut msg = e.to_string();
    if let Some(url) = e.url() {
        msg = msg.replace(&format!(" for url ({url})"), "");
    }
    msg
}

/// Stops calling a failing decider: after `threshold` consecutive failures,
/// calls fail at once for `cooldown`, then one call probes again.
pub struct Breaker<D> {
    inner: D,
    threshold: u32,
    cooldown: Duration,
    state: Mutex<BreakerState>,
}

#[derive(Default)]
struct BreakerState {
    failures: u32,
    open_until: Option<Instant>,
}

impl<D: Decider> Breaker<D> {
    pub fn new(inner: D, threshold: u32, cooldown: Duration) -> Breaker<D> {
        Breaker { inner, threshold, cooldown, state: Mutex::default() }
    }

    fn record(&self, ok: bool) {
        let mut s = self.state.lock().expect("breaker lock");
        if ok {
            *s = BreakerState::default();
        } else {
            s.failures += 1;
            if s.failures >= self.threshold {
                s.open_until = Some(Instant::now() + self.cooldown);
            }
        }
    }
}

impl<D: Decider> Decider for Breaker<D> {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send {
        let open = {
            let mut s = self.state.lock().expect("breaker lock");
            match s.open_until {
                Some(t) if Instant::now() < t => true,
                Some(_) => {
                    // Cooldown over: let this call probe; the next failure re-opens.
                    s.open_until = None;
                    s.failures = self.threshold - 1;
                    false
                }
                None => false,
            }
        };
        async move {
            if open {
                return Err("Jev circuit open after repeated failures".into());
            }
            let result = self.inner.decide(input).await;
            self.record(result.is_ok());
            result
        }
    }
}

/// Stable key for a decider input: the same text and questions replay the same answer.
pub fn input_key(input: &DeciderInput) -> String {
    let mut h = Sha256::new();
    h.update(input.state.as_bytes());
    for (c, q) in &input.questions {
        h.update([0]);
        h.update(c.as_str());
        h.update([0]);
        h.update(q.as_bytes());
    }
    h.finalize().iter().take(16).map(|b| format!("{b:02x}")).collect()
}

/// Saved answers, one JSON object per line: `{"key": ..., "answers": {category: p}}`.
pub type Recordings = HashMap<String, Vec<(Category, f32)>>;

pub fn load_recordings(src: &str) -> Result<Recordings, String> {
    let mut out = Recordings::new();
    for (i, line) in src.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        let v: Value = serde_json::from_str(line).map_err(|e| format!("line {}: {e}", i + 1))?;
        let key = v["key"].as_str().ok_or_else(|| format!("line {}: no key", i + 1))?.to_string();
        let answers = v["answers"].as_object().ok_or_else(|| format!("line {}: no answers", i + 1))?;
        let mut verdict = Vec::new();
        for (c, p) in answers {
            let c: Category = c.parse().map_err(|e| format!("line {}: {e}", i + 1))?;
            verdict.push((c, p.as_f64().ok_or_else(|| format!("line {}: bad probability", i + 1))? as f32));
        }
        out.insert(key, verdict);
    }
    Ok(out)
}

pub fn recording_line(key: &str, verdict: &Verdict) -> String {
    let answers: Map<String, Value> = verdict.0.iter().map(|(c, p)| (c.as_str().to_string(), json!(p))).collect();
    json!({ "key": key, "answers": answers }).to_string()
}

/// Answers from recordings; an input that was never recorded is an error.
pub struct Replay(pub Recordings);

impl Decider for Replay {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send {
        let key = input_key(&input);
        let found = self.0.get(&key).cloned();
        async move { found.map(Verdict).ok_or_else(|| format!("no recording for input {key}")) }
    }
}

/// Wraps a decider and keeps every answer, for writing recordings.
pub struct Recorder<D> {
    pub inner: D,
    pub seen: Arc<Mutex<Vec<(String, Verdict)>>>,
}

impl<D: Decider> Decider for Recorder<D> {
    fn decide(&self, input: DeciderInput) -> impl Future<Output = Result<Verdict, String>> + Send {
        let key = input_key(&input);
        async move {
            let v = self.inner.decide(input).await?;
            self.seen.lock().expect("recorder lock").push((key, v.clone()));
            Ok(v)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> DeciderInput {
        DeciderInput {
            state: "text".into(),
            questions: vec![(Category::WorkerHealth, "q1".into()), (Category::PrivacyCase, "q2".into())],
        }
    }

    #[test]
    fn request_has_one_noul_per_category() {
        let body = request_body("jev", &input());
        assert_eq!(body["questions"]["worker_health"]["type"], "noul");
        assert_eq!(body["questions"]["privacy_case"]["instructions"], "q2");
        assert_eq!(body["state"], "text");
    }

    #[test]
    fn parses_the_shapes_we_accept() {
        for body in [
            json!({"answers": {"worker_health": 0.9, "privacy_case": 0.1}}),
            json!({"answers": {"worker_health": {"probability": 0.9}, "privacy_case": {"p": 0.1}}}),
            json!({"worker_health": {"value": 0.9}, "privacy_case": 0.1}),
        ] {
            let v = parse_response(&body, &input()).unwrap();
            assert_eq!(v.0, vec![(Category::WorkerHealth, 0.9), (Category::PrivacyCase, 0.1)]);
        }
    }

    #[test]
    fn unreadable_answers_are_errors_not_clean() {
        for body in [
            json!({"answers": {"worker_health": 0.9}}),
            json!({"answers": {"worker_health": "yes", "privacy_case": 0.1}}),
            json!({"answers": {"worker_health": 1.5, "privacy_case": 0.1}}),
        ] {
            assert!(parse_response(&body, &input()).is_err(), "{body}");
        }
    }

    #[test]
    fn recordings_round_trip() {
        let v = Verdict(vec![(Category::WorkerHealth, 0.25)]);
        let key = input_key(&input());
        let recs = load_recordings(&recording_line(&key, &v)).unwrap();
        assert_eq!(recs[&key], v.0);
    }
}
