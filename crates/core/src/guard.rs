//! The holdback guard: text goes in, and only text that has been checked comes out.
//!
//! Incoming text is buffered and cut into *segments*: at a sentence or line
//! boundary once the buffer holds `min` bytes (`first_min` for the first
//! segment, so text appears quickly), at `max` bytes, or at end of stream.
//! Each segment is checked. If nothing blocks, the segment is released
//! **except its last `overlap` normalized bytes** (moved back to a whitespace
//! where one is near). That tail opens the next segment.
//!
//! Why this is safe: take any identifier whose detector reads at most
//! `overlap` bytes. Let segment k be the first segment that ends at or after the
//! identifier's end. Segment k begins at the release point of segment k-1,
//! which lies at least `overlap` bytes before k-1's end, and k-1 ended before
//! the identifier did. So segment k contains the whole identifier, and nothing
//! from segment k is released until k has been checked. A match that touches
//! the open end of a segment is not judged there; it lies inside the tail and is
//! judged in the next segment, with its full context.
//!
//! With a decider (Jev) enabled, each checked segment also becomes a
//! [`Event::SegmentReady`] carrying the questions to ask. Its text is held until
//! [`Guard::verdict`] or [`Guard::decider_failed`] arrives for it, and segments are
//! released strictly in order, whatever order their verdicts arrive in. The
//! guard itself does no I/O: the caller runs the requests.

use std::collections::VecDeque;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::detect::{Detectors, MAX_CONTEXT};
use crate::normalize::{Normalized, normalize};
use crate::policy::{Action, Category, Policy};

/// Segment sizes, in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentConfig {
    pub first_min: usize,
    pub min: usize,
    pub max: usize,
    pub overlap: usize,
}

impl Default for SegmentConfig {
    fn default() -> Self {
        SegmentConfig { first_min: 100, min: 240, max: 800, overlap: MAX_CONTEXT }
    }
}

impl SegmentConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.overlap < MAX_CONTEXT {
            return Err(format!("segment overlap must be at least {MAX_CONTEXT}"));
        }
        if self.first_min <= self.overlap {
            return Err("segment first_min must be larger than overlap".into());
        }
        if self.min < self.first_min || self.max < self.min {
            return Err("segment sizes must satisfy first_min <= min <= max".into());
        }
        Ok(())
    }
}

/// `Filter` stops at the first block. `Report` keeps going to find everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Filter,
    Report,
}

/// One finding. It never contains the text it flags.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    pub action: Action,
    pub category: Category,
    /// `local:<detector>` or `jev`.
    pub source: String,
    /// Byte range in the original stream.
    pub start: usize,
    pub end: usize,
    /// Jev's probability; `None` for deterministic local rules.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probability: Option<f32>,
    pub citations: Vec<String>,
    /// HMAC-SHA256 of the normalized match, when a key is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

/// What to do when the decider cannot answer for a segment (timeout, error,
/// circuit open).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnError {
    /// Fail closed: stop the stream.
    #[default]
    Block,
    /// Release the segment on the strength of the local rules, and say so.
    LocalOnly,
}

pub type SegmentId = u64;

/// What the decider is asked about one segment.
#[derive(Clone, Debug, PartialEq)]
pub struct DeciderInput {
    /// Excerpts from earlier in the response that identify someone (at most
    /// three), followed by the segment itself.
    pub state: String,
    /// (category, question) for every category that has a question and is not `off`.
    pub questions: Vec<(Category, String)>,
}

/// The decider's answer: a probability per category asked.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Verdict(pub Vec<(Category, f32)>);

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Checked text, safe to pass on.
    Release(String),
    /// A finding whose action is `warn`. The text around it is still released.
    Warn(Finding),
    /// Findings whose action is `block`. In `Filter` mode nothing more is released.
    Block(Vec<Finding>),
    /// Ask the decider about this segment, then call [`Guard::verdict`] or
    /// [`Guard::decider_failed`] with the same id.
    SegmentReady(SegmentId, DeciderInput),
    /// The decider could not answer. `fatal` (on_error = block) stops a
    /// `Filter` stream; otherwise the segment was released on local rules only.
    DeciderFailed { fatal: bool },
}

/// A checked segment waiting for its verdict.
struct Pending {
    id: SegmentId,
    /// Text to release once cleared (may be empty for the tail-only last segment).
    text: String,
    /// The segment's window, for subject memory, and its stream range.
    window: String,
    start: usize,
    end: usize,
    verdict: Option<Verdict>,
}

/// How many earlier excerpts are kept, and how long each may be.
const MEMORY_ITEMS: usize = 3;
const MEMORY_BYTES: usize = 200;

pub struct Guard {
    policy: Policy,
    detectors: Detectors,
    seg: SegmentConfig,
    mode: Mode,
    hmac_key: Option<Vec<u8>>,
    /// Unreleased text; `buf[0]` is at stream offset `base`.
    buf: String,
    base: usize,
    /// Bytes at the front of `buf` already covered by a check.
    checked: usize,
    first: bool,
    blocked: bool,
    /// Findings already reported, as (stream start, stream end, source).
    reported: Vec<(usize, usize, String)>,
    /// `Some` when a decider is in use.
    decider: Option<OnError>,
    pending: VecDeque<Pending>,
    next_id: SegmentId,
    /// Excerpts that identify someone, sent to the decider with later segments.
    memory: VecDeque<String>,
}

impl Guard {
    pub fn new(
        policy: Policy,
        detectors: Detectors,
        seg: SegmentConfig,
        mode: Mode,
        hmac_key: Option<Vec<u8>>,
    ) -> Result<Guard, String> {
        seg.validate()?;
        Ok(Guard {
            policy,
            detectors,
            seg,
            mode,
            hmac_key,
            buf: String::new(),
            base: 0,
            checked: 0,
            first: true,
            blocked: false,
            reported: Vec::new(),
            decider: None,
            pending: VecDeque::new(),
            next_id: 0,
            memory: VecDeque::new(),
        })
    }

    /// Turns on decider mode: segments wait for a verdict before release.
    pub fn with_decider(mut self, on_error: OnError) -> Guard {
        self.decider = Some(on_error);
        self
    }

    pub fn is_blocked(&self) -> bool {
        self.blocked
    }

    /// True when no segment is waiting for a verdict.
    pub fn is_idle(&self) -> bool {
        self.pending.is_empty()
    }

    /// Bytes held back: buffered plus waiting for verdicts. Callers stop
    /// reading input above their limit (back-pressure).
    pub fn held_bytes(&self) -> usize {
        self.buf.len() + self.pending.iter().map(|p| p.text.len()).sum::<usize>()
    }

    /// The decider's answer for a segment.
    pub fn verdict(&mut self, id: SegmentId, verdict: Verdict) -> Vec<Event> {
        let mut events = Vec::new();
        self.verdict_inner(id, verdict, &mut events);
        events
    }

    /// The decider could not answer for a segment.
    pub fn decider_failed(&mut self, id: SegmentId) -> Vec<Event> {
        let mut events = Vec::new();
        if self.blocked || !self.pending.iter().any(|p| p.id == id) {
            return events;
        }
        let fatal = self.decider == Some(OnError::Block);
        events.push(Event::DeciderFailed { fatal });
        if fatal && self.mode == Mode::Filter {
            self.stop();
            return events;
        }
        self.verdict_inner(id, Verdict::default(), &mut events);
        events
    }

    fn verdict_inner(&mut self, id: SegmentId, verdict: Verdict, events: &mut Vec<Event>) {
        if let Some(p) = self.pending.iter_mut().find(|p| p.id == id) {
            p.verdict = Some(verdict);
            self.flush(events);
        }
    }

    fn stop(&mut self) {
        self.blocked = true;
        self.buf.clear();
        self.pending.clear();
    }

    /// Releases, in order, every leading segment that has its verdict.
    fn flush(&mut self, events: &mut Vec<Event>) {
        while self.pending.front().is_some_and(|p| p.verdict.is_some()) {
            let p = self.pending.pop_front().expect("front exists");
            let verdict = p.verdict.clone().unwrap_or_default();
            let mut blocks = Vec::new();
            for (category, probability) in verdict.0 {
                let action = self.policy.action(category);
                let (block_at, warn_at) = self.policy.thresholds(category);
                let outcome = if action == Action::Off || probability < warn_at {
                    continue;
                } else if action == Action::Block && probability >= block_at {
                    Action::Block
                } else {
                    Action::Warn
                };
                if category == Category::PersonIdentity {
                    self.remember(&p.window);
                }
                let finding = Finding {
                    action: outcome,
                    category,
                    source: "jev".into(),
                    start: p.start,
                    end: p.end,
                    probability: Some(probability),
                    citations: self.policy.citations(category).to_vec(),
                    fingerprint: None,
                };
                match outcome {
                    Action::Block => blocks.push(finding),
                    _ => events.push(Event::Warn(finding)),
                }
            }
            if !blocks.is_empty() {
                events.push(Event::Block(blocks));
                if self.mode == Mode::Filter {
                    self.stop();
                    return;
                }
            }
            if !p.text.is_empty() {
                events.push(Event::Release(p.text));
            }
        }
    }

    fn remember(&mut self, excerpt: &str) {
        let excerpt = excerpt.trim();
        let mut end = excerpt.len().min(MEMORY_BYTES);
        while !excerpt.is_char_boundary(end) {
            end -= 1;
        }
        let excerpt = &excerpt[..end];
        if excerpt.is_empty() || self.memory.iter().any(|m| m.contains(excerpt) || excerpt.contains(m.as_str())) {
            return;
        }
        if self.memory.len() == MEMORY_ITEMS {
            self.memory.pop_front();
        }
        self.memory.push_back(excerpt.to_string());
    }

    fn decider_state(&self, window: &str) -> String {
        if self.memory.is_empty() {
            return window.to_string();
        }
        let earlier: Vec<String> = self.memory.iter().map(|m| format!("- {m}")).collect();
        format!("Earlier in this response:\n{}\n\nText:\n{window}", earlier.join("\n"))
    }

    /// Adds generated text. Returns what can be released, warned or blocked so far.
    pub fn push(&mut self, text: &str) -> Vec<Event> {
        let mut events = Vec::new();
        if self.blocked {
            return events;
        }
        self.buf.push_str(text);
        while let Some(cut) = self.next_cut() {
            self.check(cut, false, &mut events);
            if self.blocked {
                break;
            }
        }
        events
    }

    /// Ends the stream: checks and releases whatever is left.
    pub fn finish(&mut self) -> Vec<Event> {
        let mut events = Vec::new();
        if !self.blocked && !self.buf.is_empty() {
            self.check(self.buf.len(), true, &mut events);
        }
        events
    }

    fn next_cut(&self) -> Option<usize> {
        let min = if self.first { self.seg.first_min } else { self.seg.min };
        let len = self.buf.len();
        if len < min {
            return None;
        }
        let limit = self.seg.max.max(self.checked + 1);
        let bytes = self.buf.as_bytes();
        // Boundaries are ASCII, so a byte scan never lands inside a character.
        for i in (min - 1).max(self.checked)..len.min(limit) {
            match bytes[i] {
                b'\n' => return Some(i + 1),
                b'.' | b'!' | b'?' | b';' if bytes.get(i + 1).is_some_and(u8::is_ascii_whitespace) => {
                    return Some(i + 1);
                }
                _ => {}
            }
        }
        (len >= limit).then(|| ceil_boundary(&self.buf, limit))
    }

    fn check(&mut self, cut: usize, last: bool, events: &mut Vec<Event>) {
        let window = &self.buf[..cut];
        let norm = normalize(window);
        let release = if last { cut } else { release_point(&norm, window, self.seg.overlap) };

        let mut blocks = Vec::new();
        let mut identifies = Vec::new();
        for d in self.detectors.scan(&norm.text) {
            let (start, end) = norm.original_span(d.start, d.end);
            if !last && d.end == norm.text.len() && start >= release {
                continue; // judged next segment, with its full context
            }
            if matches!(d.category, Category::Contact | Category::EmployeeRef) {
                identifies.push(excerpt_around(window, start, end));
            }
            let action = self.policy.action(d.category);
            if action == Action::Off {
                continue;
            }
            let source = format!("local:{}", d.id);
            let key = (self.base + start, self.base + end, source);
            if self.reported.contains(&key) {
                continue;
            }
            let finding = Finding {
                action,
                category: d.category,
                source: key.2.clone(),
                start: key.0,
                end: key.1,
                probability: None,
                citations: self.policy.citations(d.category).to_vec(),
                fingerprint: self.fingerprint(&norm.text[d.start..d.end]),
            };
            self.reported.push(key);
            match action {
                Action::Block => blocks.push(finding),
                _ => events.push(Event::Warn(finding)),
            }
        }

        if !blocks.is_empty() {
            events.push(Event::Block(blocks));
            if self.mode == Mode::Filter {
                self.stop();
                return;
            }
        }

        let questions = if self.decider.is_some() { self.policy.questions() } else { Vec::new() };
        let ask = !questions.is_empty() && (release > 0 || last);
        // Ask with what was known before this segment; its own identifiers are in its text.
        let pending = ask.then(|| {
            let window = window.to_string();
            let input = DeciderInput { state: self.decider_state(&window), questions };
            (window, input)
        });
        for excerpt in identifies {
            self.remember(&excerpt);
        }

        let text = self.buf[..release].to_string();
        self.buf.drain(..release);
        let start = self.base;
        self.base += release;
        if let Some((window, input)) = pending {
            let id = self.next_id;
            self.next_id += 1;
            self.pending.push_back(Pending { id, text, end: start + window.len(), window, start, verdict: None });
            events.push(Event::SegmentReady(id, input));
        } else if let Some(back) = self.pending.back_mut() {
            back.text.push_str(&text); // keep order behind segments still waiting
        } else if !text.is_empty() {
            events.push(Event::Release(text));
        }
        self.checked = cut - release;
        self.first = false;
        let base = self.base;
        self.reported.retain(|(_, end, _)| *end > base);
    }

    fn fingerprint(&self, matched: &str) -> Option<String> {
        let key = self.hmac_key.as_ref()?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
        mac.update(matched.as_bytes());
        Some(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Up to `MEMORY_BYTES` of text centred on a match.
fn excerpt_around(window: &str, start: usize, end: usize) -> String {
    let pad = MEMORY_BYTES.saturating_sub(end - start) / 2;
    let from = floor_boundary(window, start.saturating_sub(pad));
    let to = ceil_boundary(window, (end + pad).min(window.len()));
    window[from..to].to_string()
}

/// Where to cut the release so that at least `overlap` normalized bytes stay
/// behind, moved back to a nearby whitespace so words are not split.
fn release_point(norm: &Normalized, window: &str, overlap: usize) -> usize {
    let n = norm.text.len();
    if n <= overlap {
        return 0;
    }
    let mut tail = n - overlap;
    while !norm.text.is_char_boundary(tail) {
        tail -= 1;
    }
    let point = norm.original_start(tail);
    let lo = floor_boundary(window, point.saturating_sub(32));
    window[lo..point].rfind(char::is_whitespace).map_or(point, |p| lo + p)
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(s: &str, mut i: usize) -> usize {
    while !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Allow;
    use crate::policy::{Audience, Rules};

    fn guard(mode: Mode) -> Guard {
        let policy = Policy::new(Rules::builtin(), Audience::Site, Default::default());
        Guard::new(policy, Detectors::new(Allow::default(), vec![]), SegmentConfig::default(), mode, None).unwrap()
    }

    fn run(g: &mut Guard, chunks: &[&str]) -> (String, Vec<Event>) {
        let mut events: Vec<Event> = chunks.iter().flat_map(|c| g.push(c)).collect();
        events.extend(g.finish());
        let released =
            events.iter().filter_map(|e| if let Event::Release(s) = e { Some(s.as_str()) } else { None }).collect();
        (released, events)
    }

    #[test]
    fn clean_text_passes_through_unchanged() {
        let text = "Lockout/tagout applies before servicing. Verify zero energy. ".repeat(40);
        let (out, events) = run(&mut guard(Mode::Filter), &[&text]);
        assert_eq!(out, text);
        assert!(events.iter().all(|e| matches!(e, Event::Release(_))));
    }

    #[test]
    fn releases_early_but_holds_the_tail() {
        let mut g = guard(Mode::Filter);
        let events = g.push(&"The crew isolated the conveyor. ".repeat(5));
        let released: usize = events.iter().map(|e| if let Event::Release(s) = e { s.len() } else { 0 }).sum();
        assert!(released > 0 && released <= 160 - 64);
    }

    #[test]
    fn blocks_and_withholds_the_segment() {
        let text = format!("{}Contact dave.miller@acme-corp.com for details.", "Summary of the week. ".repeat(3));
        let (out, events) = run(&mut guard(Mode::Filter), &[&text]);
        assert!(!out.contains("dave"));
        let Some(Event::Block(f)) = events.last() else { panic!("no block: {events:?}") };
        assert_eq!(f[0].category, Category::Contact);
        assert_eq!(&text[f[0].start..f[0].end], "dave.miller@acme-corp.com");
    }

    #[test]
    fn report_mode_finds_everything_once() {
        let text = format!(
            "{}call +44 20 7946 0958. {}and 4556 7375 8689 9855 too.",
            "padding sentence here. ".repeat(20),
            "more padding text. ".repeat(20)
        );
        let (_, events) = run(&mut guard(Mode::Report), &[&text]);
        let sources: Vec<String> = events
            .iter()
            .flat_map(|e| if let Event::Block(f) = e { f.clone() } else { vec![] })
            .map(|f| f.source)
            .collect();
        assert_eq!(sources, ["local:phone", "local:payment_card"]);
    }

    #[test]
    fn warn_categories_release_text() {
        let policy = Policy::new(Rules::builtin(), Audience::Site, Default::default());
        let custom = vec![("employee_id".to_string(), regex::Regex::new(r"\bE\d{6}\b").unwrap())];
        let mut g =
            Guard::new(policy, Detectors::new(Allow::default(), custom), SegmentConfig::default(), Mode::Filter, None)
                .unwrap();
        let (out, events) = run(&mut g, &["Badge E123456 was scanned at the gate."]);
        assert_eq!(out, "Badge E123456 was scanned at the gate.");
        assert!(matches!(&events[0], Event::Warn(f) if f.category == Category::EmployeeRef));
    }

    #[test]
    fn fingerprint_only_with_key() {
        let policy = Policy::new(Rules::builtin(), Audience::Site, Default::default());
        let mut g = Guard::new(
            policy,
            Detectors::new(Allow::default(), vec![]),
            SegmentConfig::default(),
            Mode::Filter,
            Some(b"k".to_vec()),
        )
        .unwrap();
        let (_, events) = run(&mut g, &["mail a.b@acme.org"]);
        let Some(Event::Block(f)) = events.last() else { panic!() };
        assert_eq!(f[0].fingerprint.as_ref().map(String::len), Some(64));
    }

    #[test]
    fn rejects_unsafe_segment_sizes() {
        let seg = SegmentConfig { overlap: 10, ..Default::default() };
        assert!(seg.validate().is_err());
    }

    // ---- decider mode ----

    fn decider_guard(audience: Audience, on_error: OnError) -> Guard {
        let policy = Policy::new(Rules::builtin(), audience, Default::default());
        Guard::new(policy, Detectors::new(Allow::default(), vec![]), SegmentConfig::default(), Mode::Filter, None)
            .unwrap()
            .with_decider(on_error)
    }

    fn released(events: &[Event]) -> String {
        events.iter().filter_map(|e| if let Event::Release(s) = e { Some(s.as_str()) } else { None }).collect()
    }

    fn asked(events: &[Event]) -> Vec<(SegmentId, DeciderInput)> {
        events
            .iter()
            .filter_map(|e| if let Event::SegmentReady(id, i) = e { Some((*id, i.clone())) } else { None })
            .collect()
    }

    const REPORT: &str = "The crew isolated the conveyor before cleaning it. ";

    #[test]
    fn nothing_is_released_before_its_verdict_and_order_is_kept() {
        let mut g = decider_guard(Audience::Site, OnError::Block);
        let text = REPORT.repeat(30);
        let mut events = g.push(&text);
        events.extend(g.finish());
        assert_eq!(released(&events), "");
        let ids: Vec<SegmentId> = asked(&events).into_iter().map(|(id, _)| id).collect();
        assert!(ids.len() >= 3);

        // Answer every segment but the first: still nothing may be released.
        let mut out = Vec::new();
        for id in ids.iter().rev().take(ids.len() - 1) {
            out.extend(g.verdict(*id, Verdict::default()));
        }
        assert_eq!(released(&out), "");
        // The first answer releases everything, in order.
        out.extend(g.verdict(ids[0], Verdict::default()));
        assert_eq!(released(&out), text);
        assert!(g.is_idle());
    }

    #[test]
    fn jev_block_withholds_its_segment() {
        let mut g = decider_guard(Audience::Site, OnError::Block);
        let mut events = g.push("Maria from night shift had a needlestick injury on Tuesday.");
        events.extend(g.finish());
        let (id, input) = asked(&events).remove(0);
        assert!(input.questions.iter().any(|(c, _)| *c == Category::PrivacyCase));
        let out = g.verdict(id, Verdict(vec![(Category::PrivacyCase, 0.93), (Category::PersonIdentity, 0.2)]));
        assert_eq!(released(&out), "");
        let Some(Event::Block(f)) = out.last() else { panic!("{out:?}") };
        assert_eq!((f[0].category, f[0].source.as_str(), f[0].probability), (Category::PrivacyCase, "jev", Some(0.93)));
        assert!(g.is_blocked());
    }

    #[test]
    fn jev_warn_and_below_threshold() {
        let mut g = decider_guard(Audience::Site, OnError::Block);
        let text = "The supervisor was disciplined after the forklift incident.";
        let mut events = g.push(text);
        events.extend(g.finish());
        let (id, _) = asked(&events).remove(0);
        let out = g.verdict(id, Verdict(vec![(Category::FaultOrDiscipline, 0.9), (Category::WorkerHealth, 0.3)]));
        assert_eq!(released(&out), text);
        let warns: Vec<Category> =
            out.iter().filter_map(|e| if let Event::Warn(f) = e { Some(f.category) } else { None }).collect();
        assert_eq!(warns, [Category::FaultOrDiscipline]);
    }

    #[test]
    fn decider_failure_blocks_or_falls_back() {
        let mut g = decider_guard(Audience::Site, OnError::Block);
        let events = [g.push(REPORT), g.finish()].concat();
        let (id, _) = asked(&events).remove(0);
        assert_eq!(g.decider_failed(id), [Event::DeciderFailed { fatal: true }]);
        assert!(g.is_blocked());

        let mut g = decider_guard(Audience::Site, OnError::LocalOnly);
        let events = [g.push(REPORT), g.finish()].concat();
        let (id, _) = asked(&events).remove(0);
        let out = g.decider_failed(id);
        assert_eq!(out, [Event::DeciderFailed { fatal: false }, Event::Release(REPORT.into())]);
    }

    #[test]
    fn later_segments_carry_who_the_text_is_about() {
        let mut g = decider_guard(Audience::Investigation, OnError::Block);
        let first = "Witness statement from dave.miller@acme-corp.com about the fall. ";
        let mut events = g.push(&format!("{first}{}", REPORT.repeat(12)));
        events.extend(g.finish());
        let inputs = asked(&events);
        assert!(!inputs[0].1.state.starts_with("Earlier"), "memory must not include the segment's own text");
        let later = &inputs.last().unwrap().1.state;
        assert!(later.starts_with("Earlier in this response:\n- "), "{later}");
        assert!(later.contains("dave.miller@acme-corp.com"));
    }

    #[test]
    fn local_block_does_not_wait_for_the_decider() {
        let mut g = decider_guard(Audience::Site, OnError::Block);
        let events = g.push("Card 4556 7375 8689 9855 was used.");
        let events = [events, g.finish()].concat();
        assert!(events.iter().any(|e| matches!(e, Event::Block(_))));
        assert!(asked(&events).is_empty());
    }
}
