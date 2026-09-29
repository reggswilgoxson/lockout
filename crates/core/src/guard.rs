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

use hmac::{Hmac, Mac};
use serde::Serialize;
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

#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    /// Checked text, safe to pass on.
    Release(String),
    /// A finding whose action is `warn`. The text around it is still released.
    Warn(Finding),
    /// Findings whose action is `block`. In `Filter` mode nothing more is released.
    Block(Vec<Finding>),
}

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
        })
    }

    pub fn is_blocked(&self) -> bool {
        self.blocked
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
        for d in self.detectors.scan(&norm.text) {
            let (start, end) = norm.original_span(d.start, d.end);
            if !last && d.end == norm.text.len() && start >= release {
                continue; // judged next segment, with its full context
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
                self.blocked = true;
                self.buf.clear();
                return;
            }
        }

        if release > 0 {
            events.push(Event::Release(self.buf[..release].to_string()));
            self.buf.drain(..release);
            self.base += release;
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
}
