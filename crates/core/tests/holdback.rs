//! Phase 1 acceptance: an identifier is never released, in whole or in part,
//! however the stream is chunked and wherever it falls relative to segment
//! boundaries.

use lockout_ai_core::guard::{OnError, Verdict};
use lockout_ai_core::{Allow, Audience, Detectors, Event, Guard, Mode, Policy, Rules, SegmentConfig};
use proptest::prelude::*;
use std::sync::LazyLock;

static DETECTORS: LazyLock<Detectors> = LazyLock::new(|| Detectors::new(Allow::default(), vec![]));
static RULES: LazyLock<Rules> = LazyLock::new(Rules::builtin);

/// (identifier as it appears in the stream, filler that surrounds it)
const POSITIVES: &[&str] = &[
    "dave.miller@acme-corp.com",
    "d.miller[at]acme-corp(dot)com",
    "+44 20 7946 0958",
    "(312) 555-2368",
    "4556 7375 8689 9855",
    "4556\u{200B}7375\u{200B}8689\u{200B}9855",
    "４５５６７３７５８６８９９８５５",
    "DE89 3704 0044 0532 0130 00",
    "536-22-4181",
    "AB 12 34 56 C",
    "Steuer-ID 86 095 742 719",
    "2 55 08 14 168 025 38",
    "12345678Z",
    "RSSMRA85T10A562S",
    "BSN 111222333",
    "L898902C36UTO7408122F1204159ZE184226B<<<<<10",
];

const FILLER: &str = "The crew verified zero energy at every isolation point before work began. \
Near misses are reviewed weekly; trends go to the site safety committee. ";

fn configs() -> [SegmentConfig; 2] {
    [
        SegmentConfig::default(),
        // Small segments: many boundaries, so identifiers straddle them often.
        SegmentConfig { first_min: 70, min: 80, max: 120, overlap: 64 },
    ]
}

fn guard(seg: SegmentConfig) -> Guard {
    let policy = Policy::new(RULES.clone(), Audience::Site, Default::default());
    Guard::new(policy, DETECTORS.clone(), seg, Mode::Filter, None).unwrap()
}

/// Streams `chunks`, returns (released text, whether it blocked).
fn stream(seg: SegmentConfig, chunks: &[&str]) -> (String, bool) {
    let mut g = guard(seg);
    let mut out = String::new();
    let mut blocked = false;
    let mut events: Vec<Event> = chunks.iter().flat_map(|c| g.push(c)).collect();
    events.extend(g.finish());
    for e in events {
        match e {
            Event::Release(s) => out.push_str(&s),
            Event::Block(_) => blocked = true,
            _ => {}
        }
    }
    (out, blocked)
}

fn sample(pad: usize, id: &str) -> (String, usize) {
    let lead: String = FILLER.chars().cycle().take(pad).collect();
    let text = format!("{lead} Ref: {id} — noted. {FILLER}");
    let at = text.find(id).unwrap();
    (text, at)
}

fn assert_safe(text: &str, id_start: usize, released: &str, blocked: bool, what: &str) {
    assert!(blocked, "not blocked: {what}");
    assert!(text.starts_with(released), "released text is not a prefix: {what}");
    assert!(released.len() <= id_start, "released {} bytes past identifier start {id_start}: {what}", released.len());
}

#[test]
#[ignore = "exhaustive (~1 min); CI runs it with --include-ignored"]
fn every_two_way_split_at_every_segment_position() {
    for seg in configs() {
        for id in POSITIVES {
            // Slide the identifier across a full segment's worth of positions,
            // and split at every byte from well before it to well after it.
            for pad in (0..seg.max + 20).step_by(11) {
                let (text, at) = sample(pad, id);
                let window = at.saturating_sub(seg.overlap)..=(at + id.len() + seg.overlap).min(text.len());
                for split in window.filter(|&i| text.is_char_boundary(i)) {
                    let (out, blocked) = stream(seg, &[&text[..split], &text[split..]]);
                    assert_safe(&text, at, &out, blocked, &format!("{id:?} pad={pad} split={split} {seg:?}"));
                }
            }
        }
    }
}

#[test]
fn token_sized_chunks() {
    for seg in configs() {
        for id in POSITIVES {
            for pad in 0..seg.max + 20 {
                let (text, at) = sample(pad, id);
                let chunks: Vec<&str> = split_every(&text, 3);
                let (out, blocked) = stream(seg, &chunks);
                assert_safe(&text, at, &out, blocked, &format!("{id:?} pad={pad} {seg:?}"));
            }
        }
    }
}

fn split_every(s: &str, n: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut count = 0;
    for (i, _) in s.char_indices() {
        if count == n {
            out.push(&s[start..i]);
            start = i;
            count = 0;
        }
        count += 1;
    }
    out.push(&s[start..]);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn random_chunking(id in 0..POSITIVES.len(), pad in 0usize..400, cuts in prop::collection::vec(0usize..2000, 0..40), small in any::<bool>()) {
        let seg = configs()[small as usize];
        let (text, at) = sample(pad, POSITIVES[id]);
        let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (text.len() + 1)).filter(|&i| text.is_char_boundary(i)).collect();
        points.sort_unstable();
        points.dedup();
        let mut chunks = Vec::new();
        let mut last = 0;
        for p in points {
            chunks.push(&text[last..p]);
            last = p;
        }
        chunks.push(&text[last..]);
        let (out, blocked) = stream(seg, &chunks);
        prop_assert!(blocked);
        prop_assert!(text.starts_with(&out));
        prop_assert!(out.len() <= at);
    }

    #[test]
    fn clean_text_is_released_byte_identical(pad in 0usize..3000, cuts in prop::collection::vec(0usize..4000, 0..40), small in any::<bool>()) {
        let seg = configs()[small as usize];
        let text: String = FILLER.chars().cycle().take(pad).collect();
        let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (text.len() + 1)).collect();
        points.sort_unstable();
        points.dedup();
        let mut chunks = Vec::new();
        let mut last = 0;
        for p in points {
            chunks.push(&text[last..p]);
            last = p;
        }
        chunks.push(&text[last..]);
        let (out, blocked) = stream(seg, &chunks);
        prop_assert!(!blocked);
        prop_assert_eq!(out, text);
    }

    #[test]
    fn decider_mode_keeps_order_whatever_order_verdicts_arrive(
        pad in 0usize..3000,
        cuts in prop::collection::vec(0usize..4000, 0..20),
        order in prop::collection::vec(any::<u32>(), 0..64),
    ) {
        let policy = Policy::new(RULES.clone(), Audience::Site, Default::default());
        let mut g = Guard::new(policy, DETECTORS.clone(), SegmentConfig::default(), Mode::Filter, None)
            .unwrap()
            .with_decider(OnError::Block);
        let text: String = FILLER.chars().cycle().take(pad).collect();
        let mut points: Vec<usize> = cuts.into_iter().map(|c| c % (text.len() + 1)).collect();
        points.sort_unstable();
        points.dedup();
        let mut events = Vec::new();
        let mut last = 0;
        for p in points.into_iter().chain([text.len()]) {
            events.extend(g.push(&text[last..p]));
            last = p;
        }
        events.extend(g.finish());
        let mut ids: Vec<u64> = events.iter().filter_map(|e| if let Event::SegmentReady(id, _) = e { Some(*id) } else { None }).collect();
        // Shuffle the answer order deterministically from `order`.
        for (i, r) in order.iter().enumerate() {
            if ids.len() > 1 {
                let a = i % ids.len();
                let b = *r as usize % ids.len();
                ids.swap(a, b);
            }
        }
        for id in ids {
            events.extend(g.verdict(id, Verdict::default()));
        }
        let out: String = events.iter().filter_map(|e| if let Event::Release(s) = e { Some(s.as_str()) } else { None }).collect();
        prop_assert!(g.is_idle());
        prop_assert_eq!(out, text);
    }
}
