//! Phase 1 acceptance: realistic EHS and technical text full of numbers must
//! produce no findings, even for the strictest audience.

use lockout_ai_core::{Allow, Audience, Detectors, Event, Guard, Mode, Policy, Rules, SegmentConfig};

const CORPUS: &str = include_str!("fixtures/hard_negatives.txt");

#[test]
fn no_findings_on_hard_negatives() {
    let policy = Policy::new(Rules::builtin(), Audience::Public, Default::default());
    let mut g =
        Guard::new(policy, Detectors::new(Allow::default(), vec![]), SegmentConfig::default(), Mode::Report, None)
            .unwrap();
    let mut events = g.push(CORPUS);
    events.extend(g.finish());
    let findings: Vec<String> = events
        .iter()
        .flat_map(|e| match e {
            Event::Warn(f) => vec![f.clone()],
            Event::Block(fs) => fs.clone(),
            _ => vec![],
        })
        .map(|f| format!("{} {:?}", f.source, &CORPUS[f.start..f.end]))
        .collect();
    assert!(findings.is_empty(), "false positives: {findings:#?}");
}
