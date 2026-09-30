//! `lockout eval`: runs every labelled case through the guard, then prints
//! precision and recall per category and the decider's latency.
//!
//! Cases are JSON lines: `{"id": "...", "text": "...", "labels": ["worker_health", ...]}`.
//! `labels` lists every category a careful reviewer would flag at audience
//! `public`, where no category is off. An empty list is a hard negative.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clap::Args;
use lockout_ai_core::{Audience, Category, Mode};
use serde::Deserialize;

use crate::drive::{Summary, drive};
use crate::jev::{Decider, Recorder, Replay, load_recordings, recording_line};
use crate::{CommonArgs, EXIT_OK, EXIT_USAGE, Fail, JevMode, Setup, live_decider, setup, usage};

#[derive(Args)]
pub struct EvalArgs {
    /// Labelled cases, one JSON object per line.
    #[arg(long, default_value = "bench/cases.jsonl")]
    cases: PathBuf,
    /// Answer from saved recordings instead of calling Jev.
    #[arg(long, conflicts_with = "record")]
    replay: Option<PathBuf>,
    /// Call Jev and save its answers here, for --replay.
    #[arg(long)]
    record: Option<PathBuf>,
    /// Config file. Default: ./lockout.toml if it exists.
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    text: String,
    labels: BTreeSet<Category>,
}

fn load_cases(path: &PathBuf) -> Result<Vec<Case>, Fail> {
    let src = std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
    src.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| serde_json::from_str(l).map_err(|e| usage(format!("{}:{}: {e}", path.display(), i + 1))))
        .collect()
}

pub async fn run(args: EvalArgs) -> Result<u8, Fail> {
    let cases = load_cases(&args.cases)?;
    let common = CommonArgs {
        audience: Some(Audience::Public),
        config: args.config.clone(),
        jev: if args.replay.is_some() { JevMode::Off } else { JevMode::Auto },
    };
    if let Some(path) = &args.replay {
        let src = std::fs::read_to_string(path).map_err(|e| usage(format!("{}: {e}", path.display())))?;
        let decider = Arc::new(Replay(load_recordings(&src).map_err(usage)?));
        return score(&cases, &common, Some(decider)).await;
    }
    let jev = setup(&common, Mode::Report, true)?.jev;
    match (jev, &args.record) {
        (None, Some(_)) => Err((EXIT_USAGE, "--record needs Jev: set JEV_API_KEY and JEV_URL".into())),
        (None, None) => {
            eprintln!("lockout: no Jev configured; scoring local rules only");
            score::<Replay>(&cases, &common, None).await
        }
        (Some(settings), None) => score(&cases, &common, Some(live_decider(&settings)?)).await,
        (Some(settings), Some(path)) => {
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorder = Arc::new(Recorder { inner: live_decider(&settings)?, seen: seen.clone() });
            let code = score(&cases, &common, Some(recorder)).await?;
            let lines: Vec<String> =
                seen.lock().expect("recorder lock").iter().map(|(k, v)| recording_line(k, v)).collect();
            std::fs::write(path, lines.join("\n") + "\n").map_err(|e| usage(format!("{}: {e}", path.display())))?;
            eprintln!("lockout: saved {} answers to {}", lines.len(), path.display());
            Ok(code)
        }
    }
}

#[derive(Default)]
struct Tally {
    tp: usize,
    fp: usize,
    fn_: usize,
}

async fn score<D: Decider>(cases: &[Case], common: &CommonArgs, decider: Option<Arc<D>>) -> Result<u8, Fail> {
    let mut tally: BTreeMap<Category, Tally> = Category::ALL.into_iter().map(|c| (c, Tally::default())).collect();
    let mut latencies = Vec::new();
    let mut failures = 0;
    let mut misses = Vec::new();
    for case in cases {
        let Setup { mut guard, opts, .. } = setup(common, Mode::Report, true)?;
        if decider.is_some() {
            guard = guard.with_decider(lockout_ai_core::guard::OnError::LocalOnly);
        }
        let summary: Summary = drive(guard, decider.clone(), case.text.as_bytes(), opts, |_| Ok(())).await?;
        latencies.extend(summary.latencies);
        failures += summary.decider_failures;
        let found: BTreeSet<Category> = summary.findings.iter().map(|f| f.category).collect();
        for c in Category::ALL {
            let t = tally.get_mut(&c).expect("all categories");
            match (case.labels.contains(&c), found.contains(&c)) {
                (true, true) => t.tp += 1,
                (false, true) => {
                    t.fp += 1;
                    misses.push(format!("{}: false positive {c}", case.id));
                }
                (true, false) => {
                    t.fn_ += 1;
                    misses.push(format!("{}: missed {c}", case.id));
                }
                (false, false) => {}
            }
        }
    }

    println!("{} cases, audience public{}", cases.len(), if decider.is_some() { "" } else { ", local rules only" });
    println!("{:<20} {:>9} {:>9} {:>5} {:>5} {:>5}", "category", "precision", "recall", "tp", "fp", "fn");
    for (c, t) in &tally {
        let pct = |n: usize, d: usize| {
            if d == 0 { "—".to_string() } else { format!("{:.0}%", 100.0 * n as f64 / d as f64) }
        };
        println!(
            "{:<20} {:>9} {:>9} {:>5} {:>5} {:>5}",
            c,
            pct(t.tp, t.tp + t.fp),
            pct(t.tp, t.tp + t.fn_),
            t.tp,
            t.fp,
            t.fn_
        );
    }
    if !latencies.is_empty() {
        latencies.sort();
        let at = |q: f64| latencies[((latencies.len() - 1) as f64 * q).round() as usize].as_millis();
        println!(
            "decider: {} calls, {} failed, latency p50 {} ms, p95 {} ms, p99 {} ms",
            latencies.len(),
            failures,
            at(0.5),
            at(0.95),
            at(0.99)
        );
    }
    for m in &misses {
        eprintln!("{m}");
    }
    Ok(EXIT_OK)
}
