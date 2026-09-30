//! Runs a [`Guard`] over an input stream: reads text, sends segments to the
//! decider (at most `max_inflight` at a time), feeds verdicts back, and hands
//! every event to the caller in order. Stops reading while too much text is
//! waiting for verdicts (back-pressure).

use std::sync::Arc;
use std::time::{Duration, Instant};

use lockout_ai_core::guard::{SegmentId, Verdict};
use lockout_ai_core::{Event, Finding, Guard};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::{Semaphore, mpsc};

use crate::jev::Decider;
use crate::{EXIT_BAD_FRAME, EXIT_INTERNAL, Fail};

#[derive(Clone, Copy, Debug)]
pub struct DriveOptions {
    pub max_inflight: usize,
    pub max_buffer: usize,
    pub timeout: Duration,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub findings: Vec<Finding>,
    pub blocked: bool,
    pub warned: bool,
    /// A decider failure stopped (or, in report mode, would have stopped) the stream.
    pub unavailable: bool,
    pub decider_calls: usize,
    pub decider_failures: usize,
    pub latencies: Vec<Duration>,
}

type Answer = (SegmentId, Result<Verdict, String>, Duration);

pub async fn drive<D, R, F>(
    mut guard: Guard,
    decider: Option<Arc<D>>,
    mut input: R,
    opts: DriveOptions,
    mut on_event: F,
) -> Result<Summary, Fail>
where
    D: Decider,
    R: AsyncRead + Unpin,
    F: FnMut(&Event) -> Result<(), Fail>,
{
    let (tx, mut rx) = mpsc::unbounded_channel::<Answer>();
    let permits = Arc::new(Semaphore::new(opts.max_inflight.max(1)));
    let mut summary = Summary::default();
    let mut inflight = 0usize;
    let mut eof = false;
    let mut buf = vec![0u8; 8192];
    let mut partial: Vec<u8> = Vec::new();
    let mut reported_failure = false;

    loop {
        let done = eof && inflight == 0;
        if guard.is_blocked() || done {
            break;
        }
        let can_read = !eof && guard.held_bytes() < opts.max_buffer;
        let events = tokio::select! {
            r = input.read(&mut buf), if can_read => {
                let n = r.map_err(|e| (EXIT_INTERNAL, format!("read error: {e}")))?;
                if n == 0 {
                    eof = true;
                    if !partial.is_empty() {
                        return Err((EXIT_BAD_FRAME, "input ends inside a UTF-8 character".into()));
                    }
                    guard.finish()
                } else {
                    partial.extend_from_slice(&buf[..n]);
                    let valid = match std::str::from_utf8(&partial) {
                        Ok(s) => s.len(),
                        Err(e) if e.error_len().is_none() => e.valid_up_to(),
                        Err(_) => return Err((EXIT_BAD_FRAME, "input is not valid UTF-8".into())),
                    };
                    let text = String::from_utf8(partial.drain(..valid).collect()).expect("validated");
                    guard.push(&text)
                }
            }
            Some((id, result, took)) = rx.recv(), if inflight > 0 => {
                inflight -= 1;
                summary.latencies.push(took);
                match result {
                    Ok(verdict) => guard.verdict(id, verdict),
                    Err(e) => {
                        summary.decider_failures += 1;
                        if !reported_failure {
                            eprintln!("lockout: Jev did not answer: {e}");
                            reported_failure = true;
                        }
                        guard.decider_failed(id)
                    }
                }
            }
            else => return Err((EXIT_INTERNAL, "stream stalled with no request in flight".into())),
        };

        for event in events {
            match &event {
                Event::SegmentReady(id, input) => {
                    let Some(decider) = decider.clone() else {
                        return Err((EXIT_INTERNAL, "guard asked for a verdict without a decider".into()));
                    };
                    let (tx, permits, id, input, timeout) =
                        (tx.clone(), permits.clone(), *id, input.clone(), opts.timeout);
                    inflight += 1;
                    summary.decider_calls += 1;
                    tokio::spawn(async move {
                        let _permit = permits.acquire_owned().await.expect("semaphore is never closed");
                        let start = Instant::now();
                        let result = tokio::time::timeout(timeout, decider.decide(input))
                            .await
                            .unwrap_or_else(|_| Err(format!("no answer within {} ms", timeout.as_millis())));
                        let _ = tx.send((id, result, start.elapsed()));
                    });
                    continue;
                }
                Event::Warn(f) => {
                    summary.warned = true;
                    summary.findings.push(f.clone());
                }
                Event::Block(fs) => {
                    summary.blocked = true;
                    summary.findings.extend(fs.iter().cloned());
                }
                Event::DeciderFailed { fatal } => summary.unavailable |= *fatal,
                Event::Release(_) => {}
            }
            on_event(&event)?;
        }
    }
    summary.findings.sort_by_key(|f| (f.start, f.end));
    Ok(summary)
}
