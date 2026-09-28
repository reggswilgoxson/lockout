//! lockout: lockout/tagout for AI output.

mod config;

use std::io::{self, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lockout_ai_core::{Action, Audience, Detectors, Event, Finding, Guard, Mode, Policy, Rules};
use serde::Serialize;

use config::Config;

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_BLOCKED: u8 = 3;
const EXIT_BAD_FRAME: u8 = 4;

#[derive(Parser)]
#[command(
    name = "lockout",
    version,
    about = "Lockout/tagout for AI output: blocks or flags worker health and incident data in LLM responses."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Filter a model's response from FILE or stdin to stdout, or report findings with --report.
    Scan(ScanArgs),
    /// Check one string and print the findings.
    Test {
        text: String,
        #[command(flatten)]
        common: CommonArgs,
    },
}

#[derive(Args)]
struct ScanArgs {
    /// Read from this file instead of stdin.
    file: Option<PathBuf>,
    /// Stream format of the input.
    #[arg(long, value_enum, default_value_t = Format::Raw)]
    format: Format,
    /// Print findings only, for the whole input; forward nothing.
    #[arg(long)]
    report: bool,
    /// Exit 3 on warnings as well as blocks.
    #[arg(long)]
    fail_on_warn: bool,
    #[command(flatten)]
    common: CommonArgs,
}

#[derive(Args)]
struct CommonArgs {
    /// Who will read the output: investigation, site or public. Default: site.
    #[arg(long)]
    audience: Option<Audience>,
    /// Config file. Default: ./lockout.toml if it exists.
    #[arg(long)]
    config: Option<PathBuf>,
    /// `off` runs local rules only, without the notice.
    #[arg(long, value_enum, default_value_t = Jev::Auto)]
    jev: Jev,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Format {
    Raw,
    SseOpenai,
    SseAnthropic,
    NdjsonOllama,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Jev {
    Auto,
    Off,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(args),
        Command::Test { text, common } => {
            test(&text, &common).map(|blocked| if blocked { EXIT_BLOCKED } else { EXIT_OK })
        }
    };
    ExitCode::from(result.unwrap_or_else(|(code, msg)| {
        eprintln!("lockout: {msg}");
        code
    }))
}

type Fail = (u8, String);

fn usage(msg: impl Into<String>) -> Fail {
    (EXIT_USAGE, msg.into())
}

fn build_guard(common: &CommonArgs, mode: Mode) -> Result<(Guard, Audience), Fail> {
    let config = Config::load(common.config.as_deref()).map_err(usage)?;
    let audience = common.audience.or(config.audience).unwrap_or_default();
    let detectors = Detectors::new(config.allow(), config.identifiers().map_err(usage)?);
    let policy = Policy::new(Rules::builtin(), audience, config.overrides.clone());
    let key = std::env::var("LOCKOUT_HMAC_KEY").ok().map(String::into_bytes);
    let guard = Guard::new(policy, detectors, config.segment(), mode, key).map_err(usage)?;
    if common.jev == Jev::Auto {
        eprintln!(
            "lockout: local rules only (identifiers). The EHS categories need Jev, which this build does not include yet. \
             Pass --jev off to hide this notice."
        );
    }
    Ok((guard, audience))
}

fn open_input(file: Option<&PathBuf>) -> Result<Box<dyn Read>, Fail> {
    match file {
        Some(p) => std::fs::File::open(p)
            .map(|f| Box::new(f) as Box<dyn Read>)
            .map_err(|e| usage(format!("{}: {e}", p.display()))),
        None => Ok(Box::new(io::stdin().lock())),
    }
}

fn scan(args: ScanArgs) -> Result<u8, Fail> {
    if args.format != Format::Raw {
        return Err(usage("only --format raw is supported so far; provider stream formats arrive in Phase 3"));
    }
    let mut input = open_input(args.file.as_ref())?;
    if args.report {
        let mut text = String::new();
        input.read_to_string(&mut text).map_err(|e| (EXIT_BAD_FRAME, format!("cannot read input: {e}")))?;
        let (mut guard, audience) = build_guard(&args.common, Mode::Report)?;
        let mut events = guard.push(&text);
        events.extend(guard.finish());
        let findings = collect_findings(events);
        let human = io::stdout().is_terminal();
        print_report(&text, &findings, audience, human);
        return Ok(exit_for(&findings, args.fail_on_warn));
    }
    filter(input, &args)
}

/// Streams stdin to stdout, releasing only checked text.
fn filter(mut input: Box<dyn Read>, args: &ScanArgs) -> Result<u8, Fail> {
    let (mut guard, audience) = build_guard(&args.common, Mode::Filter)?;
    let mut stdout = io::stdout().lock();
    let mut buf = vec![0u8; 8192];
    let mut pending: Vec<u8> = Vec::new();
    let mut warned = false;
    loop {
        let n = input.read(&mut buf).map_err(|e| (EXIT_INTERNAL, format!("read error: {e}")))?;
        let events = if n == 0 {
            if !pending.is_empty() {
                return Err((EXIT_BAD_FRAME, "input ends inside a UTF-8 character".into()));
            }
            guard.finish()
        } else {
            pending.extend_from_slice(&buf[..n]);
            let valid = match std::str::from_utf8(&pending) {
                Ok(s) => s.len(),
                Err(e) if e.error_len().is_none() => e.valid_up_to(),
                Err(_) => return Err((EXIT_BAD_FRAME, "input is not valid UTF-8".into())),
            };
            let text = std::str::from_utf8(&pending[..valid]).expect("validated").to_owned();
            pending.drain(..valid);
            guard.push(&text)
        };
        for event in events {
            match event {
                Event::Release(s) => {
                    if let Err(e) = stdout.write_all(s.as_bytes()).and_then(|_| stdout.flush()) {
                        return if e.kind() == io::ErrorKind::BrokenPipe {
                            Ok(EXIT_OK)
                        } else {
                            Err((EXIT_INTERNAL, format!("write error: {e}")))
                        };
                    }
                }
                Event::Warn(f) => {
                    warned = true;
                    eprintln!("{}", json_line(&f, audience));
                }
                Event::Block(fs) => {
                    for f in &fs {
                        eprintln!("{}", json_line(f, audience));
                    }
                    return Ok(EXIT_BLOCKED);
                }
            }
        }
        if n == 0 {
            return Ok(if warned && args.fail_on_warn { EXIT_BLOCKED } else { EXIT_OK });
        }
    }
}

fn test(text: &str, common: &CommonArgs) -> Result<bool, Fail> {
    let (mut guard, audience) = build_guard(common, Mode::Report)?;
    let mut events = guard.push(text);
    events.extend(guard.finish());
    let findings = collect_findings(events);
    print_report(text, &findings, audience, true);
    Ok(findings.iter().any(|f| f.action == Action::Block))
}

fn collect_findings(events: Vec<Event>) -> Vec<Finding> {
    let mut out: Vec<Finding> = events
        .into_iter()
        .flat_map(|e| match e {
            Event::Warn(f) => vec![f],
            Event::Block(fs) => fs,
            Event::Release(_) => vec![],
        })
        .collect();
    out.sort_by_key(|f| (f.start, f.end));
    out
}

fn exit_for(findings: &[Finding], fail_on_warn: bool) -> u8 {
    let blocks = findings.iter().any(|f| f.action == Action::Block);
    let warns = findings.iter().any(|f| f.action == Action::Warn);
    if blocks || (warns && fail_on_warn) { EXIT_BLOCKED } else { EXIT_OK }
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    audience: Audience,
    #[serde(flatten)]
    finding: &'a Finding,
}

fn json_line(f: &Finding, audience: Audience) -> String {
    serde_json::to_string(&JsonFinding { audience, finding: f }).expect("findings serialize")
}

fn print_report(text: &str, findings: &[Finding], audience: Audience, human: bool) {
    if !human {
        for f in findings {
            println!("{}", json_line(f, audience));
        }
        return;
    }
    for f in findings {
        let line = text[..f.start].matches('\n').count() + 1;
        let label = if f.action == Action::Block { "BLOCK" } else { "WARN " };
        println!("{label}  {:<16} line {:<4} {:<22} {}", f.category, line, f.source, f.citations.join(" · "));
    }
    let blocks = findings.iter().filter(|f| f.action == Action::Block).count();
    let warns = findings.len() - blocks;
    let plural = |n: usize, s: &str| format!("{n} {s}{}", if n == 1 { "" } else { "s" });
    let verdict = if blocks > 0 {
        format!("not safe to distribute to audience \"{audience}\"")
    } else if warns > 0 {
        format!("review before distributing to audience \"{audience}\"")
    } else {
        format!("nothing flagged for audience \"{audience}\" by local rules")
    };
    println!("{}, {} — {verdict}", plural(blocks, "blocking finding"), plural(warns, "warning"));
}
