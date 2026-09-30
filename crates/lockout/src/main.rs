//! lockout: lockout/tagout for AI output.

mod config;
mod drive;
mod eval;
mod jev;

use std::io::{self, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use lockout_ai_core::{Action, Audience, Detectors, Event, Finding, Guard, Mode, Policy};
use serde::Serialize;
use tokio::io::AsyncRead;

use config::{Config, JevSettings};
use drive::{DriveOptions, Summary, drive};
use jev::{Breaker, Jev as JevClient};

const EXIT_OK: u8 = 0;
const EXIT_INTERNAL: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_BLOCKED: u8 = 3;
const EXIT_BAD_FRAME: u8 = 4;
const EXIT_UNAVAILABLE: u8 = 5;

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
    /// Score the current rules and questions against a labelled case file.
    Eval(eval::EvalArgs),
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

#[derive(Args, Clone)]
pub struct CommonArgs {
    /// Who will read the output: investigation, site or public. Default: site.
    #[arg(long)]
    audience: Option<Audience>,
    /// Config file. Default: ./lockout.toml if it exists.
    #[arg(long)]
    config: Option<PathBuf>,
    /// auto: use Jev when JEV_API_KEY is set. on: require it. off: local rules only.
    #[arg(long, value_enum, default_value_t = JevMode::Auto)]
    jev: JevMode,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
enum Format {
    Raw,
    SseOpenai,
    SseAnthropic,
    NdjsonOllama,
}

#[derive(Clone, Copy, PartialEq, ValueEnum)]
pub enum JevMode {
    Auto,
    On,
    Off,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => scan(args).await,
        Command::Test { text, common } => test(&text, &common).await,
        Command::Eval(args) => eval::run(args).await,
    };
    ExitCode::from(result.unwrap_or_else(|(code, msg)| {
        if !msg.is_empty() {
            eprintln!("lockout: {msg}");
        }
        code
    }))
}

pub type Fail = (u8, String);

fn usage(msg: impl Into<String>) -> Fail {
    (EXIT_USAGE, msg.into())
}

/// Everything needed to run one stream.
pub struct Setup {
    pub guard: Guard,
    pub audience: Audience,
    pub jev: Option<JevSettings>,
    pub opts: DriveOptions,
}

pub fn setup(common: &CommonArgs, mode: Mode, quiet: bool) -> Result<Setup, Fail> {
    let config = Config::load(common.config.as_deref()).map_err(usage)?;
    let audience = common.audience.or(config.audience).unwrap_or_default();
    let detectors = Detectors::new(config.allow(), config.identifiers().map_err(usage)?);
    let policy = Policy::new(config.rules().map_err(usage)?, audience, config.overrides.clone());
    let key = std::env::var("LOCKOUT_HMAC_KEY").ok().map(String::into_bytes);
    let mut guard = Guard::new(policy, detectors, config.segment(), mode, key).map_err(usage)?;

    let jev = match common.jev {
        JevMode::Off => None,
        JevMode::Auto | JevMode::On => config.jev.settings().map_err(usage)?,
    };
    match (&jev, common.jev) {
        (None, JevMode::On) => {
            return Err(usage(format!("--jev on needs {} and {}", config.jev.api_key_env, config.jev.url_env)));
        }
        (None, JevMode::Auto) if !quiet => eprintln!(
            "lockout: local rules only (identifiers). Set {} and {} to check the EHS categories with Jev, \
             or pass --jev off to hide this notice.",
            config.jev.api_key_env, config.jev.url_env
        ),
        (Some(_), _) => guard = guard.with_decider(config.jev.on_error),
        _ => {}
    }
    let opts = DriveOptions {
        max_inflight: config.jev.max_inflight,
        max_buffer: config.jev.max_buffer,
        timeout: Duration::from_millis(config.jev.timeout_ms),
    };
    Ok(Setup { guard, audience, jev, opts })
}

/// The live decider: Jev behind a circuit breaker.
pub fn live_decider(settings: &JevSettings) -> Result<Arc<Breaker<JevClient>>, Fail> {
    let client = JevClient::new(settings.clone()).map_err(|e| (EXIT_INTERNAL, e))?;
    Ok(Arc::new(Breaker::new(client, 3, Duration::from_secs(30))))
}

async fn run<R, F>(s: Setup, input: R, on_event: F) -> Result<Summary, Fail>
where
    R: AsyncRead + Unpin,
    F: FnMut(&Event) -> Result<(), Fail>,
{
    match &s.jev {
        Some(settings) => drive(s.guard, Some(live_decider(settings)?), input, s.opts, on_event).await,
        None => drive::<jev::Replay, _, _>(s.guard, None, input, s.opts, on_event).await,
    }
}

async fn open_input(file: Option<&PathBuf>) -> Result<Box<dyn AsyncRead + Unpin + Send>, Fail> {
    match file {
        Some(p) => tokio::fs::File::open(p)
            .await
            .map(|f| Box::new(f) as Box<dyn AsyncRead + Unpin + Send>)
            .map_err(|e| usage(format!("{}: {e}", p.display()))),
        None => Ok(Box::new(tokio::io::stdin())),
    }
}

async fn scan(args: ScanArgs) -> Result<u8, Fail> {
    if args.format != Format::Raw {
        return Err(usage("only --format raw is supported so far; provider stream formats arrive in Phase 3"));
    }
    let input = open_input(args.file.as_ref()).await?;
    if args.report {
        let mut text = Vec::new();
        let mut input = input;
        tokio::io::AsyncReadExt::read_to_end(&mut input, &mut text)
            .await
            .map_err(|e| (EXIT_INTERNAL, format!("cannot read input: {e}")))?;
        let text = String::from_utf8(text).map_err(|_| (EXIT_BAD_FRAME, "input is not valid UTF-8".to_string()))?;
        return report(&text, &args.common, io::stdout().is_terminal(), args.fail_on_warn).await;
    }

    let s = setup(&args.common, Mode::Filter, false)?;
    let audience = s.audience;
    let mut stdout = io::stdout().lock();
    let summary = run(s, input, |event| {
        match event {
            Event::Release(text) => {
                if let Err(e) = stdout.write_all(text.as_bytes()).and_then(|_| stdout.flush()) {
                    // A closed pipe (`| head`) ends quietly; anything else is an error.
                    let code = if e.kind() == io::ErrorKind::BrokenPipe { EXIT_OK } else { EXIT_INTERNAL };
                    let msg = if code == EXIT_OK { String::new() } else { format!("write error: {e}") };
                    return Err((code, msg));
                }
            }
            Event::Warn(f) => eprintln!("{}", json_line(f, audience)),
            Event::Block(fs) => fs.iter().for_each(|f| eprintln!("{}", json_line(f, audience))),
            _ => {}
        }
        Ok(())
    })
    .await?;
    Ok(exit_for(&summary, args.fail_on_warn))
}

async fn test(text: &str, common: &CommonArgs) -> Result<u8, Fail> {
    report(text, common, true, false).await
}

async fn report(text: &str, common: &CommonArgs, human: bool, fail_on_warn: bool) -> Result<u8, Fail> {
    let s = setup(common, Mode::Report, false)?;
    let audience = s.audience;
    let jev_used = s.jev.is_some();
    let summary = run(s, text.as_bytes(), |_| Ok(())).await?;
    print_report(text, &summary.findings, audience, human, jev_used);
    Ok(exit_for(&summary, fail_on_warn))
}

fn exit_for(summary: &Summary, fail_on_warn: bool) -> u8 {
    if summary.blocked || (summary.warned && fail_on_warn) {
        EXIT_BLOCKED
    } else if summary.unavailable {
        EXIT_UNAVAILABLE
    } else {
        EXIT_OK
    }
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

fn print_report(text: &str, findings: &[Finding], audience: Audience, human: bool, jev_used: bool) {
    if !human {
        for f in findings {
            println!("{}", json_line(f, audience));
        }
        return;
    }
    for f in findings {
        let line = text[..f.start.min(text.len())].matches('\n').count() + 1;
        let label = if f.action == Action::Block { "BLOCK" } else { "WARN " };
        let source = match f.probability {
            Some(p) => format!("{} p={p:.2}", f.source),
            None => f.source.clone(),
        };
        println!("{label}  {:<19} line {:<4} {:<22} {}", f.category, line, source, f.citations.join(" · "));
    }
    let blocks = findings.iter().filter(|f| f.action == Action::Block).count();
    let warns = findings.len() - blocks;
    let plural = |n: usize, s: &str| format!("{n} {s}{}", if n == 1 { "" } else { "s" });
    let verdict = if blocks > 0 {
        format!("not safe to distribute to audience \"{audience}\"")
    } else if warns > 0 {
        format!("review before distributing to audience \"{audience}\"")
    } else if jev_used {
        format!("nothing flagged for audience \"{audience}\"")
    } else {
        format!("nothing flagged for audience \"{audience}\" by local rules")
    };
    println!("{}, {} — {verdict}", plural(blocks, "blocking finding"), plural(warns, "warning"));
}
