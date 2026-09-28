//! End-to-end tests of the `lockout` binary.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn lockout(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lockout"))
        .args(args)
        .current_dir(env!("CARGO_TARGET_TMPDIR"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr_json(o: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(o.stderr.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|_| panic!("not JSON: {l}")))
        .collect()
}

const BULLETIN: &str = "Lessons learned from October.\n\
A contractor was pinched at the conveyor tail pulley during cleaning.\n\
Always isolate and verify zero energy, including the take-up counterweight.\n";

#[test]
fn clean_text_passes_through_byte_identical() {
    let text = BULLETIN.repeat(30);
    let o = lockout(&["scan", "--jev", "off"], text.as_bytes());
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), text);
    assert!(o.stderr.is_empty());
}

#[test]
fn blocks_and_never_prints_the_identifier() {
    let text = format!("{BULLETIN}For questions contact dave.miller@acme-corp.com or +44 20 7946 0958.\n{BULLETIN}");
    let o = lockout(&["scan", "--jev", "off"], text.as_bytes());
    assert_eq!(o.status.code(), Some(3));
    let out = stdout(&o);
    assert!(text.starts_with(&out));
    assert!(!out.contains("dave") && !out.contains("7946"));
    let findings = stderr_json(&o);
    assert_eq!(findings[0]["category"], "contact");
    assert_eq!(findings[0]["action"], "block");
    assert_eq!(findings[0]["audience"], "site");
    assert!(!String::from_utf8_lossy(&o.stderr).contains("dave"));
}

#[test]
fn report_lists_every_finding_as_json_without_the_text() {
    let text = format!("{BULLETIN}Card 4556 7375 8689 9855.\n{BULLETIN}SSN 536-22-4181.\n");
    let o = lockout(&["scan", "--report", "--jev", "off"], text.as_bytes());
    assert_eq!(o.status.code(), Some(3));
    let out = stdout(&o);
    let lines: Vec<serde_json::Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let sources: Vec<&str> = lines.iter().map(|v| v["source"].as_str().unwrap()).collect();
    assert_eq!(sources, ["local:payment_card", "local:us_ssn"]);
    assert!(!out.contains("4556") && !out.contains("536-22"));
}

#[test]
fn audience_changes_the_outcome() {
    let text = "Call the site nurse on +44 20 7946 0958 after the drill.\n";
    let site = lockout(&["scan", "--jev", "off"], text.as_bytes());
    assert_eq!(site.status.code(), Some(3));
    let team = lockout(&["scan", "--jev", "off", "--audience", "investigation"], text.as_bytes());
    assert_eq!(team.status.code(), Some(0));
    assert_eq!(stdout(&team), text);
    assert_eq!(stderr_json(&team)[0]["action"], "warn");
}

#[test]
fn config_identifiers_allowlist_and_fail_on_warn() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("cfg");
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("lockout.toml");
    std::fs::write(&cfg, "[identifiers]\nemployee_id = 'E\\d{6}'\n[allow]\nemails = [\"safety@acme-corp.com\"]\n")
        .unwrap();
    let cfg = cfg.to_str().unwrap();
    let text = "Report hazards to safety@acme-corp.com. Badge E123456 badged in at 06:02.\n";

    let o = lockout(&["scan", "--jev", "off", "--config", cfg], text.as_bytes());
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(stdout(&o), text);
    assert_eq!(stderr_json(&o)[0]["category"], "employee_ref");

    let o = lockout(&["scan", "--jev", "off", "--config", cfg, "--fail-on-warn"], text.as_bytes());
    assert_eq!(o.status.code(), Some(3));
}

#[test]
fn test_command_prints_a_human_report() {
    let o = Command::new(env!("CARGO_BIN_EXE_lockout"))
        .args(["test", "--jev", "off", "Her NI number is AB 12 34 56 C."])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(3));
    let out = stdout(&o);
    assert!(out.starts_with("BLOCK  government_id"), "{out}");
    assert!(out.contains("not safe to distribute to audience \"site\""));
}

#[test]
fn failure_exit_codes() {
    assert_eq!(lockout(&["scan", "--jev", "off"], b"ok \xff").status.code(), Some(4));
    assert_eq!(lockout(&["scan", "--jev", "off", "--format", "sse-openai"], b"").status.code(), Some(2));
    assert_eq!(lockout(&["scan", "--jev", "off", "--config", "/nonexistent.toml"], b"").status.code(), Some(2));
    assert_eq!(lockout(&["scan", "--audience", "everyone"], b"").status.code(), Some(2));
}

#[test]
fn notice_when_jev_is_not_turned_off() {
    let o = lockout(&["scan"], b"hello\n");
    assert_eq!(o.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&o.stderr).contains("local rules only"));
}
