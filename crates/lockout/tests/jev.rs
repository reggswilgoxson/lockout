//! The Jev path end to end: the real binary against a mock Jev server.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// Answers each question from the text: phrases in `hits` score high for their category.
struct FakeJev {
    hits: Vec<(&'static str, &'static str, f64)>,
    /// Segments containing this word are answered slowly.
    slow_word: Option<(&'static str, Duration)>,
}

impl Respond for FakeJev {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        let state = body["state"].as_str().unwrap();
        let mut answers = serde_json::Map::new();
        for (category, _) in body["questions"].as_object().unwrap() {
            let p = self
                .hits
                .iter()
                .filter(|(phrase, c, _)| c == category && state.contains(phrase))
                .map(|(_, _, p)| *p)
                .fold(0.02, f64::max);
            answers.insert(category.clone(), json!({ "probability": p }));
        }
        let mut response = ResponseTemplate::new(200).set_body_json(json!({ "answers": answers }));
        if let Some((word, delay)) = self.slow_word {
            if state.contains(word) {
                response = response.set_delay(delay);
            }
        }
        response
    }
}

fn fake(hits: Vec<(&'static str, &'static str, f64)>) -> FakeJev {
    FakeJev { hits, slow_word: None }
}

/// A fresh directory holding `lockout.toml` (and optionally `audience.toml`).
fn workdir(name: &str, config: &str, audience: Option<&str>) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("jev-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lockout.toml"), config).unwrap();
    if let Some(a) = audience {
        std::fs::write(dir.join("audience.toml"), a).unwrap();
    }
    dir
}

async fn lockout(dir: PathBuf, url: Option<String>, args: &[&str], stdin: String) -> Output {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_lockout"));
        cmd.args(&args)
            .current_dir(&dir)
            .env_remove("JEV_API_KEY")
            .env_remove("JEV_URL")
            .env("JEV_API_KEY", "test-key")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match url {
            Some(u) => cmd.env("JEV_URL", u),
            None => cmd.env_remove("JEV_URL"),
        };
        let mut child = cmd.spawn().unwrap();
        use std::io::Write;
        child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8(o.stderr.clone()).unwrap()
}

fn findings(o: &Output) -> Vec<Value> {
    stderr(o).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
}

const SAFE: &str = "Lessons learned: isolate and verify zero energy before cleaning the conveyor.\n";
const NEEDLESTICK: &str = "Maria on the night shift had a needlestick injury in the lab on Tuesday.\n";

async fn server(responder: FakeJev) -> MockServer {
    let s = MockServer::start().await;
    Mock::given(method("POST")).and(header("authorization", "Bearer test-key")).respond_with(responder).mount(&s).await;
    s
}

#[tokio::test(flavor = "multi_thread")]
async fn blocks_an_ehs_finding_and_releases_nothing_after_it() {
    let s = server(fake(vec![("needlestick", "privacy_case", 0.96)])).await;
    let dir = workdir("block", "", None);
    let text = format!("{}{NEEDLESTICK}{}", SAFE.repeat(6), SAFE.repeat(6));
    let o = lockout(dir, Some(s.uri()), &["scan"], text.clone()).await;
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(text.starts_with(&out) && !out.contains("needlestick"));
    let f = findings(&o);
    assert_eq!(f[0]["category"], "privacy_case");
    assert_eq!(f[0]["source"], "jev");
    assert_eq!(f[0]["probability"].as_f64().map(|p| (p * 100.0).round()), Some(96.0));
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_text_passes_through_in_order_even_when_answers_arrive_out_of_order() {
    let responder = FakeJev { hits: vec![], slow_word: Some(("FIRST", Duration::from_millis(400))) };
    let s = server(responder).await;
    let dir = workdir("order", "", None);
    let text = format!("FIRST paragraph of the bulletin.\n{}", SAFE.repeat(20));
    let o = lockout(dir, Some(s.uri()), &["scan"], text.clone()).await;
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), text);
    assert!(s.received_requests().await.unwrap().len() >= 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_timeout_fails_closed_by_default() {
    let responder = FakeJev { hits: vec![], slow_word: Some(("", Duration::from_secs(3))) };
    let s = server(responder).await;
    let dir = workdir("timeout", "[jev]\ntimeout_ms = 200\n", None);
    let o = lockout(dir, Some(s.uri()), &["scan"], SAFE.repeat(4)).await;
    assert_eq!(o.status.code(), Some(5), "{}", stderr(&o));
    assert_eq!(stdout(&o), "");
    assert!(stderr(&o).contains("no answer within 200 ms"));
}

#[tokio::test(flavor = "multi_thread")]
async fn local_only_releases_on_local_rules_when_jev_is_down() {
    let responder = FakeJev { hits: vec![], slow_word: Some(("", Duration::from_secs(3))) };
    let s = server(responder).await;
    let dir = workdir("local-only", "[jev]\ntimeout_ms = 200\non_error = \"local-only\"\n", None);
    let text = SAFE.repeat(4);
    let o = lockout(dir, Some(s.uri()), &["scan"], text.clone()).await;
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), text);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_breaker_stops_calling_a_failing_service() {
    let s = MockServer::start().await;
    Mock::given(method("POST")).respond_with(ResponseTemplate::new(503)).mount(&s).await;
    let dir = workdir("breaker", "[jev]\non_error = \"local-only\"\nmax_inflight = 1\n", None);
    let text = SAFE.repeat(40);
    let o = lockout(dir, Some(s.uri()), &["scan"], text.clone()).await;
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), text);
    assert_eq!(s.received_requests().await.unwrap().len(), 3);
    assert!(stderr(&o).contains("HTTP 503"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_key_without_an_endpoint_refuses_to_start() {
    let dir = workdir("no-url", "", None);
    let o = lockout(dir, None, &["scan"], SAFE.into()).await;
    assert_eq!(o.status.code(), Some(2));
    assert!(stderr(&o).contains("JEV_URL"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_audience_table_turns_a_block_into_a_warning() {
    let s = server(fake(vec![("needlestick", "privacy_case", 0.96)])).await;
    let dir = workdir("table", "", Some("[privacy_case]\nsite = \"warn\"\n"));
    let o = lockout(dir, Some(s.uri()), &["scan"], NEEDLESTICK.into()).await;
    assert_eq!(o.status.code(), Some(0), "{}", stderr(&o));
    assert_eq!(stdout(&o), NEEDLESTICK);
    assert_eq!(findings(&o)[0]["action"], "warn");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_command_shows_jev_findings() {
    let s = server(fake(vec![("needlestick", "privacy_case", 0.96), ("Maria", "person_identity", 0.9)])).await;
    let dir = workdir("test-cmd", "", None);
    let o = lockout(dir, Some(s.uri()), &["test", NEEDLESTICK.trim()], String::new()).await;
    assert_eq!(o.status.code(), Some(3), "{}", stderr(&o));
    let out = stdout(&o);
    assert!(out.contains("BLOCK  privacy_case") && out.contains("jev p=0.96"), "{out}");
    assert!(out.contains("WARN   person_identity"), "{out}");
}

#[tokio::test(flavor = "multi_thread")]
async fn eval_records_then_replays_without_jev() {
    let s = server(fake(vec![("needlestick", "privacy_case", 0.96), ("Maria", "person_identity", 0.9)])).await;
    let dir = workdir("eval", "", None);
    let cases = [
        json!({"id": "pos-1", "text": NEEDLESTICK.trim(), "labels": ["privacy_case", "person_identity"]}),
        json!({"id": "neg-1", "text": SAFE.trim(), "labels": []}),
    ];
    std::fs::write(dir.join("cases.jsonl"), cases.map(|c| c.to_string()).join("\n")).unwrap();

    let live = lockout(
        dir.clone(),
        Some(s.uri()),
        &["eval", "--cases", "cases.jsonl", "--record", "rec.jsonl"],
        String::new(),
    )
    .await;
    assert_eq!(live.status.code(), Some(0), "{}", stderr(&live));
    let table = |o: &Output| {
        stdout(o)
            .lines()
            .filter(|l| l.starts_with("privacy_case") || l.starts_with("person_identity"))
            .map(String::from)
            .collect::<Vec<_>>()
    };
    assert!(table(&live)[0].contains("100%"), "{}", stdout(&live));

    // Replay needs neither the server nor the key's endpoint.
    let calls = s.received_requests().await.unwrap().len();
    let replay = lockout(dir, None, &["eval", "--cases", "cases.jsonl", "--replay", "rec.jsonl"], String::new()).await;
    assert_eq!(replay.status.code(), Some(0), "{}", stderr(&replay));
    assert_eq!(table(&replay), table(&live));
    assert_eq!(s.received_requests().await.unwrap().len(), calls);
}
