#![cfg(unix)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use pathchord_control::{
    ErrorCode, GenerationExpectation, RequestEnvelope, ResponseEnvelope, read_object, write_object,
};
use serde_json::{Value, json};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "pc-ctl-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_pathchordctl"));
        command
            .current_dir(&self.0)
            .env("XDG_RUNTIME_DIR", &self.0)
            .env_remove("PATHCHORD_CONFIG")
            .env_remove("PATHCHORD_CONFIG_DIR");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manages_one_egress_service_without_a_running_daemon() {
    let fixture = Fixture::new();
    let config = fixture.0.join("config");
    std::fs::create_dir(&config).unwrap();
    std::fs::write(fixture.0.join("service.yml"), "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: exit}\nspec: {bind: '127.0.0.1:7443', web: {tokenFile: '../token'}}\n").unwrap();
    let run = |tail: &[&str]| {
        fixture
            .command()
            .args(["-C", "config", "config", "--role", "egress"])
            .args(tail)
            .output()
            .unwrap()
    };
    let output = run(&["create", "-f", "service.yml"]);
    success(&output);
    assert!(String::from_utf8_lossy(&output.stdout).contains("restart required"));
    let original = std::fs::read(config.join("managed.yaml")).unwrap();
    assert!(!run(&["create", "-f", "service.yml"]).status.success());
    assert!(!run(&["delete", "EgressService/exit"]).status.success());
    assert_eq!(
        std::fs::read(config.join("managed.yaml")).unwrap(),
        original
    );
    success(&run(&["validate"]));
    let paths = run(&["paths", "-o", "json"]);
    success(&paths);
    let paths: Value = serde_json::from_slice(&paths.stdout).unwrap();
    assert_eq!(paths["egress_id"], "exit");
    let view = run(&["view", "-o", "yaml"]);
    success(&view);
    assert!(String::from_utf8_lossy(&view.stdout).contains("[redacted]"));
    assert!(!run(&["view", "--reveal-secrets"]).status.success());
    assert!(
        !run(&["view", "--reveal-secrets", "-o", "json"])
            .status
            .success()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn shows_status_in_human_json_and_yaml_and_reports_typed_errors() {
    let fixture = Fixture::new();
    let runtime = fixture.0.join("pathchord");
    std::fs::create_dir(&runtime).unwrap();
    let listener = tokio::net::UnixListener::bind(runtime.join("ingress.sock")).unwrap();
    let server = tokio::spawn(async move {
        for index in 0..4 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request: RequestEnvelope = read_object(&mut stream).await.unwrap();
            let generation = GenerationExpectation {
                scope: "observation".into(),
                value: 5,
            };
            let response = if index == 3 {
                ResponseEnvelope::failure(
                    request.request_id,
                    generation,
                    pathchord_control::ErrorBody {
                        code: ErrorCode::CapabilityDenied,
                        message: "denied".into(),
                        details: None,
                    },
                )
            } else {
                ResponseEnvelope::success(
                    request.request_id,
                    generation,
                    json!({"configuration_generation": 3, "ingress": {"state": "running"}}),
                )
            };
            write_object(&mut stream, &response).await.unwrap();
        }
    });
    let output = tokio::task::spawn_blocking(move || {
        let human = fixture.run(&["get", "status"]);
        let json = fixture.run(&["status", "-o", "json"]);
        let yaml = fixture.run(&["describe", "status", "-o", "yaml"]);
        let failure = fixture.run(&["status", "-o", "json"]);
        (human, json, yaml, failure)
    })
    .await
    .unwrap();
    server.await.unwrap();
    success(&output.0);
    assert!(String::from_utf8_lossy(&output.0.stdout).contains("Role: Ingress"));
    assert!(serde_json::from_slice::<Value>(&output.0.stdout).is_err());
    success(&output.1);
    success(&output.2);
    let json: Value = serde_json::from_slice(&output.1.stdout).unwrap();
    let yaml: Value = serde_yaml::from_slice(&output.2.stdout).unwrap();
    assert_eq!(json["result"], yaml["result"]);
    assert!(!output.3.status.success());
    let failure: Value = serde_json::from_slice(&output.3.stdout).unwrap();
    assert_eq!(failure["error"]["code"], "CAPABILITY_DENIED");
}

#[tokio::test(flavor = "current_thread")]
async fn falls_back_before_mutation_but_never_resends_after_response_loss() {
    let fixture = Fixture::new();
    std::fs::create_dir(fixture.0.join("pathchord")).unwrap();
    let fallback = fixture.0.join("pathchord/egress.sock");
    std::fs::write(fixture.0.join("egress.yaml"),
        "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: exit}\nspec: {controlSocket: custom.sock}\n"
    ).unwrap();

    let listener = tokio::net::UnixListener::bind(&fallback).unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request: RequestEnvelope = read_object(&mut stream).await.unwrap();
        assert_eq!(request.operation, "status.get");
        write_object(
            &mut stream,
            &ResponseEnvelope::success(
                request.request_id,
                GenerationExpectation {
                    scope: "authorization".into(),
                    value: 4,
                },
                json!({"egress_id": "exit", "authorization_generation": 4}),
            ),
        )
        .await
        .unwrap();
        let (mut stream, _) = listener.accept().await.unwrap();
        let request: RequestEnvelope = read_object(&mut stream).await.unwrap();
        assert_eq!(request.operation, "authorizations.revoke");
        assert_eq!(request.expected_generation.unwrap().value, 4);
        drop(stream);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), listener.accept())
                .await
                .is_err()
        );
    });
    let output = tokio::task::spawn_blocking(move || {
        fixture.run(&[
            "-c",
            "egress.yaml",
            "enroll",
            "revoke",
            "--ingress-id",
            "entry",
            "--yes",
        ])
    })
    .await
    .unwrap();
    server.await.unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("mutation outcome is uncertain"));
}

#[test]
fn rejects_single_file_edits_and_invalid_output_and_reports_missing_socket() {
    let fixture = Fixture::new();
    std::fs::write(
        fixture.0.join("config.yaml"),
        "apiVersion: pathchord.io/v1\nkind: EgressService\nmetadata: {name: exit}\nspec: {}\n",
    )
    .unwrap();
    let single = fixture.run(&[
        "-c",
        "config.yaml",
        "config",
        "--role",
        "egress",
        "delete",
        "EgressService/exit",
    ]);
    assert!(!single.status.success());
    assert!(String::from_utf8_lossy(&single.stderr).contains("require a configuration directory"));
    let invalid = fixture.run(&["-o", "xml", "status"]);
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("invalid value"));
    let absent = fixture.run(&["-c", "config.yaml", "enroll", "list"]);
    assert!(!absent.status.success());
    assert!(
        String::from_utf8_lossy(&absent.stderr)
            .contains("could not discover a local egress endpoint")
    );
}
