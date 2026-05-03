use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

use std::time::Duration;

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().unwrap().port()
}

fn start_proxy(port: u16) -> Child {
    let bin = env!("CARGO_BIN_EXE_mirage-proxy");
    Command::new(bin)
        .args([
            "run",
            "--bind",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--no-update-check",
            "--log-level",
            "warn",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start mirage-proxy")
}

async fn wait_for_health(port: u16) {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/healthz", port);
    for _ in 0..30 {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("proxy did not become healthy on {}", url);
}

#[tokio::test]
async fn healthz_endpoint_works() {
    let port = free_port();
    let mut child = start_proxy(port);
    wait_for_health(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/healthz", port))
        .await
        .expect("healthz request");
    assert!(resp.status().is_success());

    let body = resp.text().await.expect("healthz body");
    assert!(body.contains("\"status\":\"ok\""));

    let _ = child.kill();
    let _ = child.wait();
}

#[tokio::test]
async fn unmatched_provider_path_returns_bad_gateway() {
    let port = free_port();
    let mut child = start_proxy(port);
    wait_for_health(port).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/not-a-provider/v1/chat/completions", port))
        .header("content-type", "application/json")
        .body("{\"model\":\"x\",\"messages\":[]}")
        .send()
        .await
        .expect("proxy request");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body = resp.text().await.expect("error body");
    assert!(body.contains("No provider matched"));

    let _ = child.kill();
    let _ = child.wait();
}
