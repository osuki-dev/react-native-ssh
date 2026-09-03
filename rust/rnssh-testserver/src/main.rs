use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    let port: u16 = std::env::var("RNSSH_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(2222);
    let (config, fingerprint) = rnssh_testserver::config();
    println!("host key fingerprint: {fingerprint}");
    println!(
        "listening on 0.0.0.0:{port}  (user test / password test; user key / any public key; user kbi / answer 'test'; user 2fa / password test then answer 'test')"
    );
    // HTTP on port+1, loopback only: reachable from an app solely through a
    // direct-tcpip forward, which is exactly what it is there to exercise.
    let http = TcpListener::bind(("127.0.0.1", port + 1))
        .await
        .expect("bind http");
    println!(
        "http test endpoint on 127.0.0.1:{} (reach it through a local forward)",
        port + 1
    );
    tokio::spawn(rnssh_testserver::serve_http(http));

    let listener = TcpListener::bind(("0.0.0.0", port)).await.expect("bind");
    rnssh_testserver::serve(listener, config)
        .await
        .expect("server");
}
