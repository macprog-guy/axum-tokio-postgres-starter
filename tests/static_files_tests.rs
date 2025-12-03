use axum::{Router, body::Body, http::Request, routing::get};
use pictet_axum_service::Config;
use tower::ServiceExt;

/// Helper function to create a base configuration with static files
fn create_config_with_static_dirs(toml_dirs: &str) -> Config {
    let toml_str = format!(
        r#"
[database]
url = "postgres://test:test@localhost:5432/test"
max_pool_size = 5

[http]
bind_addr = "127.0.0.1"
bind_port = 3000
max_concurrent_requests = 100
max_payload_size_bytes = "1KiB"
support_compression = false
trim_trailing_slash = true
liveness_route = "/health"
readiness_route = "/ready"
metrics_route = "/metrics"

{toml_dirs}

[logging]
format = "json"
        "#
    );

    toml_str.parse().expect("Failed to parse test config TOML")
}

/// Helper function to setup a test router with configuration
async fn create_test_router_with_config(config: Config) -> Router {
    let mut config = config;
    config.http.with_metrics = false;

    let router = config.router();
    let router = router.route("/test", get(|| async { "test response" }));

    config
        .setup_middleware(router)
        .await
        .expect("Failed to setup middleware")
}

#[tokio::test]
async fn test_static_files_served_at_route() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test accessing index.html
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Test Static File"));

    // Test accessing test.txt
    let response = app
        .oneshot(
            Request::builder()
                .uri("/static/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("This is a test file for static file serving."));
}

#[tokio::test]
async fn test_static_directory_with_index_html_auto_serving() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test accessing directory with trailing slash - should serve index.html
    let response = app
        .oneshot(
            Request::builder()
                .uri("/static/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Test Static File"));
}

#[tokio::test]
async fn test_multiple_static_directories() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/assets"

[[http.directories]]
directory = "tests/test_fallback_files"
route = "/public"
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test first directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/assets/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Test Static File"));

    // Test second directory
    let response = app
        .oneshot(
            Request::builder()
                .uri("/public/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Fallback Static File"));
}

#[tokio::test]
async fn test_fallback_static_directory() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_fallback_files"
fallback = true
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test accessing root - should serve index.html from fallback directory
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Fallback Static File"));

    // Test accessing index.html directly through fallback
    let response = app
        .oneshot(
            Request::builder()
                .uri("/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Fallback Static File"));
}

#[tokio::test]
async fn test_mixed_route_and_fallback_static_directories() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"

[[http.directories]]
directory = "tests/test_fallback_files"
fallback = true
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test route-specific directory
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("This is a test file for static file serving."));

    // Test fallback directory
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(body_str.contains("Fallback Static File"));

    // Test that application routes still work
    let response = app
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(&body[..], b"test response");
}

#[tokio::test]
async fn test_static_directory_404_for_non_existent_file() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test accessing a non-existent file
    let response = app
        .oneshot(
            Request::builder()
                .uri("/static/non-existent.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_static_directory_config_parsing() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"

[[http.directories]]
directory = "tests/test_fallback_files"
fallback = true
    "#;

    let config = create_config_with_static_dirs(toml_dirs);

    // Verify configuration was parsed correctly
    assert_eq!(config.http.directories.len(), 2);

    // First directory should be a route
    assert_eq!(
        config.http.directories[0].directory,
        "tests/test_static_files"
    );
    assert!(!config.http.directories[0].is_fallback());
    if let pictet_axum_service::StaticDirRoute::Route(route) = &config.http.directories[0].route {
        assert_eq!(route, "/static");
    } else {
        panic!("Expected Route variant");
    }

    // Second directory should be a fallback
    assert_eq!(
        config.http.directories[1].directory,
        "tests/test_fallback_files"
    );
    assert!(config.http.directories[1].is_fallback());
}

#[tokio::test]
async fn test_no_static_directories_configured() {
    let toml_dirs = ""; // No directories configured

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test that application routes still work
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), 200);

    // Test that non-existent routes return 404
    let response = app
        .oneshot(
            Request::builder()
                .uri("/non-existent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_static_files_respect_content_type() {
    let toml_dirs = r#"
[[http.directories]]
directory = "tests/test_static_files"
route = "/static"
    "#;

    let config = create_config_with_static_dirs(toml_dirs);
    let app = create_test_router_with_config(config).await;

    // Test HTML file content-type
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/index.html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(content_type.to_str().unwrap().contains("text/html"));

    // Test text file content-type
    let response = app
        .oneshot(
            Request::builder()
                .uri("/static/test.txt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("Content-Type header should be present");
    assert!(content_type.to_str().unwrap().contains("text/plain"));
}
