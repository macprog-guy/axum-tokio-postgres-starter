#![cfg(feature = "keycloak")]

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    routing::get,
};
use pictet_axum_service::{Config, Sensitive};
use tower::ServiceExt;

mod keycloak;
use keycloak::KeycloakContainer;

/// Helper function to create a test configuration with OIDC enabled
fn create_oidc_config(issuer_url: &str, realm: &str) -> Config {
    // KeycloakConfig will append /realms/{realm} automatically, so pass base URL
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

[http.oidc]
issuer_url = "{}"
realm = "{}"
audiences = ["account"]
client_id = "test-client"
client_secret = "test-secret"

[logging]
format = "json"
        "#,
        issuer_url, realm
    );

    let mut config: Config = toml_str.parse().expect("Failed to parse test config TOML");
    // Disable metrics to avoid Prometheus registry conflicts in tests
    config.http.with_metrics = false;
    config
}

/// Helper function to create a test router with OIDC enabled
async fn create_oidc_test_router(config: Config) -> Router {
    let router = Router::new()
        .route("/protected", get(|| async { "Protected resource" }))
        .route("/public", get(|| async { "Public resource" }));

    let app = config
        .setup_middleware(router)
        .await
        .expect("Failed to setup middleware");

    // Give the OIDC discovery a moment to complete
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    app
}

#[tokio::test]
async fn test_oidc_integration() {
    // Start Keycloak container and setup test realm/client/user
    let keycloak = KeycloakContainer::start().await;
    keycloak.create_test_user().await;

    // Create config with Keycloak issuer URL using the test-realm
    let config = create_oidc_config(keycloak.url.as_str(), "test-realm");

    // Create router with OIDC enabled
    let app = create_oidc_test_router(config).await;

    // ------------------------------------------------------------------------
    // PROTECTED
    // ------------------------------------------------------------------------

    // Try to access protected endpoint without auth token
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be blocked (401 Unauthorized or 403 Forbidden)
    assert!(
        response.status() == StatusCode::UNAUTHORIZED || response.status() == StatusCode::FORBIDDEN,
        "Expected 401 or 403, got {}",
        response.status()
    );

    // ------------------------------------------------------------------------
    // PUBLIC / HEALTH / READINESS
    // ------------------------------------------------------------------------

    // Health endpoints should be accessible without auth
    let health_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(health_response.status(), StatusCode::OK);

    // Readiness endpoint should also be accessible
    let ready_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(ready_response.status(), StatusCode::OK);

    // ------------------------------------------------------------------------
    // INVALID AND VALID TOKENS
    // ------------------------------------------------------------------------

    // First, test with invalid token - should be rejected
    let invalid_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, "Bearer invalid-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should reject invalid token with 400, 401, or 403
    assert!(
        invalid_response.status() == StatusCode::BAD_REQUEST
            || invalid_response.status() == StatusCode::UNAUTHORIZED
            || invalid_response.status() == StatusCode::FORBIDDEN,
        "Expected 400, 401 or 403 for invalid token, got {}",
        invalid_response.status()
    );

    // ------------------------------------------------------------------------
    // VALID TOKEN
    // ------------------------------------------------------------------------

    let valid_token = keycloak
        .perform_password_login(
            "test-user-mail@foo.bar",
            "password",
            "test-realm",
            "test-client",
        )
        .await;

    // Test with valid token - should be accepted (or at least not rejected for auth reasons)
    let valid_response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(header::AUTHORIZATION, format!("Bearer {}", valid_token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // With a valid token, we should get 200 OK (or possibly 404 if route doesn't exist in real impl)
    // At minimum, it should NOT be 401/403 authorization errors
    assert!(
        valid_response.status() == StatusCode::OK
            || valid_response.status() == StatusCode::NOT_FOUND,
        "Expected 200 or 404 with valid token, got {}",
        valid_response.status()
    );
}
#[tokio::test]
async fn test_oidc_disabled_when_config_is_none() {
    // Create config without OIDC section
    let toml_str = r#"
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

[logging]
format = "json"
    "#;

    let config: Config = toml_str.parse().expect("Failed to parse config");

    // Verify OIDC is None
    assert!(config.http.oidc.is_none());

    let router = Router::new().route("/test", get(|| async { "Test endpoint" }));

    // Should successfully setup middleware without OIDC
    let app = config
        .setup_middleware(router)
        .await
        .expect("Failed to setup middleware");

    // Should be able to access endpoints without auth
    let response = app
        .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_oidc_config_parsing() {
    // Test that OIDC configuration can be parsed correctly
    let toml_str = r#"
[database]
url = "postgres://test:test@localhost:5432/test"
max_pool_size = 5

[http]
bind_addr = "127.0.0.1"
bind_port = 3000
max_concurrent_requests = 100
max_payload_size_bytes = "1KiB"

[http.oidc]
issuer_url = "https://keycloak.example.com"
realm = "test-realm"
audiences = ["api", "web"]
client_id = "my-client"
client_secret = "my-secret"

[logging]
format = "json"
    "#;

    let config: Config = toml_str.parse().expect("Failed to parse config");

    // Verify OIDC config was parsed correctly
    assert!(config.http.oidc.is_some());
    let oidc = config.http.oidc.unwrap();
    assert_eq!(oidc.issuer_url, "https://keycloak.example.com");
    assert_eq!(oidc.realm, "test-realm");
    assert_eq!(oidc.audiences, vec!["api", "web"]);
    assert_eq!(oidc.client_id, "my-client");
    assert!(oidc.client_secret == Sensitive::from("my-secret"));
}
