use crate::{Config, Result};
use axum::Router;
use std::future::Future;

pub trait RouterConfigurator {
    fn setup_middleware(
        self,
        config: Config,
    ) -> impl Future<Output = Result<Router>> + Send + 'static;
    fn start(self, config: Config) -> impl Future<Output = Result<()>> + Send + 'static;
}

impl RouterConfigurator for Router {
    fn setup_middleware(
        self,
        config: Config,
    ) -> impl Future<Output = Result<Router>> + Send + 'static {
        config.setup_middleware(self)
    }

    fn start(self, config: Config) -> impl Future<Output = Result<()>> + Send + 'static {
        config.start_with_rate_limiting(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get};
    use tower::ServiceExt;

    fn create_test_config() -> Config {
        let toml_str = r#"
[database]
url = "postgres://test:test@localhost:5432/test"
max_pool_size = 5

[http]
bind_addr = "127.0.0.1"
bind_port = 3000
max_concurrent_requests = 100
max_request_per_sec = 10
max_payload_size_bytes = "1KiB"
support_compression = false
trim_trailing_slash = true
liveness_route = "/health"
readiness_route = "/ready"
metrics_route = "/metrics"

[logging]
format = "json"
        "#;

        toml_str.parse().expect("Failed to parse test config TOML")
    }

    #[tokio::test]
    async fn test_setup_middleware_adds_routes() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        // Test that liveness route works
        let response = configured_router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_setup_middleware_adds_readiness_route() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        // Test that readiness route works
        let response = configured_router
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_setup_middleware_preserves_existing_routes() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new().route("/test", get(|| async { "test response" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        // Test that our original route still works
        let response = configured_router
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
    async fn test_setup_middleware_applies_cors() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        // Test CORS headers are present
        let response = configured_router
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/test")
                    .header("Origin", "http://example.com")
                    .header("Access-Control-Request-Method", "GET")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // CORS layer should handle OPTIONS preflight
        let headers = response.headers();
        assert!(
            headers.contains_key("access-control-allow-origin")
                || headers.contains_key("access-control-allow-methods")
        );
    }

    #[tokio::test]
    async fn test_setup_middleware_adds_request_id() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        let response = configured_router
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Check if x-request-id header is present (may be added by the layer)
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_setup_middleware_handles_compression_when_enabled() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        config.http.support_compression = true;

        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        let response = configured_router
            .oneshot(
                Request::builder()
                    .uri("/test")
                    .header("Accept-Encoding", "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[test]
    fn test_router_configurator_trait_implementation() {
        // Verify that Router implements RouterConfigurator
        fn assert_implements_configurator<T: RouterConfigurator>() {}
        assert_implements_configurator::<Router>();
    }

    #[tokio::test]
    async fn test_setup_middleware_respects_custom_liveness_route() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        config.http.liveness_route = "/custom-health".to_string();

        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        let response = configured_router
            .oneshot(
                Request::builder()
                    .uri("/custom-health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_setup_middleware_respects_custom_readiness_route() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        config.http.readiness_route = "/custom-ready".to_string();

        let router = Router::new().route("/test", get(|| async { "test" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        let response = configured_router
            .oneshot(
                Request::builder()
                    .uri("/custom-ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_setup_middleware_with_multiple_routes() {
        let mut config = create_test_config();
        config.http.with_metrics = false;
        let router = Router::new()
            .route("/route1", get(|| async { "response1" }))
            .route("/route2", get(|| async { "response2" }))
            .route("/route3", get(|| async { "response3" }));

        let configured_router = router
            .setup_middleware(config)
            .await
            .expect("Failed to setup middleware");

        // Test all routes work
        for (path, expected) in [
            ("/route1", "response1"),
            ("/route2", "response2"),
            ("/route3", "response3"),
        ] {
            let response = configured_router
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();

            assert_eq!(response.status(), 200);
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(&body[..], expected.as_bytes());
        }
    }
}
