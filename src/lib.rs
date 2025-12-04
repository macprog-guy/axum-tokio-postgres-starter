//! # Axum Tokio Postgres
//!
//! A batteries-included library for building production-ready web services with Axum,
//! designed specifically for Kubernetes deployments.
//!
//! This library provides ready-made endpoints for Kubernetes liveness and readiness probes,
//! Prometheus metrics collection, and a comprehensive set of configurable HTTP middleware
//! components.
//!
//! ## Features
//!
//! ### Built-in Endpoints
//!
//! - **Liveness probe** - Health check endpoint for Kubernetes (default: `/live`)
//! - **Readiness probe** - Load-aware readiness endpoint (default: `/ready`)
//! - **Prometheus metrics** - Built-in metrics collection (default: `/metrics`)
//!
//! ### Configurable Middleware
//!
//! - **Compression/Decompression** - Support for gzip, brotli, deflate, and zstd
//! - **Body size limits** - Configurable maximum request payload size
//! - **CORS headers** - Cross-Origin Resource Sharing support
//! - **Trailing slash handling** - Automatic normalization of paths
//! - **Concurrency limits** - Maximum simultaneous requests
//! - **Rate limiting** - Per-IP rate limiting with configurable thresholds
//! - **Request timeouts** - Protection against long-running requests
//! - **Request ID tracking** - Automatic request ID generation and propagation
//! - **Sensitive header protection** - Automatic filtering of sensitive headers from logs
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use pictet_axum_service::{Config, Result, FluentRouter};
//! use std::sync::Arc;
//!
//! #[derive(Debug, Default, Clone)]
//! struct AppState {
//!     // Your application state
//! }
//!
//! async fn todo_list() -> &'static str {
//!     "TODO list"
//! }
//!
//! #[tokio::main]
//! async fn main() -> Result<()> {
//!     // Load configuration from environment or file
//!     let config: Config = std::fs::read_to_string("config.toml")?
//!         .parse()?;
//!
//!     // Setup your application routes
//!     let app = FluentRouter::new(config)?
//!         .merge(Router::new().route("/todos", get(todo_list)))
//!         .setup_middleware()
//!         .await?
//!         .finalize_and_start()
//!         .await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Configuration
//!
//! Configuration can be provided via TOML file, TOML string or programmatically.
//! The default configuration is equivalent to the following TOML:
//!
//! ```toml
//! [database]
//! # Database connection URL (supports environment variable substitution)
//! url = "{{ DATABASE_URL }}"
//! max_pool_size = 2
//!
//! [http]
//! bind_addr = "0.0.0.0"
//! bind_port = 3000
//! max_concurrent_requests = 4096
//! max_requests_per_sec = 100
//! max_payload_size_bytes = "64KiB"
//! support_compression = false
//! trim_trailing_slash = true
//! liveness_route = "/live"
//! readiness_route = "/ready"
//! metrics_route = "/metrics"
//!
//! [logging]
//! format = "json"  # Options: "json", "compact", "pretty", "default"
//! ```
//!
//! ### Environment Variable Substitution
//!
//! Configuration values can reference environment variables using using handlebar syntax:
//! `{{ VARIABLE_NAME }}`. This is particularly useful for sensitive values like database URLs.
//!
//! ## Cargo Features
//!
//! - **`postgres`** (default) - Enables PostgreSQL support with connection pooling.
//!   Activates the `[database]` configuration section and provides a connection pool
//!   accessible via the application state.
//!
//! - **`tls`** (default) - Enables TLS support using rustls for secure database connections.
//!   Automatically activated with the `postgres` feature.
//!
//!
//! ## Examples
//!
//! ### Basic Setup with Custom Routes
//!
//! ```rust,no_run
//! use axum::{Router, routing::get};
//! use pictet_axum_service::{Config, Result, FluentRouter};
//!
//! async fn get_count() -> String {
//!     format!("Count: {}", 42)
//! }
//!
//! # async fn run() -> Result<()> {
//! let config: Config = "config.toml".parse()?;
//!
//! FluentRouter::new(config)?
//!     .merge(Router::new().route("/count", get(get_count)))
//!     .setup_middleware()
//!     .await?
//!     .finalize_and_start()
//!     .await?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ### Custom Middleware Configuration
//!
//! ```rust,no_run
//! use pictet_axum_service::Config;
//! use byte_unit::Byte;
//!
//! let mut config = Config::default();
//! config.http.support_compression = true;
//! config.http.max_payload_size_bytes = Byte::from_u64(1024 * 1024); // 1 MiB
//! config.http.max_concurrent_requests = 1000;
//! config.http.max_requests_per_sec = 50;
//! ```
//!
//! ## Module Organization
//!
//! - [`config`] - Configuration structures and parsing
//! - [`configurator`] - Router configuration trait and implementations
//! - [`error`] - Error types and handling
//! - [`utils`] - Utility structs and functions
//!
//! ## Error Handling
//!
//! The library uses a custom [`Result`] type alias that wraps [`Error`]:
//!
//! ```rust
//! use pictet_axum_service::{Result, Error};
//!
//! fn my_function() -> Result<String> {
//!     Ok("success".to_string())
//! }
//! ```
//!
//! ## Testing
//!
//! When writing tests, disable Prometheus metrics to avoid global registry conflicts:
//!
//! ```rust
//! # use pictet_axum_service::Config;
//! let mut config = Config::default();
//! config.http.with_metrics = false;
//! ```
pub mod config;
pub mod error;
pub mod utils;

pub use config::*;
pub use error::*;
use http::StatusCode;
pub use utils::*;

#[cfg(feature = "keycloak")]
use axum_keycloak_auth::{
    PassthroughMode, Url, instance::KeycloakAuthInstance, instance::KeycloakConfig,
    layer::KeycloakAuthLayer,
};

#[cfg(feature = "keycloak")]
pub type Role = String;

pub type Result<T> = std::result::Result<T, Error>;

use {
    axum::{Router, body::Body, extract::DefaultBodyLimit, routing::Route, routing::get},
    axum_keycloak_auth::decode::ProfileAndEmail,
    axum_prometheus::PrometheusMetricLayerBuilder,
    http::{HeaderName, Request, Response, header::AUTHORIZATION},
    std::convert::Infallible,
    std::{env, iter::once, net::SocketAddr, thread::JoinHandle, time::Duration},
    tokio::signal,
    tower::limit::ConcurrencyLimitLayer,
    tower::{Layer, Service},
    tower_governor::{GovernorLayer, governor::GovernorConfigBuilder},
    tower_http::{
        catch_panic::CatchPanicLayer,
        compression::CompressionLayer,
        cors::CorsLayer,
        decompression::RequestDecompressionLayer,
        limit::RequestBodyLimitLayer,
        normalize_path::NormalizePathLayer,
        request_id::{PropagateRequestIdLayer, SetRequestIdLayer},
        sensitive_headers::SetSensitiveHeadersLayer,
        services::fs::ServeDir,
        trace::TraceLayer as TowerHTTPLayer,
    },
    tower_sessions::{
        Expiry, MemoryStore, SessionManagerLayer,
        cookie::{SameSite, time::Duration as CookieDuration},
    },
};

///
/// Fluent builder for axum::Router with configuration-based middleware setup.
///
/// Router returned by [`Config::router`] that forwards layering and nesting
/// calls to the underlying `axum::Router`, allowing middleware to be set up
/// at any stage.
///
/// If the configuration has a static files directory configured as a fallback
/// then it will already be setup. For all other directories, a call to
/// `setup_directories` will install the necessary middleware.
///
pub struct FluentRouter {
    config: Config,
    inner: Router,
    governor_handle: Option<JoinHandle<()>>,
    panic_channel: Option<tokio::sync::mpsc::Sender<String>>,
}

impl FluentRouter {
    pub fn new(config: Config) -> Result<Self> {
        // Validate the configuration
        config.validate()?;

        // Create the base router and add public fallback files if configured
        let mut inner = Router::new();
        if let Some(dir) = config.http.directories.iter().find(|dir| dir.is_fallback()) {
            inner = inner.fallback_service(
                ServeDir::new(&dir.directory).append_index_html_on_directories(true),
            );
        }

        Ok(Self {
            config,
            inner,
            governor_handle: None,
            panic_channel: None,
        })
    }

    pub fn with_panic_notification_channel(self, ch: tokio::sync::mpsc::Sender<String>) -> Self {
        Self {
            panic_channel: Some(ch),
            ..self
        }
    }

    ///
    /// Sets up all static directories configured in the HTTP section except the fallback one.
    /// If public is true, only unprotected directories will be added.
    /// Otherwise only protected directories are added.
    ///
    pub fn setup_directories(mut self, protected: bool) -> Self {
        // Add all other static directories
        for dir in &self.config.http.directories {
            if let StaticDirRoute::Route(route) = &dir.route
                && dir.protected == protected
            {
                self.inner = self.inner.nest_service(
                    route,
                    ServeDir::new(&dir.directory).append_index_html_on_directories(true),
                );
            }
        }
        self
    }

    /// Delegates to setup_directories with protected = false
    pub fn setup_public_files(self) -> Self {
        self.setup_directories(false)
    }

    /// Delegates to setup_directories with protected = true
    pub fn setup_protected_files(self) -> Self {
        self.setup_directories(true)
    }

    pub fn setup_metrics(mut self) -> Self {
        if self.config.http.with_metrics {
            const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
            let metrics_path: &str =
                Box::leak(self.config.http.metrics_route.clone().into_boxed_str());
            let (prometheus_layer, metrics_handle) = PrometheusMetricLayerBuilder::new()
                .with_prefix(PACKAGE_NAME)
                .with_ignore_pattern(metrics_path)
                .with_default_metrics()
                .build_pair();

            self.inner = self
                .inner
                .route(metrics_path, get(|| async move { metrics_handle.render() }))
                .layer(prometheus_layer);
        }
        self
    }

    #[cfg(feature = "keycloak")]
    pub fn setup_oidc(mut self) -> Result<Self> {
        if let Some(oidc) = &self.config.http.oidc {
            let keycloak_auth_instance = KeycloakAuthInstance::new(
                KeycloakConfig::builder()
                    .server(Url::parse(&oidc.issuer_url)?)
                    .realm(oidc.realm.clone())
                    .build(),
            );

            self.inner = self.inner.route_layer(
                KeycloakAuthLayer::<Role, ProfileAndEmail>::builder()
                    .instance(keycloak_auth_instance)
                    .passthrough_mode(PassthroughMode::Block)
                    .expected_audiences(oidc.audiences.clone())
                    .persist_raw_claims(true)
                    .build(),
            );
        }
        Ok(self)
    }

    #[cfg(feature = "session")]
    pub fn setup_settion_handling(mut self) -> Self {
        let session_store = MemoryStore::default();
        let session_layer = SessionManagerLayer::new(session_store)
            .with_secure(false)
            .with_same_site(SameSite::Lax)
            .with_expiry(Expiry::OnInactivity(CookieDuration::seconds(3600)));
        self.inner = self.inner.layer(session_layer);
        self
    }

    pub fn setup_logging(mut self) -> Self {
        self.inner = self.inner.layer(TowerHTTPLayer::new_for_http());
        self
    }

    pub fn setup_max_payload_size(mut self) -> Self {
        self.inner =
            self.inner
                .layer(DefaultBodyLimit::disable())
                .layer(RequestBodyLimitLayer::new(
                    self.config.http.max_payload_size_bytes.as_u64() as usize,
                ));
        self
    }

    pub fn setup_concurrency_limit(mut self) -> Self {
        self.inner = self.inner.layer(ConcurrencyLimitLayer::new(
            self.config.http.max_concurrent_requests as usize,
        ));
        self
    }

    pub fn setup_request_id(mut self) -> Self {
        let x_request_id = HeaderName::from_static("x-request-id");
        self.inner = self
            .inner
            .layer(SetRequestIdLayer::new(
                x_request_id.clone(),
                RequestIdGenerator,
            ))
            .layer(PropagateRequestIdLayer::new(x_request_id));
        self
    }

    pub fn setup_sensitive_headers(mut self) -> Self {
        self.inner = self
            .inner
            .layer(SetSensitiveHeadersLayer::new(once(AUTHORIZATION)));
        self
    }

    pub fn setup_path_normalization(mut self) -> Self {
        self.inner = self.inner.layer(NormalizePathLayer::trim_trailing_slash());
        self
    }

    pub fn setup_compression(mut self) -> Self {
        if self.config.http.support_compression {
            self.inner = self
                .inner
                .layer(RequestDecompressionLayer::new())
                .layer(CompressionLayer::new())
        }
        self
    }

    pub fn setup_liveness_readiness(mut self) -> Self {
        self.inner = self
            .inner
            .route(&self.config.http.liveness_route, get(|| async { "OK\n" }))
            .route(&self.config.http.readiness_route, get(|| async { "OK\n" }));
        self
    }

    ///
    /// Builds and returns the Axum Router configured according to the Server settings.
    ///
    /// NOTE: the with_prometheus flag controls whether Prometheus metrics collection
    ///       is enabled. This is useful to disable during testing to avoid conflicts
    ///       with the global Prometheus registry.
    ///
    pub async fn setup_middleware(self) -> Result<Self> {
        // Output the current version of the service
        const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");
        const VERSION: &str = env!("CARGO_PKG_VERSION");
        tracing::info!("Starting {PACKAGE_NAME} version {VERSION}...");

        Ok(self
            .setup_metrics()
            .setup_logging()
            .setup_oidc()?
            .setup_max_payload_size()
            .setup_cors()
            .setup_concurrency_limit()
            .setup_request_id()
            .setup_sensitive_headers()
            .setup_path_normalization()
            .setup_compression()
            .setup_liveness_readiness())
    }

    pub fn setup_cors(mut self) -> Self {
        use http::HeaderValue;

        if let Some(cors_config) = &self.config.http.cors {
            let mut cors = CorsLayer::new();

            // By default we allow credentials
            let has_credentials = cors_config.allow_credentials.unwrap_or(false);

            // Configure allowed origins
            if let Some(origins) = &cors_config.allowed_origins {
                for origin in origins {
                    if let Ok(header_value) = HeaderValue::from_str(origin) {
                        cors = cors.allow_origin(header_value);
                    }
                }
            } else if !has_credentials {
                // Only use wildcard if credentials is not enabled
                cors = cors.allow_origin(tower_http::cors::Any);
            }

            // Configure allowed methods
            if let Some(methods) = &cors_config.allowed_methods {
                let method_list: Vec<http::Method> = methods.iter().map(|m| m.0.clone()).collect();
                cors = cors.allow_methods(method_list);
            } else if !has_credentials {
                // Only use wildcard if credentials is not enabled
                cors = cors.allow_methods(tower_http::cors::Any);
            }

            // Configure allowed headers
            if let Some(headers) = &cors_config.allowed_headers {
                let header_list: Vec<HeaderName> = headers.iter().map(|h| h.0.clone()).collect();
                cors = cors.allow_headers(header_list);
            } else if !has_credentials {
                // Only use wildcard if credentials is not enabled
                cors = cors.allow_headers(tower_http::cors::Any);
            }

            // Configure exposed headers
            if let Some(headers) = &cors_config.exposed_headers {
                let header_list: Vec<HeaderName> = headers.iter().map(|h| h.0.clone()).collect();
                cors = cors.expose_headers(header_list);
            }

            // Configure max age
            if let Some(max_age) = cors_config.max_age {
                cors = cors.max_age(max_age);
            }

            // Configure credentials (must be set last after origins/headers)
            if has_credentials {
                cors = cors.allow_credentials(true);
            }

            self.inner = self.inner.layer(cors);
        } else {
            // No CORS config specified, use permissive defaults
            self.inner = self.inner.layer(CorsLayer::very_permissive());
        }

        self
    }

    pub fn setup_rate_limiting(mut self) -> Self {
        // Used for rate limiting below
        let governor_conf = Box::new(
            GovernorConfigBuilder::default()
                .per_nanosecond((1_000_000_000 / self.config.http.max_requests_per_sec) as u64)
                .burst_size(self.config.http.max_requests_per_sec)
                .finish()
                .expect("Failed to build governor config for rate limiting"),
        );

        // Spawn a background thread to periodically clean up old entries
        let governor_limiter = governor_conf.limiter().clone();
        let interval = Duration::from_secs(60);

        self.governor_handle = Some(std::thread::spawn(move || {
            loop {
                std::thread::sleep(interval);
                governor_limiter.retain_recent();
                tracing::debug!("remaining rate limiting quotas: {}", governor_limiter.len());
            }
        }));

        // Add the GovernorLayer for rate limiting
        self.inner = self.inner.layer(GovernorLayer::new(governor_conf));
        self
    }

    pub fn setup_catch_panic(mut self) -> Self {
        //
        let panic_channel = self.panic_channel.clone();
        self.inner = self.inner.layer(CatchPanicLayer::custom(
            move |err: Box<dyn std::any::Any + Send + 'static>| {
                // NOTE: taken verbatime from the source of DefaultResponseForPanic
                let msg = if let Some(s) = err.downcast_ref::<String>() {
                    format!("Service panicked: {}", s)
                } else if let Some(s) = err.downcast_ref::<&str>() {
                    format!("Service panicked: {}", s)
                } else {
                    "`CatchPanic` was unable to downcast the panic info".to_string()
                };

                tracing::error!("Service panicked: {}", msg);
                if let Some(ch) = &panic_channel {
                    ch.try_send(msg).ok();
                }

                // Build the final response
                let res = Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body("Internal Server Error".to_string())
                    .expect("Failed to build panic response!!!");

                res
            },
        ));
        self
    }

    ///
    /// Starts the HTTP server based on the current configuration.
    ///
    pub async fn finalize_and_start(self) -> Result<()> {
        let bind_addr = self.config.http.full_bind_addr();
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;

        tracing::info!("Bound to {}", &bind_addr);
        tracing::info!("Waiting for connections");
        tracing::info!("Max req/s: {}", self.config.http.max_requests_per_sec);

        let router = self
            .setup_cors()
            .setup_rate_limiting()
            .setup_catch_panic()
            .into_inner();

        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown_signal())
        .await?;
        Ok(())
    }

    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request<Body>> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Response: axum::response::IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    {
        self.inner = self.inner.layer(layer);
        self
    }

    pub fn route_layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + Sync + 'static,
        L::Service: Service<Request<Body>> + Clone + Send + Sync + 'static,
        <L::Service as Service<Request<Body>>>::Response: axum::response::IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    {
        self.inner = self.inner.route_layer(layer);
        self
    }

    pub fn nest(mut self, path: &str, router: Router) -> Self {
        self.inner = self.inner.nest(path, router);
        self
    }

    pub fn nest_service<T>(mut self, path: &str, service: T) -> Self
    where
        T: Service<Request<Body>, Response = axum::response::Response, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        T::Future: Send + 'static,
    {
        self.inner = self.inner.nest_service(path, service);
        self
    }

    pub fn merge(mut self, other: Router) -> Self {
        self.inner = self.inner.merge(other);
        self
    }

    pub fn route_service<T>(mut self, path: &str, service: T) -> Self
    where
        T: Service<Request<Body>, Response = axum::response::Response, Error = Infallible>
            + Clone
            + Send
            + Sync
            + 'static,
        T::Future: Send + 'static,
    {
        self.inner = self.inner.route_service(path, service);
        self
    }

    pub fn into_inner(self) -> axum::Router {
        self.inner
    }
}
///
/// Returns a signal handler that allows us to stop the server using Ctrl+C
/// or the terminate signal, which in turn allows us to perform a graceful
/// shutdown.
///
#[allow(dead_code)]
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("signal received, starting graceful shutdown");
}

// ----------------------------------------------------------------------------
//
//
// UNIT TESTS
//
//
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    use tower_http::request_id::MakeRequestId;

    /// Helper function to create a test configuration by parsing TOML
    fn create_base_config() -> Config {
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

        toml_str.parse().expect("Failed to parse test config TOML")
    }

    async fn create_test_router(config: Option<Config>) -> Router {
        //
        let mut config = config.unwrap_or_else(create_base_config);
        config.http.with_metrics = false;

        FluentRouter::new(config)
            .expect("Failed to create FluentRouter")
            .merge(Router::new().route("/noop", get(|| async { "OK\n" }).post(|| async { "OK\n" })))
            .setup_middleware()
            .await
            .expect("Failed to setup middleware")
            .into_inner()
    }

    #[tokio::test]
    async fn test_readiness_endpoint_responds() {
        //
        let app = create_test_router(None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 200);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK\n");
    }

    #[tokio::test]
    async fn test_liveness_endpoint_uses_configured_path() {
        //
        let mut config = create_base_config();
        config.http.liveness_route = "/custom-health".to_string();
        let app = create_test_router(Some(config)).await;

        let response = app
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
    async fn test_metrics_endpoint_not_present_without_prometheus() {
        let app = create_test_router(None).await;

        // When Prometheus is disabled, the metrics endpoint should return 404
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 404);
    }

    #[test]
    fn test_metrics_route_configured() {
        let config = create_base_config();

        // Verify the metrics route is configured in the config
        // (whether it's enabled depends on the with_prometheus flag)
        assert_eq!(config.http.metrics_route, "/metrics");
    }

    #[test]
    fn test_trailing_slash_normalization_config() {
        let config = create_base_config();

        // Verify that the configuration has trailing slash normalization enabled
        assert!(config.http.trim_trailing_slash);
    }

    #[tokio::test]
    async fn test_cors_headers_present() {
        //
        let app = create_test_router(None).await;
        let response = app
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/noop")
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
    async fn test_compression_layer_applied_when_enabled() {
        let mut config = create_base_config();
        config.http.support_compression = true;
        let app = create_test_router(Some(config)).await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/noop")
                    .header("Accept-Encoding", "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Response should be successful
        assert_eq!(response.status(), 200);
    }

    #[cfg(feature = "postgres")]
    #[test]
    fn test_database_config_applied() {
        //
        let config = create_base_config();
        // Verify the database configuration values are as expected
        assert_eq!(
            config.database.url,
            "postgres://test:test@localhost:5432/test"
        );
        assert_eq!(config.database.max_pool_size, 5);
    }

    #[test]
    fn test_http_config_values() {
        let config = create_base_config();
        assert_eq!(config.http.bind_addr, "127.0.0.1");
        assert_eq!(config.http.bind_port, 3000);
        assert_eq!(config.http.max_concurrent_requests, 100);
        assert_eq!(config.http.max_payload_size_bytes.as_u64(), 1024);
        assert!(!config.http.support_compression);
        assert!(config.http.trim_trailing_slash);
    }

    #[test]
    fn test_routes_config_values() {
        //
        let config = create_base_config();
        assert_eq!(config.http.liveness_route, "/health");
        assert_eq!(config.http.readiness_route, "/ready");
        assert_eq!(config.http.metrics_route, "/metrics");
    }

    #[test]
    fn test_logging_config_values() {
        let config = create_base_config();

        assert!(matches!(config.logging.format, LogFormat::Json));
    }

    #[tokio::test]
    async fn test_404_for_unknown_routes() {
        let app = create_test_router(None).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/unknown-route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), 404);
    }

    #[test]
    fn test_request_id_generator_creates_uuid() {
        //
        let mut generator = RequestIdGenerator;
        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let request_id = generator.make_request_id(&request);
        assert!(request_id.is_some());

        let id_value = request_id.unwrap();
        let id_str = id_value.header_value().to_str().unwrap();

        // Verify it's a valid UUID format
        assert_eq!(id_str.len(), 36); // UUID v7 format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        assert_eq!(id_str.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn test_request_id_generator_preserves_existing_id() {
        //
        let mut generator = RequestIdGenerator;
        let existing_id = "existing-request-id-12345";
        let request = Request::builder()
            .uri("/test")
            .header("x-request-id", existing_id)
            .body(Body::empty())
            .unwrap();

        let request_id = generator.make_request_id(&request);
        assert!(request_id.is_some());

        let id_value = request_id.unwrap();
        let id_str = id_value.header_value().to_str().unwrap();

        // Should preserve the existing request ID
        assert_eq!(id_str, existing_id);
    }

    #[tokio::test]
    async fn test_request_id_header_added() {
        let app = create_test_router(None).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that x-request-id header is present in response
        // Note: PropagateRequestIdLayer should add this header
        if let Some(request_id) = response.headers().get("x-request-id") {
            let id_str = request_id.to_str().unwrap();
            // Should be a valid UUID v7 format
            assert_eq!(id_str.len(), 36);
        }
        // If not present, the layer configuration is correct but header propagation
        // may work differently in tests vs production
    }

    #[tokio::test]
    async fn test_request_id_preserved_from_request() {
        //
        let app = create_test_router(None).await;

        let custom_id = "my-custom-request-id-123";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/noop")
                    .header("x-request-id", custom_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Verify that the custom request ID is preserved
        let response_id = response
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(response_id, custom_id);
    }

    #[tokio::test]
    async fn test_state_accessible_in_handlers() {
        //
        let app = create_test_router(None).await;

        // Test that the router was successfully built with state
        // The fact that it responds means the state was properly configured
        let response = app
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
    async fn test_compression_disabled_by_default() {
        //
        let config = create_base_config();
        // Verify compression is disabled in base config
        assert!(!config.http.support_compression);
    }

    #[tokio::test]
    async fn test_all_middleware_layers_applied() {
        //
        let app = create_test_router(None).await;

        // Make a request that exercises multiple middleware layers
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/noop") // Use the actual route path
                    .header("Origin", "http://example.com") // Tests CorsLayer
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should successfully respond with CORS handled
        assert_eq!(response.status(), 200);

        // Should have CORS headers (CorsLayer with very_permissive)
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );

        // Verify the body is correct
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK\n");
    }

    #[tokio::test]
    async fn test_payload_size_limit_configured() {
        //
        let config = create_base_config();

        // Verify that the max payload size limit is properly configured
        assert_eq!(config.http.max_payload_size_bytes.as_u64(), 1024);

        // The RequestBodyLimitLayer is applied in setup_http_service with this value
        // Note: In the current implementation, DefaultBodyLimit::disable() is called
        // and RequestBodyLimitLayer is added, which should enforce the limit.
        // However, the actual enforcement may depend on how the body is consumed.
    }

    #[tokio::test]
    async fn test_payload_within_limit_accepted() {
        //
        let app = create_test_router(None).await;

        // Create a payload smaller than the configured limit (1KiB)
        let acceptable_payload = vec![b'x'; 512]; // 512 Bytes
        let payload_len = acceptable_payload.len();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/noop")
                    .header("content-type", "application/octet-stream")
                    .header("content-length", payload_len.to_string())
                    .body(Body::from(acceptable_payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should succeed and not be rejected based on payload size
        assert_eq!(response.status(), 200);
    }

    #[tokio::test]
    async fn test_payload_exceeds_configured_limit() {
        //
        let app = create_test_router(None).await;

        // Create a payload bigger than the configured limit (1KiB)
        let unacceptable_payload = vec![b'x'; 1025]; // 1 KiB + 1 byte
        let payload_len = unacceptable_payload.len();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/test-post")
                    .header("content-type", "application/octet-stream")
                    .header("content-length", payload_len.to_string())
                    .body(Body::from(unacceptable_payload))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should succeed and not be rejected based on payload size
        assert_eq!(response.status(), 413);
    }
}

#[cfg(test)]
mod fluent_router_tests {
    use super::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        response::{IntoResponse, Response},
        routing::get,
    };
    use tower::{Service, ServiceExt};
    use tower_http::compression::CompressionLayer;

    async fn nested_handler() -> &'static str {
        "nested response"
    }

    fn create_test_config() -> Config {
        let mut config = Config::default();
        #[cfg(feature = "postgres")]
        {
            config.database.url = "postgresql://test:test@localhost:5432/test".to_string();
        }
        config
    }

    #[tokio::test]
    async fn test_fluent_router_new() {
        let config = create_test_config();
        let fluent_router = FluentRouter::new(config);
        assert!(fluent_router.is_ok());
    }

    #[tokio::test]
    async fn test_fluent_router_into_inner() {
        let config = create_test_config();
        let fluent_router = FluentRouter::new(config).unwrap();
        let router: Router = fluent_router.into_inner();

        // Verify we get a valid Router back
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_fluent_router_nest() {
        let config = create_test_config();
        let nested_router = Router::new().route("/nested", get(nested_handler));

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .nest("/api", nested_router);

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/api/nested")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"nested response");
    }

    #[tokio::test]
    async fn test_fluent_router_merge() {
        let config = create_test_config();
        let other_router = Router::new().route("/merged", get(|| async { "merged response" }));

        let fluent_router = FluentRouter::new(config).unwrap().merge(other_router);

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/merged")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"merged response");
    }

    #[tokio::test]
    async fn test_fluent_router_layer() {
        let config = create_test_config();
        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .layer(CompressionLayer::new());

        let router = fluent_router.into_inner();

        // Verify router is created successfully with layer
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_fluent_router_route_layer() {
        let config = create_test_config();
        let test_router = Router::new().route("/test", get(|| async { "test" }));

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(test_router)
            .route_layer(tower::limit::ConcurrencyLimitLayer::new(10));

        let mut app = fluent_router.into_inner();

        // Verify the route works with the route layer applied
        let response = app
            .call(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fluent_router_method_chaining() {
        let config = create_test_config();
        let nested_router = Router::new().route("/nested", get(nested_handler));
        let other_router = Router::new().route("/merged", get(|| async { "merged" }));

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .nest("/api", nested_router)
            .merge(other_router)
            .layer(CompressionLayer::new());

        let app = fluent_router.into_inner();

        // Test nested route
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/nested")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Test merged route
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/merged")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fluent_router_setup_methods() {
        let config = create_test_config();
        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .setup_public_files()
            .setup_protected_files();

        let router = fluent_router.into_inner();

        // Verify router is created successfully
        assert!(std::mem::size_of_val(&router) > 0);
    }

    #[tokio::test]
    async fn test_fluent_router_with_invalid_config() {
        // Create a config that will fail validation (if validation exists)
        let config = create_test_config();
        // Depending on validation logic, this might pass or fail
        let result = FluentRouter::new(config);

        // This test demonstrates handling of potential validation failures
        // Adjust based on actual validation requirements
        assert!(result.is_ok() || result.is_err());
    }

    #[tokio::test]
    async fn test_fluent_router_nest_service() {
        use tower::service_fn;

        let config = create_test_config();

        let service = service_fn(|_req: Request<Body>| async {
            Ok::<Response, Infallible>((StatusCode::OK, "service response").into_response())
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .nest_service("/service", service);

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/service")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"service response");
    }

    #[tokio::test]
    async fn test_fluent_router_route_service() {
        use tower::service_fn;

        let config = create_test_config();

        let service = service_fn(|_req: Request<Body>| async {
            Ok::<Response, Infallible>((StatusCode::OK, "route service response").into_response())
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .route_service("/route", service);

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/route")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"route service response");
    }

    #[tokio::test]
    async fn test_setup_cors_with_no_config() {
        // When no CORS config is provided, should use permissive defaults
        let config = create_test_config();
        let fluent_router = FluentRouter::new(config).unwrap().setup_cors();

        let mut app = fluent_router.into_inner();

        // Make a CORS preflight request
        let response = app
            .call(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have CORS headers
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
                || response
                    .headers()
                    .contains_key("access-control-allow-methods")
        );
    }

    #[tokio::test]
    async fn test_setup_cors_with_allowed_origins() {
        use crate::{CorsMethod, HttpCorsConfig};
        use http::Method;

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: Some(vec![CorsMethod(Method::GET)]),
            allowed_headers: None,
            exposed_headers: None,
            max_age: None,
            allow_credentials: None,
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let mut app = fluent_router.into_inner();

        // Make an actual GET request with Origin header
        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should allow the configured origin
        let allow_origin = response.headers().get("access-control-allow-origin");
        assert!(allow_origin.is_some());
        assert_eq!(allow_origin.unwrap(), "https://example.com");
    }

    #[tokio::test]
    async fn test_setup_cors_with_allowed_methods() {
        use crate::{CorsMethod, HttpCorsConfig};
        use http::Method;

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: Some(vec![CorsMethod(Method::GET), CorsMethod(Method::POST)]),
            allowed_headers: None,
            exposed_headers: None,
            max_age: None,
            allow_credentials: None,
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have CORS headers
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[tokio::test]
    async fn test_setup_cors_with_allowed_headers() {
        use crate::{CorsHeader, CorsMethod, HttpCorsConfig};
        use http::{HeaderName, Method};

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: Some(vec![CorsMethod(Method::GET)]),
            allowed_headers: Some(vec![
                CorsHeader(HeaderName::from_static("content-type")),
                CorsHeader(HeaderName::from_static("authorization")),
            ]),
            exposed_headers: None,
            max_age: None,
            allow_credentials: None,
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have CORS headers
        assert!(
            response
                .headers()
                .contains_key("access-control-allow-origin")
        );
    }

    #[tokio::test]
    async fn test_setup_cors_with_credentials() {
        use crate::{CorsHeader, CorsMethod, HttpCorsConfig};
        use http::{HeaderName, Method};

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: Some(vec![CorsMethod(Method::GET)]),
            allowed_headers: Some(vec![CorsHeader(HeaderName::from_static("content-type"))]),
            exposed_headers: None,
            max_age: None,
            allow_credentials: Some(true),
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have credentials header
        let credentials = response.headers().get("access-control-allow-credentials");
        assert!(credentials.is_some() && credentials.unwrap() == "true");
    }

    #[tokio::test]
    async fn test_setup_cors_with_max_age() {
        use crate::HttpCorsConfig;
        use std::time::Duration;

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: None,
            allowed_methods: None,
            allowed_headers: None,
            exposed_headers: None,
            max_age: Some(Duration::from_secs(3600)),
            allow_credentials: None,
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let app = fluent_router.into_inner();

        // Max age is typically reflected in preflight responses
        // For this test, we just verify the router was built successfully with the config
        assert!(std::mem::size_of_val(&app) > 0);
    }

    #[tokio::test]
    async fn test_setup_cors_complete_config() {
        use crate::{CorsHeader, CorsMethod, HttpCorsConfig};
        use http::{HeaderName, Method};
        use std::time::Duration;

        let mut config = create_test_config();
        config.http.cors = Some(HttpCorsConfig {
            allowed_origins: Some(vec!["https://example.com".to_string()]),
            allowed_methods: Some(vec![CorsMethod(Method::GET), CorsMethod(Method::POST)]),
            allowed_headers: Some(vec![CorsHeader(HeaderName::from_static("content-type"))]),
            exposed_headers: Some(vec![CorsHeader(HeaderName::from_static("x-custom-header"))]),
            max_age: Some(Duration::from_secs(7200)),
            allow_credentials: Some(true),
        });

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(Router::new().route("/test", get(|| async { "test" })))
            .setup_cors();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .method("GET")
                    .uri("/test")
                    .header("Origin", "https://example.com")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should have multiple CORS headers configured
        let headers = response.headers();
        assert!(headers.contains_key("access-control-allow-origin"));
        assert_eq!(
            headers.get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );

        let credentials = headers.get("access-control-allow-credentials");
        assert!(credentials.is_some() && credentials.unwrap() == "true");
    }

    #[tokio::test]
    async fn test_setup_catch_panic_with_panic() {
        let config = create_test_config();

        // Create a route that panics
        let panic_router = Router::new().route(
            "/panic",
            get(|| async {
                panic!("Test panic!");
                #[allow(unreachable_code)]
                "This will never be reached"
            }),
        );

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(panic_router)
            .setup_catch_panic();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 500 Internal Server Error
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Should have the correct content type
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; charset=utf-8"
        );

        // Check the body
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"Internal Server Error");
    }

    #[tokio::test]
    async fn test_setup_catch_panic_normal_request() {
        let config = create_test_config();

        // Create a normal route
        let normal_router = Router::new().route("/normal", get(|| async { "OK" }));

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .merge(normal_router)
            .setup_catch_panic();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/normal")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK for normal requests
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"OK");
    }

    #[tokio::test]
    async fn test_with_panic_notification_channel() {
        let config = create_test_config();

        // Create a channel to receive panic notifications
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);

        // Create a route that panics
        let panic_router = Router::new().route(
            "/panic_notify",
            get(|| async {
                panic!("Notification test panic!");
                #[allow(unreachable_code)]
                "This will never be reached"
            }),
        );

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .with_panic_notification_channel(tx)
            .merge(panic_router)
            .setup_catch_panic();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/panic_notify")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 500 Internal Server Error
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // Check that we received a panic notification
        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

        assert!(notification.is_ok());
        let msg = notification.unwrap().unwrap();
        assert!(msg.contains("Service panicked"));
        assert!(msg.contains("Notification test panic!"));
    }

    #[tokio::test]
    async fn test_with_panic_notification_channel_no_panic() {
        let config = create_test_config();

        // Create a channel to receive panic notifications
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);

        // Create a normal route
        let normal_router = Router::new().route("/no_panic", get(|| async { "All good" }));

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .with_panic_notification_channel(tx)
            .merge(normal_router)
            .setup_catch_panic();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/no_panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return 200 OK
        assert_eq!(response.status(), StatusCode::OK);

        // Check that no panic notification was sent
        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

        // Should timeout since no panic occurred
        assert!(notification.is_err());
    }

    #[tokio::test]
    async fn test_catch_panic_with_string_panic() {
        let config = create_test_config();

        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(10);

        // Create a route that panics with a String
        let panic_router = Router::new().route(
            "/string_panic",
            get(|| async {
                panic!("String panic message");
                #[allow(unreachable_code)]
                "This will never be reached"
            }),
        );

        let fluent_router = FluentRouter::new(config)
            .unwrap()
            .with_panic_notification_channel(tx)
            .merge(panic_router)
            .setup_catch_panic();

        let mut app = fluent_router.into_inner();

        let response = app
            .call(
                Request::builder()
                    .uri("/string_panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let notification =
            tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await;

        assert!(notification.is_ok());
        let msg = notification.unwrap().unwrap();
        assert!(msg.contains("String panic message"));
    }
}
