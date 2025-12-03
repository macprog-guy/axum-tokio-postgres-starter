//!
//! Configuration structures and utilities for wiring up the application or service.
//!
//! A configuration can be created in many ways:
//! - From an environment-specific TOML file via `Config::from_env_toml`
//! - From a TOML string via `Config::from_toml`
//! - Constructed programmatically via the builder methods on `Config`
//!
//! In both TOML-based methods, environment variables can be referenced in the TOML
//! using the {{ VAR_NAME }} syntax, and they will be substituted with the corresponding
//! environment variable value. This is done via the `replace_handlebars_with_env`
//! function and prevents sensitive information from being stored directly in the
//! TOML files.
//!
//! Configuration is split into logical sections, each represented by their own struct:
//!
//! - `HttpConfig` for HTTP server settings
//! - `DatabaseConfig` for database connection pool settings
//! - `LoggingConfig` for logging and tracing settings
//! - `StaticDirConfig` for static file serving settings
//!
//!
#[cfg(feature = "keycloak")]
use crate::Sensitive;
pub use byte_unit::Byte;

use {
    crate::{Error, Result, replace_handlebars_with_env},
    serde::Deserialize,
    std::{env, fs, str::FromStr, time::Duration},
};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub http: HttpConfig,
    #[cfg(feature = "postgres")]
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

impl Config {
    ///
    /// Loads the configuration from a file based on the RUST_ENV environment variable.
    /// If RUST_ENV is not set, defaults to "prod".
    ///
    pub fn from_rust_env() -> Result<Config> {
        Self::from_toml_file(env::var("RUST_ENV")?)
    }

    ///
    /// Given an environment name, loads the corresponding configuration file,
    /// substitutes any environment variables, and returns a Config struct.
    /// The configuration file is expected to be located at "config/{env}.toml"
    /// where {env} is the string representation of the RuntimeEnv.
    ///
    pub fn from_toml_file(env: impl AsRef<str>) -> Result<Config> {
        let path = format!("config/{}.toml", env.as_ref());
        let text = fs::read_to_string(path)?;
        Self::from_toml(&text)
    }

    ///
    /// Parses a configuration string in TOML format into a Config struct.
    ///
    pub fn from_toml(toml_str: &str) -> Result<Config> {
        replace_handlebars_with_env(toml_str).parse()
    }

    /// Sets the HTTP server bind address of the HttpConfig.
    pub fn with_bind_addr<S: AsRef<str>>(mut self, addr: S) -> Self {
        self.http.bind_addr = addr.as_ref().into();
        self
    }

    /// Sets the HTTP server bind port of the HttpConfig.
    pub fn with_bind_port(mut self, port: u16) -> Self {
        self.http.bind_port = port;
        self
    }

    /// Sets the maximum number of concurrent requests of the HttpConfig.
    pub fn with_max_concurrent_requests(mut self, max: u32) -> Self {
        self.http.max_concurrent_requests = max;
        self
    }

    /// Sets the request timeout duration of the HttpConfig.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.http.request_timeout = Some(timeout);
        self
    }

    pub fn with_max_payload_size_bytes(mut self, size: u64) -> Self {
        self.http.max_payload_size_bytes = Byte::from_u64(size);
        self
    }

    /// Enables or disables compression support in the HttpConfig.
    pub fn with_compression(mut self, enable: bool) -> Self {
        self.http.support_compression = enable;
        self
    }

    /// Enables or disables trailing slash trimming in the HttpConfig.
    pub fn with_trim_trailing_slash(mut self, enable: bool) -> Self {
        self.http.trim_trailing_slash = enable;
        self
    }

    /// Sets the liveness route path of the HttpConfig.
    pub fn with_liveness_route(mut self, route: &str) -> Self {
        self.http.liveness_route = route.into();
        self
    }

    /// Sets the readiness route path of the HttpConfig.
    pub fn with_readiness_route(mut self, route: &str) -> Self {
        self.http.readiness_route = route.into();
        self
    }

    /// Sets the metrics route path of the HttpConfig.
    pub fn with_metrics_route(mut self, route: &str) -> Self {
        self.http.metrics_route = route.into();
        self
    }

    /// Sets the Postgres database connection URL of the DatabaseConfig.
    #[cfg(feature = "postgres")]
    pub fn with_pg_url(mut self, url: &str) -> Self {
        self.database.url = url.into();
        self
    }

    /// Sets the maximum pool size of the DatabaseConfig.
    #[cfg(feature = "postgres")]
    pub fn with_pg_max_pool_size(mut self, size: u8) -> Self {
        self.database.max_pool_size = size;
        self
    }

    /// Sets the maximum idle time duration of the DatabaseConfig.
    #[cfg(feature = "postgres")]
    pub fn with_pg_max_idle_time(mut self, duration: Duration) -> Self {
        self.database.max_idle_time = Some(duration);
        self
    }

    /// Sets the log format of the LoggingConfig.
    pub fn with_log_format(mut self, format: LogFormat) -> Self {
        self.logging.format = format;
        self
    }

    /// Sets the OIDC configuration of the HttpConfig.
    /// The default OIDC configuration is empty and must be set explicitly
    /// either programmatically or via TOML.
    #[cfg(feature = "keycloak")]
    pub fn with_oidc_config(mut self, oidc_config: HttpOidcConfig) -> Self {
        self.http.oidc = Some(oidc_config);
        self
    }

    /// Ensures that the configuration is valid.
    /// Most configuration values are either optional or have sensible defaults.
    /// Some are required and since and here we ensure that those required values
    /// are set.
    pub fn validate(&self) -> Result<()> {
        #[cfg(feature = "postgres")]
        self.database.validate()?;
        self.http.validate()?;
        self.logging.validate()?;
        Ok(())
    }
}

///
/// Parses a configuration string with references to environment variables
/// into a Config struct by substituting the environment variables and then
/// parsing the resulting TOML.
///
impl FromStr for Config {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let config_file = replace_handlebars_with_env(s);
        let config = toml::from_str::<Config>(&config_file)?;
        Ok(config)
    }
}

///
/// Configuration for the HTTP server
///
/// This configuration includes many settings that control the behavior
/// of the HTTP server, including binding address and port, request limits,
/// timeouts, and specific route paths.
///
#[derive(Debug, Clone, Deserialize)]
pub struct HttpConfig {
    /// IP address to bind the HTTP server to
    /// The default `bind_addr` is "127.0.0.1".
    #[serde(default = "HttpConfig::default_bind_addr")]
    pub bind_addr: String,

    /// Port to bind the HTTP server to
    /// The default `bind_port` is 3000.
    #[serde(default = "HttpConfig::default_bind_port")]
    pub bind_port: u16,

    /// Maximum number of concurrent requests to handle.
    /// If the number of concurrent requests exceeds this number, new requests
    /// will be rejected with a 503 Service Unavailable response.
    /// By default `max_concurrent_requests` is set to 4096.
    #[serde(default = "HttpConfig::default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,

    /// Maximum number of request per second (per IP address).
    /// If the rate is exceeded, new requests to the server will be rejected
    /// with a 429 Too Many Requests. The default is 100 requests per second.
    #[serde(default = "HttpConfig::default_max_requests_per_sec")]
    pub max_requests_per_sec: u32,

    /// Maximum allowed time for a request to complete before timing out.
    /// If a request takes longer than this it will be aborted with a 408
    /// Request Timeout response. Too many such responses in a short time
    /// interval will make the server unavaliable during a readiness check.
    /// By default `request_timeout` is None.
    #[serde(default, with = "humantime_serde")]
    pub request_timeout: Option<Duration>,

    /// Maximum payload size in bytes for incoming HTTP requests.
    /// Requests with payloads larger than this will be rejected with
    /// a 413 Payload Too Large response.
    /// By default `max_payload_size_bytes` is set to 256KiB.
    pub max_payload_size_bytes: byte_unit::Byte,

    /// Whether or not to support gzip/brotli/deflate/zstd request and
    /// response compression. By default compression is disabled.
    #[serde(default)]
    pub support_compression: bool,

    /// Whether or not to expose Prometheus metrics endpoint.
    /// By default `with_metrics` is set to true.
    #[serde(default = "HttpConfig::default_with_metrics")]
    pub with_metrics: bool,

    /// Whether or not to trim trailing slashes from the request path.
    /// By default `trim_trailing_slash` is set to true.
    #[serde(default = "HttpConfig::default_trim_trailing_slash")]
    pub trim_trailing_slash: bool,

    /// Route for liveness checks.
    /// By default `liveness` is "/live".
    #[serde(default = "HttpConfig::default_liveness_route")]
    pub liveness_route: String,

    /// Route for readiness checks.
    /// The readiness check will return a 429 Too Many Requests when unable
    /// to handle the load. By default `readiness` is set to "/ready".
    #[serde(default = "HttpConfig::default_readiness_route")]
    pub readiness_route: String,

    /// Route for metrics.
    /// Our Kubernetes infrastructure can scrape this endpoint for
    /// Prometheus metrics. By default `metrics` is set to "/metrics".
    #[serde(default = "HttpConfig::default_metrics_route")]
    pub metrics_route: String,

    /// Configuration for serving static files.
    #[serde(default)]
    pub directories: Vec<StaticDirConfig>,

    /// OIDC authentication configuration.
    /// Only included if the "oidc" feature is enabled.
    /// When None, OIDC authentication is disabled.
    #[cfg(feature = "keycloak")]
    #[serde(default)]
    pub oidc: Option<HttpOidcConfig>,
}

impl HttpConfig {
    ///
    /// Returns the full bind address as a string in the format "IP:PORT".
    ///
    pub fn full_bind_addr(&self) -> String {
        format!("{}:{}", self.bind_addr, self.bind_port)
    }

    fn default_bind_addr() -> String {
        "127.0.0.1".into()
    }

    fn default_bind_port() -> u16 {
        3000
    }

    fn default_max_concurrent_requests() -> u32 {
        4096
    }

    fn default_max_requests_per_sec() -> u32 {
        100
    }

    fn default_max_payload_size_bytes() -> byte_unit::Byte {
        byte_unit::Byte::from_u64(32 * 1024)
    }

    fn default_trim_trailing_slash() -> bool {
        true
    }
    fn default_with_metrics() -> bool {
        true
    }
    fn default_liveness_route() -> String {
        "/live".into()
    }

    fn default_readiness_route() -> String {
        "/ready".into()
    }

    fn default_metrics_route() -> String {
        "/metrics".into()
    }
    fn validate(&self) -> Result<()> {
        #[cfg(feature = "keycloak")]
        if let Some(oidc_config) = &self.oidc {
            oidc_config.validate()?;
        }
        Ok(())
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            bind_addr: Self::default_bind_addr(),
            bind_port: Self::default_bind_port(),
            max_payload_size_bytes: Self::default_max_payload_size_bytes(),
            max_concurrent_requests: Self::default_max_concurrent_requests(),
            max_requests_per_sec: Self::default_max_requests_per_sec(),
            support_compression: false,
            with_metrics: Self::default_with_metrics(),
            trim_trailing_slash: Self::default_trim_trailing_slash(),
            request_timeout: None,
            liveness_route: Self::default_liveness_route(),
            readiness_route: Self::default_readiness_route(),
            metrics_route: Self::default_metrics_route(),
            directories: Vec::new(),
            #[cfg(feature = "keycloak")]
            oidc: None,
        }
    }
}

///
/// Configuration for OIDC authentication.
///
/// The default value for issuer_url depends on the RUST_ENV environment
/// variable and will be valid for a PCO deployment.
///
#[cfg(feature = "keycloak")]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct HttpOidcConfig {
    #[serde(default)]
    pub issuer_url: String,
    #[serde(default = "HttpOidcConfig::default_realm")]
    pub realm: String,
    #[serde(default)]
    pub audiences: Vec<String>,
    pub client_id: String,
    pub client_secret: Sensitive<String>,
}

impl HttpOidcConfig {
    pub fn default_realm() -> String {
        "pictet".into()
    }
    pub fn validate(&self) -> Result<()> {
        if self.issuer_url.is_empty() {
            return Err(Error::Other(
                "OIDC issuer_url must be set in the configuration",
            ));
        }
        if self.client_id.is_empty() {
            return Err(Error::Other(
                "OIDC client_id must be set in the configuration",
            ));
        }
        if self.client_secret.0.is_empty() {
            return Err(Error::Other(
                "OIDC client_secret must be set in the configuration",
            ));
        }
        Ok(())
    }
}

///
/// Configuration for the database connection pool.
///
#[cfg(feature = "postgres")]
#[derive(Debug, Clone, Deserialize, Default)]
pub struct DatabaseConfig {
    /// Database connection URL.
    /// This should be a valid Postgres connection string in URL format.
    /// For example, "postgres://user:password@localhost:5432/database".
    /// This value is required.
    #[serde(default = "DatabaseConfig::default_url")]
    pub url: String,

    /// Sets the maximum number of connections in the pool.
    /// By default `max_pool_size` is set to 2.
    #[serde(default = "DatabaseConfig::default_max_pool_size")]
    pub max_pool_size: u8,

    /// Maximum idle time for connections in the pool.
    /// Connections that have been idle for longer than this duration
    /// will be closed. For example, a value of "5m" would set the
    /// maximum idle time to 5 minutes. By default `max_idle_time` is None.
    #[serde(default, with = "humantime_serde")]
    pub max_idle_time: Option<Duration>,
}

#[cfg(feature = "postgres")]
impl DatabaseConfig {
    fn default_url() -> String {
        env::var("DATABASE_URL").unwrap_or_default()
    }
    fn default_max_pool_size() -> u8 {
        2
    }
    fn validate(&self) -> Result<()> {
        if self.url.is_empty() {
            return Err(Error::Other(
                "Database URL must be set or provided through the DATABASE_URL environment variable",
            ));
        }
        Ok(())
    }
}

///
/// Configuration for logging and tracing.
///
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LoggingConfig {
    /// Format for log output.
    /// The default format is `default`, which is "full" human-readable format.
    /// Other options are `json`, `compact`, and `pretty`.
    pub format: LogFormat,
}

impl LoggingConfig {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    #[default]
    Default,
    Compact,
    Pretty,
}

///
/// Configuration for serving static files.
///
#[derive(Debug, Clone, Deserialize)]
pub struct StaticDirConfig {
    pub directory: String,
    #[serde(flatten)]
    pub route: StaticDirRoute,
}

impl StaticDirConfig {
    pub fn is_fallback(&self) -> bool {
        matches!(self.route, StaticDirRoute::Fallback(_))
    }
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StaticDirRoute {
    Route(String),
    Fallback(bool),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_static_dir_config_parsing() {
        let config_str = r#"
        [http]
        max_payload_size_bytes = "1KiB"
        
        [[http.directories]]
        directory = "static"
        route = "route"
        
        [[http.directories]]
        directory = "public"
        fallback = true
        "#;

        let config = config_str.parse::<Config>().unwrap();
        assert_eq!(config.http.directories[0].directory, "static");
        assert!(matches!(
            config.http.directories[0].route,
            StaticDirRoute::Route(_)
        ));

        assert_eq!(config.http.directories[1].directory, "public");
        assert!(matches!(
            config.http.directories[1].route,
            StaticDirRoute::Fallback(_)
        ));
    }

    #[test]
    fn test_replace_handlebars_with_env_no_variables() {
        let input = "This is a plain string with no variables";
        let output = replace_handlebars_with_env(input);
        assert_eq!(output, input);
    }

    #[test]
    fn test_replace_handlebars_with_env_with_variables() {
        unsafe {
            env::set_var("TEST_VAR", "test_value");
            env::set_var("ANOTHER_VAR", "another_value");
        }
        let input = "Database URL: {{ TEST_VAR }}, Host: {{ ANOTHER_VAR }}";
        let output = replace_handlebars_with_env(input);
        assert_eq!(output, "Database URL: test_value, Host: another_value");

        unsafe {
            env::remove_var("TEST_VAR");
            env::remove_var("ANOTHER_VAR");
        }
    }

    #[test]
    fn test_replace_handlebars_with_env_missing_variable() {
        unsafe {
            env::remove_var("NONEXISTENT_VAR");
        }

        let input = "Value: {{ NONEXISTENT_VAR }}";
        let output = replace_handlebars_with_env(input);
        assert_eq!(output, "Value: ");
    }

    #[test]
    fn test_replace_handlebars_with_env_whitespace() {
        unsafe {
            env::set_var("SPACED_VAR", "value");
        }

        let input = "{{SPACED_VAR}} {{ SPACED_VAR }} {{  SPACED_VAR  }}";
        let output = replace_handlebars_with_env(input);
        assert_eq!(output, "value value value");

        unsafe {
            env::remove_var("SPACED_VAR");
        }
    }

    #[test]
    fn test_replace_handlebars_with_env_multiple_occurrences() {
        unsafe {
            env::set_var("REPEATED_VAR", "repeated");
        }

        let input = "{{ REPEATED_VAR }} and {{ REPEATED_VAR }} again";
        let output = replace_handlebars_with_env(input);
        assert_eq!(output, "repeated and repeated again");

        unsafe {
            env::remove_var("REPEATED_VAR");
        }
    }

    #[test]
    fn test_config_from_str_valid() {
        unsafe {
            env::set_var("DATABASE_URL", "postgres://localhost/test");
        }

        let config_str = r#"
[database]
url = "{{ DATABASE_URL }}"
max_pool_size = 10

[http]
bind_addr = "0.0.0.0"
bind_port = 8080
max_payload_size_bytes = "1MB"
max_requests_per_sec = 5000

[http.oidc]
issuer_url = "https://keycloak.pictet.aws/realms/pictet"
client_id = "one-environment-pkce"
client_secret = "test"
realm = "pictet"

[logging]
format = "json"
        "#;

        let config = config_str.parse::<Config>();
        eprintln!("{:?}", config);
        assert!(config.is_ok());

        let config = config.unwrap();
        #[cfg(feature = "postgres")]
        assert_eq!(config.database.url, "postgres://localhost/test");
        assert_eq!(config.http.bind_addr, "0.0.0.0");
        assert_eq!(config.http.bind_port, 8080);

        unsafe {
            env::remove_var("DATABASE_URL");
        }
    }

    #[test]
    fn test_config_from_str_invalid_toml() {
        let invalid_config = "this is not valid toml";
        let result = invalid_config.parse::<Config>();
        assert!(result.is_err());
    }

    #[test]
    #[cfg(feature = "postgres")]
    fn test_config_from_str_missing_required_fields() {
        // Test that validation catches missing required fields
        // In this case, an empty database URL should fail validation
        let incomplete_config = r#"
[database]
url = "postgres://localhost/test"

[http]
max_payload_size_bytes = "1KiB"
        "#;

        let result = incomplete_config.parse::<Config>();
        assert!(result.is_ok()); // Parsing should succeed with valid values
        
        // Now test with an empty database URL - validation should fail
        let mut config = result.unwrap();
        config.database.url = "".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_builder_matches_toml_equivalent() {
        // Build a configuration using builder methods
        let builder_config = Config::default()
            .with_bind_addr("0.0.0.0")
            .with_bind_port(8080)
            .with_max_concurrent_requests(2048)
            .with_request_timeout(Duration::from_secs(30))
            .with_max_payload_size_bytes(2 * 1024 * 1024) // 2 MiB
            .with_compression(true)
            .with_trim_trailing_slash(false)
            .with_liveness_route("/health")
            .with_readiness_route("/ready")
            .with_metrics_route("/prometheus")
            .with_log_format(LogFormat::Compact);

        #[cfg(feature = "postgres")]
        let builder_config = builder_config
            .with_pg_url("postgres://user:pass@localhost:5432/mydb")
            .with_pg_max_pool_size(20)
            .with_pg_max_idle_time(Duration::from_secs(300));

        // Create an equivalent configuration from TOML
        let toml_str = r#"
[http]
bind_addr = "0.0.0.0"
bind_port = 8080
max_concurrent_requests = 2048
request_timeout = "30s"
max_payload_size_bytes = "2MiB"
support_compression = true
trim_trailing_slash = false
liveness_route = "/health"
readiness_route = "/ready"
metrics_route = "/prometheus"

[http.oidc]
issuer_url = "http://localhost:8080"
client_id = "test"
client_secret = "test"
realm = "test"

[database]
url = "postgres://user:pass@localhost:5432/mydb"
max_pool_size = 20
max_idle_time = "300s"

[logging]
format = "compact"
        "#;

        let toml_config: Config = toml_str.parse().expect("Failed to parse TOML config");

        // Compare HTTP configuration
        assert_eq!(builder_config.http.bind_addr, toml_config.http.bind_addr);
        assert_eq!(builder_config.http.bind_port, toml_config.http.bind_port);
        assert_eq!(
            builder_config.http.max_concurrent_requests,
            toml_config.http.max_concurrent_requests
        );
        assert_eq!(
            builder_config.http.request_timeout,
            toml_config.http.request_timeout
        );
        assert_eq!(
            builder_config.http.max_payload_size_bytes.as_u64(),
            toml_config.http.max_payload_size_bytes.as_u64()
        );
        assert_eq!(
            builder_config.http.support_compression,
            toml_config.http.support_compression
        );
        assert_eq!(
            builder_config.http.trim_trailing_slash,
            toml_config.http.trim_trailing_slash
        );
        assert_eq!(
            builder_config.http.liveness_route,
            toml_config.http.liveness_route
        );
        assert_eq!(
            builder_config.http.readiness_route,
            toml_config.http.readiness_route
        );
        assert_eq!(
            builder_config.http.metrics_route,
            toml_config.http.metrics_route
        );

        // Compare database configuration (if postgres feature is enabled)
        #[cfg(feature = "postgres")]
        {
            assert_eq!(builder_config.database.url, toml_config.database.url);
            assert_eq!(
                builder_config.database.max_pool_size,
                toml_config.database.max_pool_size
            );
            assert_eq!(
                builder_config.database.max_idle_time,
                toml_config.database.max_idle_time
            );
        }

        // Compare logging configuration
        assert!(matches!(builder_config.logging.format, LogFormat::Compact));
        assert!(matches!(toml_config.logging.format, LogFormat::Compact));
    }

    #[test]
    fn test_config_builder_chaining() {
        // Test that builder methods can be chained fluently
        let config = Config::default()
            .with_bind_addr("127.0.0.1")
            .with_bind_port(3000)
            .with_compression(true)
            .with_log_format(LogFormat::Json);

        assert_eq!(config.http.bind_addr, "127.0.0.1");
        assert_eq!(config.http.bind_port, 3000);
        assert_eq!(config.http.full_bind_addr(), "127.0.0.1:3000");
        assert!(config.http.support_compression);
        assert!(matches!(config.logging.format, LogFormat::Json));
    }

    #[test]
    fn test_config_builder_partial_configuration() {
        // Test that we can use builder methods to override just some defaults
        let config = Config::default()
            .with_bind_port(9000)
            .with_max_concurrent_requests(500);

        // Check overridden values
        assert_eq!(config.http.bind_port, 9000);
        assert_eq!(config.http.max_concurrent_requests, 500);

        // Check that defaults remain for non-overridden values
        assert_eq!(config.http.bind_addr, "127.0.0.1");
        assert_eq!(config.http.full_bind_addr(), "127.0.0.1:9000");
        assert_eq!(config.http.liveness_route, "/live");
        assert_eq!(config.http.readiness_route, "/ready");
    }

    #[test]
    fn test_load_from_rust_env() {
        unsafe {
            env::set_var("RUST_ENV", "test");
        }

        let result = Config::from_rust_env();
        assert!(
            result.is_ok(),
            "Expected configuration file to load successfully"
        );

        unsafe {
            env::remove_var("RUST_ENV");
        }

        let result = Config::from_rust_env();
        assert!(
            result.is_err(),
            "Expected error when loading non-existent default config file"
        );
    }
}
