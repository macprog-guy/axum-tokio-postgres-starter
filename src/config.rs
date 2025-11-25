#![allow(unused)]
use {
    crate::{Error, Result},
    deadpool_postgres::Pool,
    regex::{Captures, Regex},
    serde::Deserialize,
    std::{env, fs, str::FromStr, sync::LazyLock, time::Duration},
};

static HANDLEBAR_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\s*([A-Z0-9_]+)\s*\}\}").unwrap());

#[derive(Debug)]
pub enum RuntimeEnv {
    Dev,
    Tuni,
    Intg,
    Ctlq,
    CtlqM1,
    Prod,
    ProdM1,
}

impl RuntimeEnv {
    fn as_str(&self) -> &'static str {
        match self {
            RuntimeEnv::Dev => "dev",
            RuntimeEnv::Tuni => "tuni",
            RuntimeEnv::Intg => "intg",
            RuntimeEnv::Ctlq => "ctlq",
            RuntimeEnv::CtlqM1 => "ctlq-m1",
            RuntimeEnv::Prod => "prod",
            RuntimeEnv::ProdM1 => "prod-m1",
        }
    }
}

impl FromStr for RuntimeEnv {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "dev" => Ok(RuntimeEnv::Dev),
            "tuni" => Ok(RuntimeEnv::Tuni),
            "intg" => Ok(RuntimeEnv::Intg),
            "ctlq" => Ok(RuntimeEnv::Ctlq),
            "ctlq-m1" | "ctlqm1" => Ok(RuntimeEnv::CtlqM1),
            "prod" => Ok(RuntimeEnv::Prod),
            "prod-m1" | "prodm1" => Ok(RuntimeEnv::ProdM1),
            _ => Err(Error::UnsupportedEnv(s.into())),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Config {
    pub database: DatabaseConfig,
    pub http: HttpConfig,
    pub logging: LoggingConfig,
}

///
/// Configuration for the database connection pool.
///
#[derive(Debug, Deserialize)]
pub struct DatabaseConfig {
    /// Database connection URL.
    /// This should be a valid Postgres connection string in URL format.
    /// For example, "postgres://user:password@localhost:5432/database".
    /// This value is required.
    pub url: String,
    #[serde(default = "default_max_pool_size")]

    /// Sets the maximum number of connections in the pool.
    /// By default `max_pool_size` is set to 2.
    pub max_pool_size: u8,

    /// Maximum idle time for connections in the pool.
    /// Connections that have been idle for longer than this duration
    /// will be closed. For example, a value of "5m" would set the
    /// maximum idle time to 5 minutes. By default `max_idle_time` is None.
    #[serde(default, with = "humantime_serde")]
    pub max_idle_time: Option<Duration>,
}

///
/// Configuration for the HTTP server
///
/// This configuration includes many settings that control the behavior
/// of the HTTP server, including binding address and port, request limits,
/// timeouts, and specific route paths.
///
#[derive(Debug, Deserialize)]
pub struct HttpConfig {
    /// IP address to bind the HTTP server to
    /// The default `bind_addr` is "127.0.0.1".
    #[serde(default = "default_bind_addr")]
    pub bind_addr: String,

    /// Port to bind the HTTP server to
    /// The default `bind_port` is 3000.
    #[serde(default = "default_bind_port")]
    pub bind_port: u16,

    /// Maximum number of concurrent requests to handle.
    /// If the number of concurrent requests exceeds this number, new requests
    /// will be rejected with a 503 Service Unavailable response.
    /// By default `max_concurrent_requests` is set to 2048.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,

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

    /// Whether or not to trim trailing slashes from the request path.
    /// By default `trim_trailing_slash` is set to true.
    #[serde(default = "default_trim_trailing_slash")]
    pub trim_trailing_slash: bool,

    /// Configuration for specific HTTP routes
    pub routes: HttpRoutesConfig,
}

#[derive(Debug, Deserialize)]
pub struct HttpRoutesConfig {
    /// Route for liveness checks.
    /// By default `liveness` is "/live".
    #[serde(default = "default_health_route")]
    pub liveness: String,

    /// Route for readiness checks.
    /// The readiness check will return a 429 Too Many Requests when unable
    /// to handle the load. By default `readiness` is set to "/ready".
    #[serde(default = "default_readiness_route")]
    pub readiness: String,

    /// Route for metrics.
    /// Our Kubernetes infrastructure can scrape this endpoint for
    /// Prometheus metrics. By default `metrics` is set to "/metrics".
    #[serde(default = "default_metrics_route")]
    pub metrics: String,
}

///
/// Configuration for logging and tracing.
///
#[derive(Debug, Deserialize)]
pub struct LoggingConfig {
    /// Format for log output.
    /// The default format is `default`, which is "full" human-readable format.
    /// Other options are `json`, `compact`, and `pretty`.
    pub format: LogFormat,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Default,
    Compact,
    Pretty,
}

#[derive(Debug, Deserialize)]
pub struct HttpAuthConfig {
    /// Configuration for OIDC authentication
    #[serde(default)]
    pub oidc: Option<HttpAuthOidcConfig>,
}

///
/// Configuration for OIDC authentication.
///
#[derive(Debug, Deserialize)]
pub struct HttpAuthOidcConfig {
    issuer_url: String,
    client_id: String,
    client_secret: String,
    callback_url: String,
    state: bool,
    pkce: bool,
}

fn default_max_pool_size() -> u8 {
    2
}

fn default_bind_addr() -> String {
    "127.0.0.1".into()
}

fn default_bind_port() -> u16 {
    3000
}

fn default_max_concurrent_requests() -> usize {
    2048
}

fn default_max_payload_size_bytes() -> byte_unit::Byte {
    byte_unit::Byte::from_u64(256 * 1024)
}

fn default_health_route() -> String {
    "/live".into()
}

fn default_readiness_route() -> String {
    "/ready".into()
}

fn default_metrics_route() -> String {
    "/metrics".into()
}

fn default_trim_trailing_slash() -> bool {
    true
}

///
/// Given an [`RuntimeEnv`], loads the corresponding configuration file,
/// substitutes any environment variables, and returns a Config struct.
///
pub fn load_config_for_env(env: RuntimeEnv) -> Result<Config> {
    let path = format!("config/{}.toml", env.as_str());
    let text = fs::read_to_string(path)?;
    text.parse()
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
/// Looks through the input string for any {{ VAR_NAME }} patterns
/// and substitutes them with the corresponding environment variable value.
///
pub fn replace_handlebars_with_env(input: &str) -> String {
    HANDLEBAR_REGEXP
        .replace_all(input, |caps: &Captures| {
            env::var(&caps[1]).unwrap_or_default()
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runtime_env_from_str() {
        assert!(matches!(
            "dev".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Dev
        ));
        assert!(matches!(
            "Dev".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Dev
        ));
        assert!(matches!(
            "DEV".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Dev
        ));
        assert!(matches!(
            "tuni".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Tuni
        ));
        assert!(matches!(
            "intg".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Intg
        ));
        assert!(matches!(
            "ctlq".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Ctlq
        ));
        assert!(matches!(
            "ctlq-m1".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::CtlqM1
        ));
        assert!(matches!(
            "ctlqm1".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::CtlqM1
        ));
        assert!(matches!(
            "prod".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::Prod
        ));
        assert!(matches!(
            "prod-m1".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::ProdM1
        ));
        assert!(matches!(
            "prodm1".parse::<RuntimeEnv>().unwrap(),
            RuntimeEnv::ProdM1
        ));
    }

    #[test]
    fn test_runtime_env_from_str_invalid() {
        assert!("invalid".parse::<RuntimeEnv>().is_err());
        assert!("".parse::<RuntimeEnv>().is_err());
        assert!("production".parse::<RuntimeEnv>().is_err());
    }

    #[test]
    fn test_runtime_env_as_str() {
        assert_eq!(RuntimeEnv::Dev.as_str(), "dev");
        assert_eq!(RuntimeEnv::Tuni.as_str(), "tuni");
        assert_eq!(RuntimeEnv::Intg.as_str(), "intg");
        assert_eq!(RuntimeEnv::Ctlq.as_str(), "ctlq");
        assert_eq!(RuntimeEnv::CtlqM1.as_str(), "ctlq-m1");
        assert_eq!(RuntimeEnv::Prod.as_str(), "prod");
        assert_eq!(RuntimeEnv::ProdM1.as_str(), "prod-m1");
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
            env::set_var("DB_URL", "postgres://localhost/test");
        }

        let config_str = r#"
[database]
url = "{{ DB_URL }}"
max_pool_size = 10

[http]
bind_addr = "0.0.0.0"
bind_port = 8080
max_payload_size_bytes = "1MB"

[http.routes]
liveness = "/health"
metrics = "/metrics"

[http.auth.oidc]
issuer_url = "https://keycloak.pictet.aws/realms/pictet"
client_id = "one-environment-pkce"
client_secret = "{{ OIDC_SECRET }}"
callback_url = "http://localhost:3000/auth/callback"
state = true
pkce = true

[logging]
format = "json"
        "#;

        let config = config_str.parse::<Config>();
        eprintln!("{:?}", config);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert_eq!(config.database.url, "postgres://localhost/test");
        assert_eq!(config.http.bind_addr, "0.0.0.0");
        assert_eq!(config.http.bind_port, 8080);

        unsafe {
            env::remove_var("DB_URL");
        }
    }

    #[test]
    fn test_config_from_str_invalid_toml() {
        let invalid_config = "this is not valid toml";
        let result = invalid_config.parse::<Config>();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_from_str_missing_required_fields() {
        let incomplete_config = r#"
[database]
url = "postgres://localhost/test"
        "#;

        let result = incomplete_config.parse::<Config>();
        assert!(result.is_err());
    }
}
