use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Database pool configuration error: {0}")]
    PoolConfig(#[from] deadpool_postgres::ConfigError),
    #[error("Database pool error: {0}")]
    PoolGet(#[from] deadpool_postgres::PoolError),
    #[error("Database pool error: {0}")]
    PoolCreate(#[from] deadpool_postgres::CreatePoolError),
    #[error("Database error: {0}")]
    Database(#[from] tokio_postgres::Error),
    #[error("Configuration error: {0}")]
    Config(#[from] toml::de::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Unknown environment variable: {0}")]
    UnknownEnv(#[from] std::env::VarError),
    #[error("Unsupported runtime environment: {0}")]
    UnsupportedEnv(String),
    #[error("Other error: {0}")]
    Other(String),
}
