use {
    http::{HeaderValue, Request},
    regex::{Captures, Regex},
    serde::Deserialize,
    std::{env, sync::LazyLock},
    tower_http::request_id::{MakeRequestId, RequestId},
    uuid::{ContextV7, Timestamp, Uuid},
};

static HANDLEBAR_REGEXP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{\{\s*([A-Z0-9_]+)\s*\}\}").unwrap());

///
/// Simple wrapper around sensitive secrets.
///
#[derive(Clone, Deserialize, Default)]
pub struct Sensitive<T: Default>(pub T);

impl Sensitive<String> {
    pub fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl<T: Default + PartialEq> PartialEq for Sensitive<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Default> std::fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sensitive(****)")
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RequestIdGenerator;

impl MakeRequestId for RequestIdGenerator {
    fn make_request_id<B>(&mut self, req: &Request<B>) -> Option<RequestId> {
        match req.headers().get("x-request-id") {
            Some(value) => Some(RequestId::new(value.clone())),
            None => {
                let cx = ContextV7::new().with_additional_precision();
                let uuid = Uuid::new_v7(Timestamp::now(cx));
                let value = HeaderValue::from_str(&uuid.to_string()).ok()?;
                Some(RequestId::new(value))
            }
        }
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
