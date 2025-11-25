use {
    http::{HeaderValue, Request},
    tower_http::request_id::{MakeRequestId, RequestId},
    uuid::{ContextV7, Timestamp, Uuid},
};

#[derive(Clone)]
pub struct AppState {
    pub dbpool: deadpool_postgres::Pool,
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
