//! Request admission, per-client rate limits and transport observations.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use jsonrpsee::server::ConnectionId;
use jsonrpsee::server::middleware::rpc::{
    Batch, MethodResponse, Notification, Request, RpcServiceT,
};
use jsonrpsee::types::{ErrorObjectOwned, Id};

use super::clients::ClientIp;
use super::errors::{BUSY_CODE, RATE_LIMITED_CODE, RUNTIME_TIMEOUT_CODE};

/// Shared admission state reused by every HTTP request and connection.
#[derive(Clone)]
pub(super) struct RequestLimits {
    permits: Arc<tokio::sync::Semaphore>,
    buckets: Arc<Mutex<BucketTable>>,
}

impl RequestLimits {
    pub(super) fn new(
        max_concurrent_requests: u32,
        requests_per_second_per_client: u32,
        max_connections: u32,
    ) -> Self {
        let permits = Arc::new(tokio::sync::Semaphore::new(
            usize::try_from(max_concurrent_requests.max(1)).unwrap_or(usize::MAX),
        ));
        // HTTP builds the middleware per request, so per-client state lives in
        // one shared table keyed by the client the listener attached; the
        // execution permits are shared process-wide.
        let buckets = Arc::new(Mutex::new(BucketTable::new(
            requests_per_second_per_client.max(1),
            usize::try_from(max_connections.max(1))
                .unwrap_or(usize::MAX)
                .saturating_mul(4),
        )));
        Self { permits, buckets }
    }
}

/// Per-connection token bucket: `rate` tokens per second, burst of twice
/// the rate. Refill is computed lazily on each request.
#[derive(Debug)]
struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let rate = f64::from(rate);
        Self {
            capacity: rate * 2.0,
            tokens: rate * 2.0,
            refill_per_sec: rate,
            last: Instant::now(),
        }
    }

    fn try_take(&mut self, cost: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = elapsed
            .mul_add(self.refill_per_sec, self.tokens)
            .min(self.capacity);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Whose budget a request draws on: its client, or, for a request served
/// without one (in-process), its connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Budget {
    Client(std::net::IpAddr),
    Connection(usize),
}

impl Budget {
    fn of(extensions: &http::Extensions) -> Self {
        extensions.get::<ClientIp>().map_or_else(
            || {
                Self::Connection(
                    extensions
                        .get::<ConnectionId>()
                        .map_or(ANONYMOUS_CONNECTION, |id| id.0),
                )
            },
            |client| Self::Client(client.0),
        )
    }
}

/// Token buckets keyed by budget, bounded by evicting the oldest entries
/// once `capacity` distinct budgets have been seen.
#[derive(Debug)]
struct BucketTable {
    rate: u32,
    capacity: usize,
    buckets: std::collections::HashMap<Budget, TokenBucket>,
    order: std::collections::VecDeque<Budget>,
}

impl BucketTable {
    fn new(rate: u32, capacity: usize) -> Self {
        Self {
            rate,
            capacity: capacity.max(1),
            buckets: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn try_take(&mut self, conn: Budget, cost: f64) -> bool {
        if !self.buckets.contains_key(&conn) {
            while self.buckets.len() >= self.capacity {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.buckets.remove(&oldest);
            }
            self.buckets.insert(conn, TokenBucket::new(self.rate));
            self.order.push_back(conn);
        }
        self.buckets
            .get_mut(&conn)
            .is_some_and(|bucket| bucket.try_take(cost))
    }
}

/// Connection id used when jsonrpsee attached none to the request.
const ANONYMOUS_CONNECTION: usize = usize::MAX;
/// Rate and concurrency guard applied in front of method dispatch.
#[derive(Clone)]
pub(super) struct RequestGovernor<S> {
    service: S,
    metrics: Arc<crate::metrics::RpcMetrics>,
    limits: RequestLimits,
}

impl<S> RequestGovernor<S> {
    pub(super) const fn new(
        service: S,
        metrics: Arc<crate::metrics::RpcMetrics>,
        limits: RequestLimits,
    ) -> Self {
        Self {
            service,
            metrics,
            limits,
        }
    }

    fn admit(
        &self,
        conn: Budget,
        cost: u32,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, ErrorObjectOwned> {
        let allowed = self
            .limits
            .buckets
            .lock()
            .expect("rpc token buckets poisoned")
            .try_take(conn, f64::from(cost));
        if !allowed {
            return Err(ErrorObjectOwned::owned(
                RATE_LIMITED_CODE,
                "rate limited: per-client request budget exhausted",
                None::<()>,
            ));
        }
        Arc::clone(&self.limits.permits)
            .try_acquire_many_owned(cost)
            .map_err(|_| {
                ErrorObjectOwned::owned(
                    BUSY_CODE,
                    "server busy: too many requests in flight",
                    None::<()>,
                )
            })
    }
}

impl<S> RpcServiceT for RequestGovernor<S>
where
    S: RpcServiceT<
            MethodResponse = MethodResponse,
            BatchResponse = MethodResponse,
            NotificationResponse = MethodResponse,
        > + Send
        + Sync
        + Clone
        + 'static,
{
    type MethodResponse = MethodResponse;
    type NotificationResponse = MethodResponse;
    type BatchResponse = MethodResponse;

    fn call<'a>(&self, request: Request<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let conn = Budget::of(request.extensions());
        let observation = self
            .metrics
            .begin(crate::metrics::RpcMetrics::kind(request.method_name()));
        let admitted = self.admit(conn, 1);
        let service = self.service.clone();
        async move {
            let response = match admitted {
                Ok(_permit) => service.call(request).await,
                Err(error) => MethodResponse::error(request.id(), error),
            };
            observation.finish(response.as_error_code());
            response
        }
    }

    fn batch<'a>(&self, requests: Batch<'a>) -> impl Future<Output = MethodResponse> + Send + 'a {
        let mut requests = requests;
        let conn = Budget::of(requests.extensions());
        let cost = u32::try_from(requests.len()).unwrap_or(u32::MAX).max(1);
        let observation = self.metrics.begin(crate::metrics::BATCH);
        let admitted = self.admit(conn, cost);
        let service = self.service.clone();
        async move {
            let response = match admitted {
                Ok(_permit) => service.batch(requests).await,
                Err(error) => MethodResponse::error(Id::Null, error),
            };
            observation.finish(if response.is_batch() {
                batch_error_code(response.as_ref())
            } else {
                response.as_error_code()
            });
            response
        }
    }

    fn notification<'a>(
        &self,
        n: Notification<'a>,
    ) -> impl Future<Output = MethodResponse> + Send + 'a {
        let observation = self.metrics.begin(crate::metrics::NOTIFICATION);
        let future = self.service.notification(n);
        async move {
            let response = future.await;
            observation.finish(response.as_error_code());
            response
        }
    }
}

// jsonrpsee marks a transport batch successful even when its individual
// responses failed. Result payloads are skipped; only error codes are kept.
// The first error classifies the batch unless a `runtime_call` deadline
// expired, which takes precedence.
fn batch_error_code(json: &str) -> Option<i32> {
    #[derive(serde::Deserialize)]
    struct ErrorCode {
        code: i32,
    }
    #[derive(serde::Deserialize)]
    struct Verdict {
        error: Option<ErrorCode>,
    }
    let Ok(verdicts) = serde_json::from_str::<Vec<Verdict>>(json) else {
        return Some(-32603);
    };
    verdicts
        .into_iter()
        .filter_map(|verdict| verdict.error.map(|error| error.code))
        .fold(None, |code, next| {
            (code.is_none() || next == RUNTIME_TIMEOUT_CODE)
                .then_some(next)
                .or(code)
        })
}

#[cfg(test)]
mod tests;
