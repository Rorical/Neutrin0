use super::super::errors::runtime_err;
use super::*;
use crate::backend::{QueryError, RuntimeCallError};
use std::time::Duration;

#[test]
fn token_bucket_allows_burst_then_refills() {
    let mut bucket = TokenBucket::new(10);
    // Burst capacity is twice the rate.
    assert!((0..20).all(|_| bucket.try_take(1.0)));
    assert!(!bucket.try_take(1.0));
    // Simulate half a second elapsing: five tokens come back.
    bucket.last -= Duration::from_millis(500);
    assert!((0..5).all(|_| bucket.try_take(1.0)));
    assert!(!bucket.try_take(1.0));
    // Refill never exceeds capacity.
    bucket.last -= Duration::from_secs(60);
    assert!((0..20).all(|_| bucket.try_take(1.0)));
    assert!(!bucket.try_take(1.0));
}

#[test]
fn admit_reports_rate_limit_and_busy_distinctly() {
    let governor = RequestGovernor::new((), Arc::default(), RequestLimits::new(2, 50, 4));
    let first = governor.admit(Budget::Connection(1), 1).unwrap();
    let second = governor.admit(Budget::Connection(1), 1).unwrap();
    // Permits are exhausted while two requests are in flight.
    assert_eq!(
        governor.admit(Budget::Connection(1), 1).unwrap_err().code(),
        -32005
    );
    drop(first);
    drop(second);
    assert!(governor.admit(Budget::Connection(1), 1).is_ok());
    // A batch larger than the whole burst budget is rate limited.
    assert_eq!(
        governor
            .admit(Budget::Connection(1), 1_000)
            .unwrap_err()
            .code(),
        -32006
    );
    // Connections are isolated: draining one leaves another untouched.
    // Four tokens are gone already: two admitted, one refused for lack of
    // a permit (still charged) and one admitted after the permits freed.
    for _ in 0..96 {
        drop(governor.admit(Budget::Connection(1), 1).unwrap());
    }
    assert_eq!(
        governor.admit(Budget::Connection(1), 1).unwrap_err().code(),
        -32006
    );
    assert!(governor.admit(Budget::Connection(2), 1).is_ok());
}

#[test]
fn bucket_table_evicts_oldest_connections() {
    let mut table = BucketTable::new(1, 2);
    assert!(table.try_take(Budget::Connection(1), 2.0));
    assert!(!table.try_take(Budget::Connection(1), 1.0));
    assert!(table.try_take(Budget::Connection(2), 1.0));
    // A third connection evicts connection 1; it then starts fresh.
    assert!(table.try_take(Budget::Connection(3), 1.0));
    assert_eq!(table.buckets.len(), 2);
    assert!(table.try_take(Budget::Connection(1), 1.0));
}

#[test]
fn a_client_draws_one_budget_across_its_connections() {
    let client = ClientIp("192.0.2.7".parse().unwrap());
    let budget = |connection: usize, client: Option<ClientIp>| {
        let mut extensions = http::Extensions::new();
        extensions.insert(ConnectionId(connection));
        if let Some(client) = client {
            extensions.insert(client);
        }
        Budget::of(&extensions)
    };
    assert_eq!(budget(1, Some(client)), budget(2, Some(client)));
    assert_eq!(budget(1, None), Budget::Connection(1));
    assert_ne!(budget(1, None), budget(2, None));
}

#[test]
fn batch_metrics_do_not_treat_internal_failure_as_success() {
    assert_eq!(
        batch_error_code(
            r#"[{"id":1,"result":{"ignored":[1,2,3]}},{"id":2,"error":{"code":-32601,"message":"unknown"}}]"#
        ),
        Some(-32601)
    );
    assert_eq!(
        batch_error_code(r#"[{"id":1,"error":{"code":-32601}},{"id":2,"error":{"code":-32012}}]"#),
        Some(-32012)
    );
    assert_eq!(batch_error_code(r#"[{"id":1,"result":"ok"}]"#), None);
    assert_eq!(batch_error_code("[] trailing"), Some(-32603));
}

#[test]
fn runtime_execution_failures_are_not_classified_as_timeouts() {
    let trap = RuntimeCallError::Runtime("wasm trap: unreachable".to_owned());
    let failure = runtime_err(&trap);
    assert_eq!(failure.code(), -32014);
    assert_ne!(failure.code(), RUNTIME_TIMEOUT_CODE);
    for (error, code) in [
        (RuntimeCallError::RuntimeNotConfigured, -32010),
        (RuntimeCallError::Decode("truncated".to_owned()), -32013),
        (RuntimeCallError::Query(QueryError::BlockNotFound), -32020),
    ] {
        assert_eq!(runtime_err(&error).code(), code);
        assert_ne!(code, RUNTIME_TIMEOUT_CODE);
    }

    // A runtime failure in a batch does not take the timeout's precedence.
    assert_eq!(
        batch_error_code(r#"[{"id":1,"error":{"code":-32601}},{"id":2,"error":{"code":-32014}}]"#),
        Some(-32601)
    );
    assert_eq!(
        batch_error_code(r#"[{"id":1,"error":{"code":-32014}},{"id":2,"error":{"code":-32012}}]"#),
        Some(RUNTIME_TIMEOUT_CODE)
    );

    let metrics = Arc::new(crate::metrics::RpcMetrics::default());
    let runtime = crate::metrics::RpcMetrics::kind("runtime_call");
    metrics.begin(runtime).finish(Some(failure.code()));
    metrics.begin(runtime).finish(Some(RUNTIME_TIMEOUT_CODE));
    let batch = batch_error_code(r#"[{"id":1,"error":{"code":-32014}}]"#);
    metrics.begin(crate::metrics::BATCH).finish(batch);
    let mut out = String::new();
    metrics.render(&mut out);
    assert!(out.contains("family=\"runtime\",outcome=\"failed\"} 1"));
    assert!(out.contains("family=\"runtime\",outcome=\"timeout\"} 1"));
    assert!(out.contains("family=\"batch\",outcome=\"failed\"} 1"));
    assert!(out.contains("family=\"batch\",outcome=\"timeout\"} 0"));
}
