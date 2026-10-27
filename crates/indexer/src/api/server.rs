//! Bounded HTTP transport and configurable browser origin policy.
use super::{IndexerSchema, gql};
use crate::{Error, Result, config::Config, db::Store};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tower_http::cors::CorsLayer;
#[derive(Clone)]
struct HttpState {
    store: Store,
    schema: IndexerSchema,
    permits: Arc<Semaphore>,
}
/// Build the independent query router; every data request owns one immutable database snapshot.
pub fn router(store: Store, config: &Config) -> Result<Router> {
    let state = HttpState {
        store,
        schema: super::schema(),
        permits: Arc::new(Semaphore::new(8)),
    };
    let origins = config
        .cors_origins
        .iter()
        .map(|origin| {
            if origin == "*" {
                return Err(Error::Config("CORS requires exact origins".into()));
            }
            HeaderValue::from_str(origin).map_err(|_| Error::Config("invalid CORS origin".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([axum::http::header::CONTENT_TYPE])
        .allow_origin(origins);
    Ok(Router::new()
        .route("/graphql", post(graphql))
        .route("/graphql/schema", get(sdl))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(cors)
        .with_state(state))
}
async fn graphql(
    State(state): State<HttpState>,
    Json(request): Json<async_graphql::Request>,
) -> impl IntoResponse {
    let Ok(permit) = state.permits.clone().try_acquire_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(serde_json::json!({"errors":[{"message":"query concurrency limit reached"}]})),
        )
            .into_response();
    };
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let view = state.store.read_view().await.map_err(gql)?;
        Ok::<_, async_graphql::Error>(state.schema.execute(request.data(view)).await)
    })
    .await;
    drop(permit);
    let response = match response {
        Ok(Ok(response)) => serde_json::to_vec(&response),
        Ok(Err(error)) => serde_json::to_vec(
            &serde_json::json!({"errors":[{"message":error.message,"extensions":error.extensions}]}),
        ),
        Err(_) => {
            return (
                StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({"errors":[{"message":"query deadline exceeded"}]})),
            )
                .into_response();
        }
    };
    match response {
        Ok(bytes) if bytes.len()<=4*1024*1024=>([(axum::http::header::CONTENT_TYPE,"application/json")],bytes).into_response(),
        _=>(StatusCode::PAYLOAD_TOO_LARGE,Json(serde_json::json!({"errors":[{"message":"query response exceeds 4 MiB; narrow the selection/page"}]}))).into_response(),
    }
}
async fn sdl(State(state): State<HttpState>) -> String {
    state.schema.sdl()
}
async fn live() -> Json<serde_json::Value> {
    Json(serde_json::json!({"service":"neutrin0-indexer","alive":true}))
}
async fn ready(State(state): State<HttpState>) -> impl IntoResponse {
    match tokio::time::timeout(std::time::Duration::from_secs(5), state.store.ready()).await {
        Ok(Ok(true)) => (StatusCode::OK, Json(serde_json::json!({"ready":true}))),
        _ => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"ready":false})),
        ),
    }
}
