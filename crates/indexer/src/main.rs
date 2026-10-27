#![deny(unsafe_code)]
//! Independent indexer daemon; query-only replicas can use the same PostgreSQL dataset.
use neutrin0_indexer::{
    Error, Result, api,
    config::Config,
    db::Store,
    ingest::Indexer,
    source::{HttpSource, Source},
};
use std::{path::PathBuf, sync::Arc, time::Duration};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error=%error,"indexer stopped");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>().into_iter();
    let mut path = PathBuf::from("indexer.toml");
    let mut serve_only = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => {
                path = PathBuf::from(
                    args.next()
                        .ok_or_else(|| Error::Config("--config requires a file".into()))?,
                );
            }
            "--serve-only" => serve_only = true,
            "--print-schema" => {
                println!("{}", api::schema().sdl());
                return Ok(());
            }
            "--help" | "-h" => {
                println!(
                    "neutrin0-indexer --config indexer.toml [--serve-only]\nneutrin0-indexer --print-schema"
                );
                return Ok(());
            }
            _ => return Err(Error::Config("unknown indexer argument".into())),
        }
    }
    let config = Config::load(&path)?;
    let url = std::env::var(&config.database_url_env).map_err(|_| {
        Error::Config(format!(
            "set {} to a PostgreSQL connection string",
            config.database_url_env
        ))
    })?;
    let store = if serve_only {
        Store::open_read_only(&url, &config.database_schema).await?
    } else {
        Store::open(&url, &config.database_schema).await?
    };
    if let Some(state) = store.state().await?
        && (state.binding.chain_spec_hash
            != neutrin0_indexer::model::hash(&config.chain_spec_hash)?
            || state.binding.decoder_hash != config.decoder_hash()?)
    {
        return Err(Error::Binding(
            "configuration differs from stored index".into(),
        ));
    }
    let router = api::server::router(store.clone(), &config)?;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!(listen=%listener.local_addr()?,schema=%config.database_schema,query_only=serve_only,"indexer query service listening");
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let worker = if serve_only {
        None
    } else {
        let source: Arc<dyn Source> = Arc::new(HttpSource::connect(&config)?);
        let worker_store = store.clone();
        let worker_config = config.clone();
        let worker_shutdown = receiver.clone();
        Some(tokio::spawn(async move {
            worker(worker_config, worker_store, source, worker_shutdown).await;
        }))
    };
    let mut signal = receiver;
    let server = axum::serve(listener, router).with_graceful_shutdown(async move {
        while !*signal.borrow() {
            if signal.changed().await.is_err() {
                break;
            }
        }
    });
    let signal_sender = shutdown.clone();
    let signal_task = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = signal_sender.send(true);
    });
    let result = server.await.map_err(Error::from);
    signal_task.abort();
    let _ = shutdown.send(true);
    if let Some(worker) = worker {
        worker
            .await
            .map_err(|_| Error::Data("ingestion task failed".into()))?;
    }
    store.close().await;
    result
}
async fn worker(
    config: Config,
    store: Store,
    source: Arc<dyn Source>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut indexer = None;
    let mut retry = 1_u64;
    loop {
        if *shutdown.borrow() {
            break;
        }
        let attempt = async {
            if indexer.is_none() {
                indexer =
                    Some(Indexer::new(config.clone(), store.clone(), Arc::clone(&source)).await?);
            }
            let Some(indexer) = indexer.as_mut() else {
                return Err(Error::Data("missing ingestion worker".into()));
            };
            indexer.step().await
        };
        let result = tokio::select! {result=attempt=>result,_=shutdown.changed()=>break};
        let delay = match result {
            Ok(caught_up) => {
                retry = 1;
                if caught_up {
                    Duration::from_secs(config.poll_seconds)
                } else {
                    Duration::from_millis(10)
                }
            }
            Err(error) => {
                tracing::warn!(error=%error,"indexing paused; saved progress retained");
                if let Some(active) = indexer.as_mut() {
                    let _ = active.record_error(&error).await;
                }
                if matches!(error, Error::Database(_)) {
                    indexer = None;
                }
                let delay = Duration::from_secs(retry);
                retry = (retry * 2).min(30);
                delay
            }
        };
        tokio::select! {()=tokio::time::sleep(delay)=>{},_=shutdown.changed()=>break}
    }
}
