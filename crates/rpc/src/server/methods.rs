//! Canonical JSON-RPC method registration and parameter parsing.

use jsonrpsee::server::RpcModule;
use jsonrpsee::types::ErrorObjectOwned;

use crate::backend::BlockId;
use crate::types::{
    BlockIdJson, BlockJson, BytesHex, FinalizedInfoJson, HashHex, HeadInfoJson, HeaderJson,
    HealthJson, RuntimeCallResultJson, SubmitResultJson, SystemInfoJson, ValidatorJson,
};

use super::errors::{
    RUNTIME_TIMEOUT_CODE, invalid_params, query_err, reg_err, runtime_err, submit_err,
};
use super::{RpcContext, RpcStartError};

pub(super) fn register_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    super::ethereum::register(module)?;
    super::consensus::register(module)?;
    register_system_methods(module)?;
    register_chain_methods(module)?;
    register_state_methods(module)?;
    register_mempool_methods(module)?;
    register_runtime_methods(module)?;
    register_history_methods(module)?;
    Ok(())
}

fn register_system_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("system_diagnostics", |_, ctx, _| async move {
            ctx.backend()
                .diagnostics()
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("system_chainId", |_, ctx, _| async move {
            Ok::<_, ErrorObjectOwned>(ctx.backend().chain_id())
        })
        .map_err(reg_err)?;

    module
        .register_async_method("system_health", |_, ctx, _| async move {
            let head = ctx
                .backend()
                .head()
                .await
                .map_err(|error| query_err(&error))?;
            ctx.blocking(move |backend| HealthJson {
                peers: backend.peer_count(),
                is_syncing: backend.is_syncing(),
                runtime_available: backend.runtime_available(),
                mempool: u64::try_from(backend.mempool_len()).unwrap_or(u64::MAX),
                head_height: head.height,
            })
            .await
        })
        .map_err(reg_err)?;

    module
        .register_async_method("system_info", |_, ctx, _| async move {
            ctx.blocking(|backend| SystemInfoJson {
                runtime_code_hash: backend.runtime_code_hash().map(HashHex::from),
            })
            .await
        })
        .map_err(reg_err)?;

    module
        .register_async_method("programs_status", |_, ctx, _| async move {
            ctx.blocking(crate::backend::RpcBackend::programs_status)
                .await
        })
        .map_err(reg_err)?;

    module
        .register_async_method("proving_status", |_, ctx, _| async move {
            ctx.blocking(crate::backend::RpcBackend::proving_status)
                .await
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_chain_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("chain_getGenesis", |_, ctx, _| async move {
            ctx.backend()
                .genesis_info()
                .await
                .map(|genesis| genesis.map(crate::types::GenesisInfoJson::from))
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("chain_head", |_, ctx, _| async move {
            let head = ctx
                .backend()
                .head()
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(HeadInfoJson::from(head))
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_finalized", |_, ctx, _| async move {
            let fin = ctx
                .backend()
                .finalized()
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(FinalizedInfoJson::from(fin))
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getHeader", |params, ctx, _| async move {
            let at: BlockIdJson = parse_optional_block_id(&params)?;
            let Some(hash) = resolve(&ctx, &at.0).await? else {
                return Ok::<_, ErrorObjectOwned>(None);
            };
            Ok::<_, ErrorObjectOwned>(
                ctx.backend()
                    .header_by_hash(hash)
                    .await
                    .map_err(|error| query_err(&error))?
                    .map(|h| HeaderJson::from(&h)),
            )
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getBlock", |params, ctx, _| async move {
            let at: BlockIdJson = parse_optional_block_id(&params)?;
            let Some(hash) = resolve(&ctx, &at.0).await? else {
                return Ok::<_, ErrorObjectOwned>(None);
            };
            Ok::<_, ErrorObjectOwned>(
                ctx.backend()
                    .block_by_hash(hash)
                    .await
                    .map_err(|error| query_err(&error))?
                    .map(|b| BlockJson::from(&b)),
            )
        })
        .map_err(reg_err)?;

    module
        .register_async_method("chain_getValidatorSet", |_, ctx, _| async move {
            let validators = ctx.backend().active_validator_set().await;
            Ok::<_, ErrorObjectOwned>(
                validators
                    .iter()
                    .map(ValidatorJson::from)
                    .collect::<Vec<_>>(),
            )
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_state_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("state_getStorage", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct StorageParams {
                key: BytesHex,
                #[serde(default)]
                at: BlockIdJson,
            }
            let p: StorageParams = params.parse().map_err(invalid_params)?;
            let value = ctx
                .backend()
                .storage_at(&p.key.0, &p.at.0)
                .await
                .map_err(|error| query_err(&error))?;
            Ok::<_, ErrorObjectOwned>(value.map(BytesHex::from))
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_mempool_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("mempool_submitTransaction", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct SubmitParams {
                bytes: BytesHex,
            }
            let p: SubmitParams = params.parse().map_err(invalid_params)?;
            match ctx.backend().submit_transaction(p.bytes.0).await {
                Ok(hash) => Ok::<_, ErrorObjectOwned>(SubmitResultJson::new(hash)),
                Err(err) => Err(submit_err(&err)),
            }
        })
        .map_err(reg_err)?;

    module
        .register_async_method("mempool_status", |_, ctx, _| async move {
            #[derive(Clone, serde::Serialize)]
            struct MempoolStatus {
                pending: u64,
            }
            Ok::<_, ErrorObjectOwned>(MempoolStatus {
                pending: u64::try_from(ctx.backend().mempool_len()).unwrap_or(u64::MAX),
            })
        })
        .map_err(reg_err)?;

    Ok(())
}

fn register_runtime_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("runtime_call", |params, ctx, _| async move {
            #[derive(serde::Deserialize)]
            struct CallParams {
                method: String,
                #[serde(default)]
                args: BytesHex,
                #[serde(default)]
                at: BlockIdJson,
            }
            let p: CallParams = params.parse().map_err(invalid_params)?;
            if ["evm:pending", "runtime:select_transactions"].contains(&p.method.as_str()) {
                return Err(invalid_params(
                    "consensus-context operations are internal node calls",
                ));
            }
            let call = ctx.backend().runtime_call(p.method, p.args.0, &p.at.0);
            match tokio::time::timeout(ctx.runtime_call_timeout, call).await {
                Ok(Ok(resp)) => Ok::<_, ErrorObjectOwned>(RuntimeCallResultJson {
                    code: resp.code,
                    payload: BytesHex(resp.payload),
                    gas_used: resp.gas_used,
                }),
                Ok(Err(err)) => Err(runtime_err(&err)),
                Err(_) => Err(ErrorObjectOwned::owned(
                    RUNTIME_TIMEOUT_CODE,
                    "runtime_call timed out",
                    None::<()>,
                )),
            }
        })
        .map_err(reg_err)?;

    Ok(())
}

/// Resolve a [`BlockId`] to a block hash by asking the backend.
async fn resolve(ctx: &RpcContext, at: &BlockId) -> Result<Option<[u8; 32]>, ErrorObjectOwned> {
    ctx.backend()
        .resolve_block_id(at)
        .await
        .map_err(|error| query_err(&error))
}

/// Parse the optional `BlockIdJson` parameter; default to `Latest`.
///
/// Accepts either named (`{"at": ...}`) or positional (`[<id>]` /
/// empty `[]`) parameters so clients can use whichever style is
/// idiomatic for their JSON-RPC library.
fn parse_optional_block_id(
    params: &jsonrpsee::types::Params<'_>,
) -> Result<BlockIdJson, ErrorObjectOwned> {
    if params.is_object() {
        #[derive(serde::Deserialize)]
        struct Wrapped {
            #[serde(default)]
            at: BlockIdJson,
        }
        let w: Wrapped = params.parse().map_err(invalid_params)?;
        Ok(w.at)
    } else {
        let mut seq = params.sequence();
        let opt: Option<BlockIdJson> = seq.optional_next().map_err(invalid_params)?;
        Ok(opt.unwrap_or_default())
    }
}

fn register_history_methods(module: &mut RpcModule<RpcContext>) -> Result<(), RpcStartError> {
    module
        .register_async_method("history_getRetention", |_, ctx, _| async move {
            ctx.backend()
                .history_retention()
                .await
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    module
        .register_async_method("history_getLatest", |_, ctx, _| async move {
            ctx.backend
                .history_latest()
                .await
                .map(BytesHex)
                .map_err(|error| query_err(&error))
        })
        .map_err(reg_err)?;
    Ok(())
}
