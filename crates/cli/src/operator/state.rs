//! Selected-state views: `account get` and `validator status` against the EVM runtime.

use alloy_primitives::U256;
use neutrin0_rpc::client::{NodeApiClient, NodeClient, PinnedBlock};
use neutrin0_rpc::{BlockId, BlockIdJson, BytesHex, HashHex};
use serde_json::{Value, json};

use super::arguments::credentials;
use super::{Arguments, Error, to_value};

pub(super) async fn account(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    let address = credentials(options.required("address")?)?;
    let at = client.pin(options.at()?).await?;
    check_runtime(client, at).await?;
    let account: neutrin0_runtime_abi::ethereum::EvmAccount = client
        .query("evm:account", address[12..].to_vec(), at)
        .await?;
    let account = json!({"nonce": account.nonce, "balance": U256::from_be_bytes(account.balance).to_string(), "code_hash": HashHex(account.code_hash)});
    Ok(json!({"address": BytesHex(address[12..].to_vec()), "at": at, "account": account}))
}

pub(super) async fn validator(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    let local = client.rpc().diagnostics().await?;
    let Some(address) = options.get("address") else {
        return to_value(local);
    };
    let address = credentials(address)?;
    let at = client.pin(options.at()?).await?;
    check_runtime(client, at).await?;
    let (record, queue, registration): (
        Option<neutrin0_runtime_system::Validator>,
        neutrin0_runtime_system::WithdrawalQueue,
        Option<neutrin0_runtime_system::ValidatorRegistration>,
    ) = tokio::try_join!(
        client.query("validator_get", address.to_vec(), at),
        client.query("pending_withdrawals", address.to_vec(), at),
        client.query("validator_registration", address.to_vec(), at)
    )?;
    let withdrawals: Vec<_> = queue.entries.iter().map(|entry| json!({"amount": entry.amount.to_string(), "mature_at_height": entry.mature_at_height, "matured": at.height >= entry.mature_at_height})).collect();
    let registration = registration.map(|registration| json!({"public_key": BytesHex(registration.bls_pubkey.to_vec()), "registered_at_height": registration.registered_at_height}));
    // The consensus endpoint observes the current committee independently of selected runtime state.
    let committee: Vec<_> = client
        .rpc()
        .validators()
        .await?
        .into_iter()
        .filter(|validator| validator.withdrawal_credentials.0 == address)
        .collect();
    let queue = client
        .rpc()
        .storage(
            BytesHex(neutrin0_runtime_system::accountability::QUEUE_KEY.to_vec()),
            BlockIdJson(BlockId::Hash(at.hash.0)),
        )
        .await?;
    let sanctions: Vec<neutrin0_runtime_system::accountability::PendingSanction> = queue
        .map_or(Ok(vec![]), |bytes| borsh::from_slice(&bytes.0))
        .map_err(|error| Error::Local(format!("invalid sanction queue: {error}")))?;
    let held = sanctions
        .iter()
        .any(|pending| pending.sanction.offender.withdrawal_credentials == address);
    Ok(
        json!({"at": at, "address": HashHex(address), "validator": record.map(|validator| json!({"stake": validator.stake.to_string(), "active": validator.stake > 0})),
        "withdrawals": withdrawals, "withdrawals_held": held, "registration": registration, "current_committee": committee}),
    )
}

/// The installed runtime at `at` must be the EVM runtime this tooling speaks.
pub(super) async fn check_runtime(client: &NodeClient, at: PinnedBlock) -> Result<(), Error> {
    let info: neutrin0_primitives::RuntimeInfo = client.query("runtime_info", vec![], at).await?;
    if info.spec_name == *b"NEUTRIN0_EVM\0\0\0\0" {
        Ok(())
    } else {
        Err(Error::Usage(
            "the installed runtime at the selected block is not the EVM runtime".into(),
        ))
    }
}
