//! A collection of node-specific RPC methods.
//! Substrate provides the `sc-rpc` crate, which defines the core RPC layer
//! used by Substrate nodes. This file extends those RPC definitions with
//! capabilities that are specific to this project's runtime configuration.

#![warn(missing_docs)]

use std::sync::Arc;

use jsonrpsee::RpcModule;
use sc_transaction_pool_api::TransactionPool;
use bls_beefer_runtime::{opaque::Block, AccountId, Balance, Nonce};
use sp_api::ProvideRuntimeApi;
use sp_block_builder::BlockBuilder;
use sp_blockchain::{Error as BlockChainError, HeaderBackend, HeaderMetadata};

pub use sc_rpc_api::DenyUnsafe;

use beefy_gadget::notification::BeefySignedCommitmentStream;
use beefy_node_runtime::{opaque::Block, AccountId, Balance, Index};

/// Extra dependencies for BEEFY
pub struct BeefyDeps<B: BlockT> {
    /// Receives notifications about signed commitments from BEEFY.
    pub signed_commitment_stream: BeefySignedCommitmentStream<B>,
    /// Executor to drive the subscription manager in the BEEFY RPC handler.
    pub subscription_executor: SubscriptionTaskExecutor,
}

/// Full client dependencies.
pub struct FullDeps<B: BlockT, C, P> {
    /// The client instance to use.
    pub client: Arc<C>,
    /// Transaction pool instance.
    pub pool: Arc<P>,
    /// Whether to deny unsafe calls
    pub deny_unsafe: DenyUnsafe,
    /// BEEFY specific dependencies.
    pub beefy: BeefyDeps<B>,
}

/// Instantiate all full RPC extensions.
pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    B: BlockT,
    C: ProvideRuntimeApi<Block>,
    C: HeaderBackend<Block> + HeaderMetadata<Block, Error = BlockChainError> + 'static,
    C: Send + Sync + 'static,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<Block, AccountId, Nonce>,
    C::Api: pallet_transaction_payment_rpc::TransactionPaymentRuntimeApi<Block, Balance>,
    C::Api: BlockBuilder<Block>,
    P: TransactionPool + 'static,
{
    use pallet_transaction_payment_rpc::{TransactionPayment, TransactionPaymentApiServer};
    use substrate_frame_rpc_system::{System, SystemApiServer};

    let mut io = jsonrpc_core::IoHandler::default();
    let FullDeps {
        client,
        pool,
        deny_unsafe,
        beefy,
    } = deps;

    let BeefyDeps {
        signed_commitment_stream,
        subscription_executor,
    } = beefy;

    io.extend_with(SystemApi::to_delegate(FullSystem::new(
        client.clone(),
        pool,
        deny_unsafe,
    )));

    module.merge(System::new(client.clone(), pool, deny_unsafe).into_rpc())?;
    module.merge(TransactionPayment::new(client).into_rpc())?;

    // Extend this RPC with a custom API by using the following syntax.
    // `YourRpcStruct` should have a reference to a client, which is needed
    // to call into the runtime.
    // `module.merge(YourRpcTrait::into_rpc(YourRpcStruct::new(ReferenceToClient, ...)))?;`

    // You probably want to enable the `rpc v2 chainSpec` API as well
    //
    // let chain_name = chain_spec.name().to_string();
    // let genesis_hash = client.block_hash(0).ok().flatten().expect("Genesis block exists; qed");
    // let properties = chain_spec.properties();
    // module.merge(ChainSpec::new(chain_name, genesis_hash, properties).into_rpc())?;
    io.extend_with(beefy_gadget_rpc::BeefyApi::to_delegate(
        beefy_gadget_rpc::BeefyRpcHandler::new(signed_commitment_stream, subscription_executor),
    ));

    Ok(module)
}
