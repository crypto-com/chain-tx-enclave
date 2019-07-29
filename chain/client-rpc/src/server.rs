use failure::ResultExt;
use hex;
use jsonrpc_core::{self, IoHandler};
use jsonrpc_http_server::{AccessControlAllowOrigin, DomainsValidation, ServerBuilder};
use std::net::SocketAddr;

use crate::client_rpc::{ClientRpc, ClientRpcImpl};
use crate::Options;
use chain_core::tx::fee::LinearFee;
use client_common::error::{Error, ErrorKind, Result};
use client_common::storage::SledStorage;
use client_common::tendermint::{Client, RpcClient};
use client_core::signer::DefaultSigner;
use client_core::transaction_builder::DefaultTransactionBuilder;
use client_core::wallet::DefaultWalletClient;
use client_index::cipher::AbciTransactionCipher;
use client_index::index::DefaultIndex;
use client_network::network_ops::DefaultNetworkOpsClient;

type AppSigner = DefaultSigner<SledStorage>;
type AppIndex = DefaultIndex<SledStorage, RpcClient>;
type AppTxBuilder =
    DefaultTransactionBuilder<AppSigner, LinearFee, AbciTransactionCipher<RpcClient>>;
type AppWalletClient = DefaultWalletClient<SledStorage, AppIndex, AppTxBuilder>;
type AppOpsClient = DefaultNetworkOpsClient<AppWalletClient, AppSigner, RpcClient, LinearFee>;

pub(crate) struct Server {
    host: String,
    port: u16,
    network_id: u8,
    storage_dir: String,
    tendermint_url: String,
}

impl Server {
    pub(crate) fn new(options: Options) -> Result<Server> {
        let network_id =
            hex::decode(&options.network_id).context(ErrorKind::SerializationError)?[0];
        Ok(Server {
            host: options.host,
            port: options.port,
            network_id,
            storage_dir: options.storage_dir,
            tendermint_url: options.tendermint_url,
        })
    }

    fn make_wallet_client(&self, storage: SledStorage) -> AppWalletClient {
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let signer = DefaultSigner::new(storage.clone());
        let transaction_cipher = AbciTransactionCipher::new(tendermint_client.clone());
        let transaction_builder = DefaultTransactionBuilder::new(
            signer,
            tendermint_client.genesis().unwrap().fee_policy(),
            transaction_cipher,
        );
        let index = DefaultIndex::new(storage.clone(), tendermint_client);
        DefaultWalletClient::builder()
            .with_wallet(storage)
            .with_transaction_read(index)
            .with_transaction_write(transaction_builder)
            .build()
            .unwrap()
    }

    pub fn make_ops_client(&self, storage: SledStorage) -> AppOpsClient {
        let tendermint_client = RpcClient::new(&self.tendermint_url);
        let signer = DefaultSigner::new(storage.clone());
        let fee_algorithm = tendermint_client.genesis().unwrap().fee_policy();
        let wallet_client = self.make_wallet_client(storage);
        DefaultNetworkOpsClient::new(wallet_client, signer, tendermint_client, fee_algorithm)
    }

    pub fn start_client(&self, io: &mut IoHandler, storage: SledStorage) -> Result<()> {
        {
            let wallet_client = self.make_wallet_client(storage.clone());
            let ops_client = self.make_ops_client(storage.clone());
            let client_rpc = ClientRpcImpl::new(wallet_client, ops_client, self.network_id);
            io.extend_with(client_rpc.to_delegate());
        }
        Ok(())
    }

    pub(crate) fn start(&self) -> Result<()> {
        let mut io = IoHandler::new();
        let storage = SledStorage::new(&self.storage_dir)?;

        self.start_client(&mut io, storage.clone()).unwrap();

        let server = ServerBuilder::new(io)
            // TODO: Either make CORS configurable or make it more strict
            .cors(DomainsValidation::AllowOnly(vec![
                AccessControlAllowOrigin::Any,
            ]))
            .start_http(&SocketAddr::new(self.host.parse().unwrap(), self.port))
            .expect("Unable to start JSON-RPC server");

        server.wait();

        Ok(())
    }
}

pub(crate) fn to_rpc_error(error: Error) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error.to_string(),
        data: None,
    }
}

pub(crate) fn rpc_error_from_string(error: String) -> jsonrpc_core::Error {
    jsonrpc_core::Error {
        code: jsonrpc_core::ErrorCode::InternalError,
        message: error,
        data: None,
    }
}