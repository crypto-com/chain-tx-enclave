use crate::enclave_u::{
    check_deposit_tx, check_initchain, check_transfertx, check_withdraw_tx, get_token_arr,
    store_token,
};
use chain_core::state::account::DepositBondTx;
use chain_core::tx::data::TxId;
use chain_core::tx::TxAux;
use enclave_protocol::{EnclaveRequest, EnclaveResponse, FLAGS};
use log::{debug, info};
use parity_scale_codec::{Decode, Encode};
use sgx_urts::SgxEnclave;
use sled::Tree;
use std::sync::Arc;
use zmq::{Context, Error, Socket, REP};

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave,
    txdb: Arc<Tree>,
    metadb: Arc<Tree>,
}

impl TxValidationServer {
    pub fn new(
        connection_str: &str,
        enclave: SgxEnclave,
        txdb: Arc<Tree>,
        metadb: Arc<Tree>,
    ) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;
        Ok(TxValidationServer {
            socket,
            enclave,
            txdb,
            metadb,
        })
    }

    fn lookup_txids<I>(&self, inputs: I) -> Option<Vec<Vec<u8>>>
    where
        I: IntoIterator<Item = TxId> + ExactSizeIterator,
    {
        let mut result = Vec::with_capacity(inputs.len());
        for input in inputs.into_iter() {
            if let Ok(Some(txin)) = self.txdb.get(input) {
                result.push(txin.to_vec());
            } else {
                return None;
            }
        }
        Some(result)
    }

    fn lookup(&self, tx: &TxAux) -> Option<Vec<Vec<u8>>> {
        match tx {
            TxAux::TransferTx { inputs, .. } => self.lookup_txids(inputs.iter().map(|x| x.id)),
            TxAux::DepositStakeTx {
                tx: DepositBondTx { inputs, .. },
                ..
            } => self.lookup_txids(inputs.iter().map(|x| x.id)),
            _ => None,
        }
    }

    pub fn execute(&mut self) {
        info!("running zmq server");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
                let resp = match mcmd {
                    Ok(EnclaveRequest::CheckChain {
                        chain_hex_id,
                        last_app_hash,
                    }) => {
                        debug!("check chain");
                        match self.txdb.get(b"last_apphash") {
                            Err(_) => EnclaveResponse::CheckChain(Err(None)),
                            Ok(s) => {
                                let ss = s.map(|stored| {
                                    let mut app_hash = [0u8; 32];
                                    app_hash.copy_from_slice(&stored);
                                    app_hash
                                });
                                if last_app_hash == ss {
                                    EnclaveResponse::CheckChain(check_initchain(
                                        self.enclave.geteid(),
                                        chain_hex_id,
                                        ss,
                                    ))
                                } else {
                                    EnclaveResponse::CheckChain(Err(ss))
                                }
                            }
                        }
                    }
                    Ok(EnclaveRequest::CommitBlock { app_hash }) => {
                        let _ = self.txdb.insert(b"last_apphash", &app_hash);
                        if let Ok(_) = self.txdb.flush() {
                            EnclaveResponse::CommitBlock(Ok(()))
                        } else {
                            EnclaveResponse::CommitBlock(Err(()))
                        }
                    }
                    Ok(EnclaveRequest::VerifyTx {
                        tx: tx @ TxAux::TransferTx { .. },
                        info,
                        ..
                    }) => {
                        debug!("verify transfer tx");
                        if let Some(txins) = self.lookup(&tx) {
                            EnclaveResponse::VerifyTx(check_transfertx(
                                self.enclave.geteid(),
                                tx,
                                txins,
                                info,
                                self.txdb.clone(),
                            ))
                        } else {
                            EnclaveResponse::VerifyTx(Err(chain_tx_validation::Error::InvalidInput))
                        }
                    }
                    Ok(EnclaveRequest::VerifyTx {
                        tx: tx @ TxAux::DepositStakeTx { .. },
                        info,
                        account,
                    }) => {
                        debug!("verify deposit tx");
                        if let Some(txins) = self.lookup(&tx) {
                            EnclaveResponse::VerifyTx(check_deposit_tx(
                                self.enclave.geteid(),
                                tx,
                                txins,
                                account,
                                info,
                                self.txdb.clone(),
                            ))
                        } else {
                            EnclaveResponse::VerifyTx(Err(chain_tx_validation::Error::InvalidInput))
                        }
                    }
                    Ok(EnclaveRequest::VerifyTx {
                        tx: tx @ TxAux::WithdrawUnbondedStakeTx { .. },
                        info,
                        account: Some(account),
                        ..
                    }) => {
                        debug!("verify withdraw tx");
                        EnclaveResponse::VerifyTx(check_withdraw_tx(
                            self.enclave.geteid(),
                            tx,
                            account,
                            info,
                            self.txdb.clone(),
                        ))
                    }
                    Ok(EnclaveRequest::GetCachedLaunchToken { enclave_metaname }) => {
                        EnclaveResponse::GetCachedLaunchToken(get_token_arr(
                            self.metadb.clone(),
                            &enclave_metaname,
                        ))
                    }
                    Ok(EnclaveRequest::UpdateCachedLaunchToken {
                        enclave_metaname,
                        token,
                    }) => EnclaveResponse::UpdateCachedLaunchToken(store_token(
                        self.metadb.clone(),
                        &enclave_metaname,
                        token.to_vec(),
                    )),
                    Ok(EnclaveRequest::GetSealedTxData { txids }) => {
                        EnclaveResponse::GetSealedTxData(
                            self.lookup_txids(txids.iter().map(|x| *x)),
                        )
                    }
                    Ok(_) => {
                        debug!("verify other tx");
                        EnclaveResponse::UnsupportedTxType
                    }
                    Err(e) => {
                        debug!("unknown request / failed to decode: {}", e);
                        EnclaveResponse::UnknownRequest
                    }
                };
                let response = resp.encode();
                self.socket
                    .send(response, FLAGS)
                    .expect("reply sending failed");
            }
        }
    }
}
