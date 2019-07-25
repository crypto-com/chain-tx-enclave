use crate::enclave_u::{check_deposit_tx, check_initchain, check_transfertx, check_withdraw_tx};
use chain_core::tx::TxAux;
use enclave_protocol::{EnclaveRequest, EnclaveResponse, FLAGS};
use log::{debug, info};
use parity_codec::{Decode, Encode};
use sgx_urts::SgxEnclave;
use zmq::{Context, Error, Socket, REP};

pub struct TxValidationServer {
    socket: Socket,
    enclave: SgxEnclave,
}

impl TxValidationServer {
    pub fn new(connection_str: &str, enclave: SgxEnclave) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;
        Ok(TxValidationServer { socket, enclave })
    }

    pub fn execute(&mut self) {
        info!("running zmq server");
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                debug!("received a message");
                let mcmd = EnclaveRequest::decode(&mut msg.as_slice());
                let resp = match mcmd {
                    Some(EnclaveRequest::CheckChain { chain_hex_id }) => {
                        debug!("check chain");
                        EnclaveResponse::CheckChain(check_initchain(
                            self.enclave.geteid(),
                            chain_hex_id,
                        ))
                    }
                    Some(EnclaveRequest::VerifyTx {
                        tx: tx @ TxAux::TransferTx { .. },
                        inputs,
                        info,
                        ..
                    }) => {
                        debug!("verify transfer tx");
                        EnclaveResponse::VerifyTx(check_transfertx(
                            self.enclave.geteid(),
                            tx,
                            inputs,
                            info,
                        ))
                    }
                    Some(EnclaveRequest::VerifyTx {
                        tx: tx @ TxAux::DepositStakeTx { .. },
                        inputs,
                        info,
                        account,
                    }) => {
                        debug!("verify deposit tx");
                        EnclaveResponse::VerifyTx(check_deposit_tx(
                            self.enclave.geteid(),
                            tx,
                            inputs,
                            account,
                            info,
                        ))
                    }
                    Some(EnclaveRequest::VerifyTx {
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
                        ))
                    }
                    Some(_) => {
                        debug!("verify other tx");
                        EnclaveResponse::UnsupportedTxType
                    }
                    None => {
                        debug!("unknown request / failed to decode");
                        EnclaveResponse::UnsupportedTxType
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
