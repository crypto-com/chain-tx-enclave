use crate::enclave_u::{check_initchain, check_transfertx};
use chain_core::tx::{TxAux, TxObfuscated};
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
                        tx:
                            TxAux::TransferTx {
                                payload: TxObfuscated { txpayload, .. },
                                ..
                            },
                        inputs,
                        info,
                        ..
                    }) => {
                        debug!("verify transfer tx");
                        EnclaveResponse::VerifyTx(check_transfertx(
                            self.enclave.geteid(),
                            txpayload,
                            inputs,
                            info.min_fee_computed,
                            info.previous_block_time,
                            info.unbonding_period,
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
