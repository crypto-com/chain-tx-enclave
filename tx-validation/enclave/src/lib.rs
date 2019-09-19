#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use chain_core::init::coin::Coin;
use chain_core::tx::data::TxId;
use chain_core::tx::fee::Fee;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::input::TxoIndex, PlainTxAux, TxAux, TxObfuscated};
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, TxWithOutputs,
};
use enclave_macro::get_network_id;
use enclave_protocol::{IntraEnclaveRequest, IntraEnclaveResponse, IntraEnclaveResponseOk};
use parity_scale_codec::{Decode, Encode};
use sgx_tseal::SgxSealedData;
use sgx_types::{sgx_sealed_data_t, sgx_status_t};
use std::prelude::v1::Vec;
use std::slice;

const NETWORK_HEX_ID: u8 = get_network_id!();

/// FIXME: genesis app_hash etc.
#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == NETWORK_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

#[inline]
fn unseal(sealed_log: &mut [u8]) -> Option<TxWithOutputs> {
    if sealed_log.len() >= (std::u32::MAX as usize) {
        return None;
    }
    let opt = unsafe {
        SgxSealedData::<[u8]>::from_raw_sealed_data_t(
            sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
            sealed_log.len() as u32,
        )
    };
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return None;
        }
    };
    let result = sealed_data.unseal_data();
    let unsealed_data = match result {
        Ok(x) => x,
        Err(_) => {
            return None;
        }
    };
    let otx = TxWithOutputs::decode(&mut unsealed_data.get_decrypt_txt());
    // TODO: check decoded txid against unsealed_data.get_additional_txt?
    match otx {
        Ok(tx) => Some(tx),
        _ => None,
    }
}

#[inline]
fn unseal_all(mut sealed_logs: Vec<Vec<u8>>) -> Option<Vec<TxWithOutputs>> {
    let mut result = Vec::with_capacity(sealed_logs.len());
    for sealed_log in sealed_logs.iter_mut() {
        if let Some(tx) = unseal(sealed_log) {
            result.push(tx);
        } else {
            return None;
        }
    }
    Some(result)
}

#[inline]
fn construct_sealed_response(
    result: Result<Fee, chain_tx_validation::Error>,
    txid: &TxId,
    to_seal_tx: TxWithOutputs,
) -> Result<IntraEnclaveResponse, sgx_status_t> {
    let to_seal = to_seal_tx.encode();
    match result {
        Err(e) => Ok(Err(e)),
        Ok(fee) => {
            let sealing_result = SgxSealedData::<[u8]>::seal_data(txid, &to_seal);
            let sealed_data = match sealing_result {
                Ok(x) => x,
                Err(ret) => {
                    return Err(ret);
                }
            };
            let sealed_log_size = SgxSealedData::<[u8]>::calc_raw_sealed_data_size(
                sealed_data.get_add_mac_txt_len(),
                sealed_data.get_encrypt_txt_len(),
            ) as usize;
            let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];

            unsafe {
                let sealed_r = sealed_data.to_raw_sealed_data_t(
                    sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
                    sealed_log_size as u32,
                );
                if sealed_r.is_none() {
                    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
                }
            }
            Ok(Ok(IntraEnclaveResponseOk::TxWithOutputs {
                paid_fee: fee,
                sealed_tx: sealed_log,
            }))
        }
    }
}

#[inline]
fn construct_simple_response(
    result: Result<Coin, chain_tx_validation::Error>,
) -> Result<IntraEnclaveResponse, sgx_status_t> {
    match result {
        Err(e) => Ok(Err(e)),
        Ok(input_coins) => Ok(Ok(IntraEnclaveResponseOk::DepositStakeTx { input_coins })),
    }
}

#[inline]
fn write_back_response(
    response: Result<IntraEnclaveResponse, sgx_status_t>,
    response_buf: *mut u8,
    max_response_len: u32,
) -> sgx_status_t {
    match response {
        Ok(r) => {
            let to_copy = r.encode();
            let resp_len = to_copy.len() as u32;
            if resp_len > 0 && resp_len <= max_response_len {
                unsafe {
                    std::ptr::copy_nonoverlapping(to_copy.as_ptr(), response_buf, to_copy.len());
                }
                sgx_status_t::SGX_SUCCESS
            } else {
                sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
        Err(e) => e,
    }
}

#[no_mangle]
pub extern "C" fn ecall_check_tx(
    tx_request: *const u8,
    tx_request_len: usize,
    response_buf: *mut u8,
    response_len: u32,
) -> sgx_status_t {
    let mut tx_request_slice = unsafe { slice::from_raw_parts(tx_request, tx_request_len) };
    if let Ok(req) = IntraEnclaveRequest::decode(&mut tx_request_slice) {
        if req.is_basic_valid(NETWORK_HEX_ID).is_err() {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        match (req.tx_inputs, req.request.tx) {
            (
                Some(sealed_inputs),
                TxAux::TransferTx {
                    txid,
                    payload: TxObfuscated { txpayload, .. },
                    no_of_outputs,
                    ..
                },
            ) => {
                // FIXME: decrypting
                let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
                let unsealed_inputs = unseal_all(sealed_inputs);
                match (plaintx, unsealed_inputs) {
                    (Ok(PlainTxAux::TransferTx(tx, witness)), Some(inputs)) => {
                        if tx.id() != txid || tx.outputs.len() as TxoIndex != no_of_outputs {
                            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                        }
                        let result = verify_transfer(&tx, &witness, req.request.info, inputs);
                        let response =
                            construct_sealed_response(result, &txid, TxWithOutputs::Transfer(tx));
                        write_back_response(response, response_buf, response_len)
                    }
                    _ => {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                }
            }
            (
                Some(sealed_inputs),
                TxAux::DepositStakeTx {
                    tx,
                    payload: TxObfuscated { txpayload, .. },
                },
            ) => {
                // FIXME: decrypting
                let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
                let inputs = unseal_all(sealed_inputs);
                match (plaintx, inputs) {
                    (Ok(PlainTxAux::DepositStakeTx(witness)), Some(inputs)) => {
                        let result =
                            verify_bonded_deposit_core(&tx, &witness, req.request.info, inputs);
                        let response = construct_simple_response(result);
                        write_back_response(response, response_buf, response_len)
                    }
                    _ => {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                }
            }
            (
                None,
                TxAux::WithdrawUnbondedStakeTx {
                    txid,
                    no_of_outputs,
                    payload: TxObfuscated { txpayload, .. },
                    witness,
                },
            ) => {
                let address = verify_tx_recover_address(&witness, &txid);
                if address.is_err() {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                // FIXME: decrypting
                let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
                match (plaintx, req.request.account) {
                    (Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)), Some(account)) => {
                        if tx.id() != txid
                            || no_of_outputs != tx.outputs.len() as TxoIndex
                            || account.address != address.unwrap()
                        {
                            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                        }
                        let result = verify_unbonded_withdraw_core(&tx, req.request.info, &account);
                        let response = construct_sealed_response(
                            result,
                            &txid,
                            TxWithOutputs::StakeWithdraw(tx),
                        );
                        write_back_response(response, response_buf, response_len)
                    }
                    _ => {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                }
            }
            (_, _) => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    } else {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
}
