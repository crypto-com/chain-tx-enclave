#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use chain_core::state::account::StakedState;
use chain_core::tx::TransactionId;
use chain_core::tx::{data::input::TxoIndex, PlainTxAux, TxAux, TxObfuscated};
use chain_tx_validation::witness::verify_tx_recover_address;
use chain_tx_validation::{
    verify_bonded_deposit_core, verify_transfer, verify_unbonded_withdraw_core, ChainInfo,
    TxWithOutputs,
};
use enclave_macro::get_network_id;
use parity_scale_codec::{Decode, Encode, Error};
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
fn check_chain_info(chain_info: *const u8, chain_info_len: usize) -> Option<ChainInfo> {
    let mut chain_info_slice = unsafe { slice::from_raw_parts(chain_info, chain_info_len) };
    let chain_info = ChainInfo::decode(&mut chain_info_slice);
    match chain_info {
        Ok(ChainInfo { chain_hex_id, .. }) if chain_hex_id == NETWORK_HEX_ID => {
            Some(chain_info.unwrap())
        }
        _ => None,
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

/// FIXME: use bytestream (local socket) to read request and write response?
#[no_mangle]
pub extern "C" fn ecall_check_transfer_tx(
    actual_fee_paid: *mut u64,
    sealed_log: *mut u8,
    sealed_log_size: u32,
    error_code: *mut i32,
    chain_info: *const u8,
    chain_info_len: usize,
    txaux: *const u8,
    txaux_len: usize,
    txsin: *const u8,
    txsin_len: usize,
) -> sgx_status_t {
    let info = match check_chain_info(chain_info, chain_info_len) {
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        Some(x) => x,
    };

    let mut txaux_slice = unsafe { slice::from_raw_parts(txaux, txaux_len) };
    let txaux = TxAux::decode(&mut txaux_slice);
    if let Ok(TxAux::TransferTx {
        txid,
        payload: TxObfuscated { txpayload, .. },
        no_of_outputs,
        ..
    }) = txaux
    {
        let mut inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
        let inputs_enc: Result<Vec<Vec<u8>>, Error> = Decode::decode(&mut inputs_slice);
        let inputs = inputs_enc.map(unseal_all);
        // FIXME: decrypting
        let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
        match (plaintx, inputs) {
            (Ok(PlainTxAux::TransferTx(tx, witness)), Ok(Some(input_txs))) => {
                if tx.id() != txid || tx.outputs.len() as TxoIndex != no_of_outputs {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let result = verify_transfer(&tx, &witness, info, input_txs);
                if let Err(e) = result {
                    let err: i32 = e as i32;
                    unsafe {
                        *error_code = err;
                    }
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let to_seal = TxWithOutputs::Transfer(tx).encode();
                let sealing_result = SgxSealedData::<[u8]>::seal_data(&txid, &to_seal);
                let sealed_data = match sealing_result {
                    Ok(x) => x,
                    Err(ret) => {
                        return ret;
                    }
                };
                let actual_fee: u64 = result.unwrap().to_coin().into();
                unsafe {
                    let sealed_r = sealed_data.to_raw_sealed_data_t(
                        sealed_log as *mut sgx_sealed_data_t,
                        sealed_log_size,
                    );
                    if sealed_r.is_none() {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    *actual_fee_paid = actual_fee;
                }
                sgx_status_t::SGX_SUCCESS
            }
            _ => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

/// FIXME: use bytestream (local socket) to read request and write response?
#[no_mangle]
pub extern "C" fn ecall_check_deposit_tx(
    input_coin_sum: *mut u64,
    error_code: *mut i32,
    chain_info: *const u8,
    chain_info_len: usize,
    txaux: *const u8,
    txaux_len: usize,
    txsin: *const u8,
    txsin_len: usize,
) -> sgx_status_t {
    let info = match check_chain_info(chain_info, chain_info_len) {
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        Some(x) => x,
    };

    let mut txaux_slice = unsafe { slice::from_raw_parts(txaux, txaux_len) };
    let txaux = TxAux::decode(&mut txaux_slice);
    if let Ok(TxAux::DepositStakeTx {
        tx,
        payload: TxObfuscated { txpayload, .. },
    }) = txaux
    {
        let mut inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
        let inputs_enc: Result<Vec<Vec<u8>>, Error> = Decode::decode(&mut inputs_slice);
        let inputs = inputs_enc.map(unseal_all);
        // FIXME: decrypting
        let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
        match (plaintx, inputs) {
            (Ok(PlainTxAux::DepositStakeTx(witness)), Ok(Some(input_txs))) => {
                let result = verify_bonded_deposit_core(&tx, &witness, info, input_txs);
                if let Err(e) = result {
                    let err: i32 = e as i32;
                    unsafe {
                        *error_code = err;
                    }
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let incoins: u64 = result.unwrap().into();
                unsafe {
                    *input_coin_sum = incoins;
                }
                sgx_status_t::SGX_SUCCESS
            }
            _ => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

/// FIXME: use bytestream (local socket) to read request and write response?
#[no_mangle]
pub extern "C" fn ecall_check_withdraw_tx(
    actual_fee_paid: *mut u64,
    sealed_log: *mut u8,
    sealed_log_size: u32,
    error_code: *mut i32,
    chain_info: *const u8,
    chain_info_len: usize,
    txaux: *const u8,
    txaux_len: usize,
    account: *const u8,
    account_len: usize,
) -> sgx_status_t {
    let info = match check_chain_info(chain_info, chain_info_len) {
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        Some(x) => x,
    };

    let mut txaux_slice = unsafe { slice::from_raw_parts(txaux, txaux_len) };
    let txaux = TxAux::decode(&mut txaux_slice);
    if let Ok(TxAux::WithdrawUnbondedStakeTx {
        txid,
        no_of_outputs,
        payload: TxObfuscated { txpayload, .. },
        witness,
        ..
    }) = txaux
    {
        let address = verify_tx_recover_address(&witness, &txid);
        if address.is_err() {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
        // FIXME: decrypting
        let mut account_slice = unsafe { slice::from_raw_parts(account, account_len) };
        let account = StakedState::decode(&mut account_slice);
        let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
        match (plaintx, account) {
            (Ok(PlainTxAux::WithdrawUnbondedStakeTx(tx)), Ok(account)) => {
                if tx.id() != txid
                    || no_of_outputs != tx.outputs.len() as TxoIndex
                    || account.address != address.unwrap()
                {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let result = verify_unbonded_withdraw_core(&tx, info, &account);
                if let Err(e) = result {
                    let err: i32 = e as i32;
                    unsafe {
                        *error_code = err;
                    }
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let to_seal = TxWithOutputs::StakeWithdraw(tx).encode();
                let sealing_result = SgxSealedData::<[u8]>::seal_data(&txid, &to_seal);
                let sealed_data = match sealing_result {
                    Ok(x) => x,
                    Err(ret) => {
                        return ret;
                    }
                };
                let actual_fee: u64 = result.unwrap().to_coin().into();
                unsafe {
                    let sealed_r = sealed_data.to_raw_sealed_data_t(
                        sealed_log as *mut sgx_sealed_data_t,
                        sealed_log_size,
                    );
                    if sealed_r.is_none() {
                        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                    }
                    *actual_fee_paid = actual_fee;
                }
                sgx_status_t::SGX_SUCCESS
            }
            _ => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}
