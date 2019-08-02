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

/// FIXME: struct / typedef / fixed-size array for chain info
#[no_mangle]
pub extern "C" fn ecall_check_transfer_tx(
    actual_fee_paid: *mut u64,
    sealed_log: *mut u8,
    sealed_log_size: u32,
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
        // FIXME: decrypting
        let mut inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
        let inputs: Result<Vec<TxWithOutputs>, Error> = Decode::decode(&mut inputs_slice);
        let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
        match (plaintx, inputs) {
            (Ok(PlainTxAux::TransferTx(tx, witness)), Ok(input_txs)) => {
                if tx.id() != txid || tx.outputs.len() as TxoIndex != no_of_outputs {
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                let result = verify_transfer(&tx, &witness, info, input_txs);
                if result.is_err() {
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

/// FIXME: struct / typedef / fixed-size array for chain info
#[no_mangle]
pub extern "C" fn ecall_check_deposit_tx(
    input_coin_sum: *mut u64,
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
        // FIXME: decrypting
        let mut inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
        let inputs: Result<Vec<TxWithOutputs>, Error> = Decode::decode(&mut inputs_slice);
        let plaintx = PlainTxAux::decode(&mut txpayload.as_slice());
        match (plaintx, inputs) {
            (Ok(PlainTxAux::DepositStakeTx(witness)), Ok(input_txs)) => {
                let result = verify_bonded_deposit_core(&tx, &witness, info, input_txs);
                if result.is_err() {
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

/// FIXME: struct / typedef / fixed-size array for chain info and account?
#[no_mangle]
pub extern "C" fn ecall_check_withdraw_tx(
    actual_fee_paid: *mut u64,
    sealed_log: *mut u8,
    sealed_log_size: u32,
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
                if result.is_err() {
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
                // FIXME: sealing
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
