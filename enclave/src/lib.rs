#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

 use std::prelude::v1::Vec;
use chain_core::init::coin::Coin;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
use chain_tx_validation::{verify_transfer, TxWithOutputs, ChainInfo};
use parity_codec::Decode;
use sgx_types::sgx_status_t;
use std::slice;
/// FIXME: proc-macro
const NETWORK_HEX_ID: u8 = 0xab;

/// FIXME: genesis app_hash etc.
#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == NETWORK_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}

#[no_mangle]
pub extern "C" fn ecall_check_transfer_tx(
    min_computed_fee: u64,
    previous_block_time: i64,
    unbonding_period: u32,
    txaux: *const u8,
    txaux_len: usize,
    txsin: *const u8,
    txsin_len: usize,
) -> sgx_status_t {
    let fee_c = Coin::new(min_computed_fee);
    if fee_c.is_err() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let fee = Fee::new(fee_c.unwrap());
    let mut txaux_slice = unsafe { slice::from_raw_parts(txaux, txaux_len) };
    let mut inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
    // FIXME: decrypting
    let txaux = TxAux::decode(&mut txaux_slice);
    let inputs: Option<Vec<TxWithOutputs>> = Decode::decode(&mut inputs_slice);

    return match (txaux, inputs) {
        (Some(TxAux::TransferTx(tx, witness)), Some(input_txs)) => {
            let info = ChainInfo {
                min_fee_computed: fee,
                chain_hex_id: NETWORK_HEX_ID,
                previous_block_time,
                unbonding_period
            };
            let result = verify_transfer(&tx, &witness, info, input_txs);
            if result.is_err() {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
            // FIXME: sealing
            sgx_status_t::SGX_SUCCESS
        }
        _ => {
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER
        }
    }
}
