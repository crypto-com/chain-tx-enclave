#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use chain_core::init::coin::Coin;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
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
    _previous_block_time: i64,
    _unbonding_period: u32,
    txaux: *const u8,
    txaux_len: usize,
    txsin: *const u8,
    txsin_len: usize,
) -> sgx_status_t {
    let fee_c = Coin::new(min_computed_fee);
    if fee_c.is_err() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
    let _fee = Fee::new(fee_c.unwrap());
    let mut txaux_slice = unsafe { slice::from_raw_parts(txaux, txaux_len) };
    // FIXME: decode inputs
    let mut _inputs_slice = unsafe { slice::from_raw_parts(txsin, txsin_len) };
    // FIXME: decrypting
    let txaux = TxAux::decode(&mut txaux_slice);
    match txaux {
        Some(TxAux::TransferTx(_tx, _witnesses)) => {
            // FIXME: tx validation
        }
        _ => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        }
    }
    // FIXME: sealing
    return sgx_status_t::SGX_SUCCESS;
}
