#![crate_name = "txvalidationenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]


#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::sgx_status_t;

/// FIXME: proc-macro
const NETWORK_HEX_ID: u8 = 0xab;

#[no_mangle]
pub extern "C" fn ecall_initchain(chain_hex_id: u8) -> sgx_status_t {
    if chain_hex_id == NETWORK_HEX_ID {
        sgx_status_t::SGX_SUCCESS
    } else {
        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    }
}