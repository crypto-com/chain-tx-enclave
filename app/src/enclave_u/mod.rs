pub mod init_enclave;

use sgx_types::*;

use chain_core::common::Timespec;
use chain_core::tx::fee::Fee;
use chain_core::tx::{data::Tx, TxAux};
use parity_codec::Encode;
use chain_tx_validation::TxWithOutputs;

extern "C" {
    fn ecall_initchain(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        chain_hex_id: u8,
    ) -> sgx_status_t;

    fn ecall_check_transfer_tx(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        min_computed_fee: u64,
        previous_block_time: i64,
        unbonding_period: u32,
        txaux: *const u8,
        txaux_len: usize,
        txsin: *const u8,
        txsin_len: usize,
    ) -> sgx_status_t;
}

pub fn initchain(eid: sgx_enclave_id_t, chain_hex_id: u8) -> bool {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_initchain(eid, &mut retval, chain_hex_id) };
    retval == sgx_status_t::SGX_SUCCESS && result == retval
}

pub fn check_transfertx(
    eid: sgx_enclave_id_t,
    tx: TxAux,
    txins: Vec<TxWithOutputs>,
    min_computed_fee: Fee,
    previous_block_time: Timespec,
    unbonding_period: u32,
) -> bool {
    let tx_enc: Vec<u8> = tx.encode();
    let txins_enc: Vec<u8> = txins.encode();
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall_check_transfer_tx(
            eid,
            &mut retval,
            min_computed_fee.to_coin().into(),
            previous_block_time,
            unbonding_period,
            tx_enc.as_ptr(),
            tx_enc.len(),
            txins_enc.as_ptr(),
            txins_enc.len(),
        )
    };
    retval == sgx_status_t::SGX_SUCCESS && result == retval
}
