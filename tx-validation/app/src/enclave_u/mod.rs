use sgx_types::*;

use chain_core::common::H256;
use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
use chain_core::ChainInfo;
use chain_tx_validation::Error;
use enclave_u_common::enclave_u::TOKEN_LEN;
use log::{info, warn};
use parity_scale_codec::Encode;
use sled::Tree;
use std::mem::size_of;
use std::sync::Arc;

extern "C" {
    fn ecall_initchain(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        chain_hex_id: u8,
    ) -> sgx_status_t;

    fn ecall_check_transfer_tx(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
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
    ) -> sgx_status_t;

    fn ecall_check_deposit_tx(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        input_coin_sum: *mut u64,
        error_code: *mut i32,
        chain_info: *const u8,
        chain_info_len: usize,
        txaux: *const u8,
        txaux_len: usize,
        txsin: *const u8,
        txsin_len: usize,
    ) -> sgx_status_t;

    fn ecall_check_withdraw_tx(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
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
    ) -> sgx_status_t;

}

pub fn get_token(metadb: Arc<Tree>, token_key: &[u8]) -> Option<Vec<u8>> {
    match metadb.get(token_key) {
        Ok(x) => x.map(|tok| tok.to_vec()),
        _ => None,
    }
}

pub fn get_token_arr(
    metadb: Arc<Tree>,
    token_key: &[u8],
) -> Result<Option<Box<[u8; TOKEN_LEN]>>, ()> {
    match metadb.get(token_key) {
        Ok(x) => Ok(x.map(|tok| {
            let mut token = [0; TOKEN_LEN];
            token.copy_from_slice(&tok);
            Box::new(token)
        })),
        _ => Err(()),
    }
}

pub fn store_token(metadb: Arc<Tree>, token_key: &[u8], launch_token: Vec<u8>) -> Result<(), ()> {
    match metadb.insert(token_key, launch_token) {
        Ok(_) => {
            info!("[+] Saved updated launch token!");
            Ok(())
        }
        Err(_) => {
            warn!("[-] Failed to save updated launch token!");
            Err(())
        }
    }
}

pub fn check_initchain(
    eid: sgx_enclave_id_t,
    chain_hex_id: u8,
    last_app_hash: Option<H256>,
) -> Result<(), Option<H256>> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_initchain(eid, &mut retval, chain_hex_id) };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        Ok(())
    } else {
        Err(last_app_hash)
    }
}

pub fn check_transfertx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    txins: Vec<Vec<u8>>,
    info: ChainInfo,
    txdb: Arc<Tree>,
) -> Result<(Fee, Option<StakedState>), Error> {
    let txins_enc: Vec<u8> = txins.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let sealed_log_size = size_of::<sgx_sealed_data_t>() + txaux_enc.len();
    let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut actual_fee_paid = 0;
    let mut error_code = -1;
    let result = unsafe {
        ecall_check_transfer_tx(
            eid,
            &mut retval,
            &mut actual_fee_paid,
            sealed_log.as_mut_ptr(),
            sealed_log_size as u32,
            &mut error_code,
            info_enc.as_ptr(),
            info_enc.len(),
            txaux_enc.as_ptr(),
            txaux_enc.len(),
            txins_enc.as_ptr(),
            txins_enc.len(),
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let fee = Fee::new(
            Coin::new(actual_fee_paid).expect("fee should not be larger than coin supply"),
        );
        let _ = txdb
            .insert(&txaux.tx_id(), sealed_log)
            .map_err(|_| Error::IoError)?;
        Ok((fee, None))
    } else {
        Err(Error::from(error_code))
    }
}

pub fn check_deposit_tx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    txins: Vec<Vec<u8>>,
    maccount: Option<StakedState>,
    info: ChainInfo,
    _txdb: Arc<Tree>,
) -> Result<(Fee, Option<StakedState>), Error> {
    let txins_enc: Vec<u8> = txins.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut input_coin_sum = 0;
    let mut error_code = -1;
    let result = unsafe {
        ecall_check_deposit_tx(
            eid,
            &mut retval,
            &mut input_coin_sum,
            &mut error_code,
            info_enc.as_ptr(),
            info_enc.len(),
            txaux_enc.as_ptr(),
            txaux_enc.len(),
            txins_enc.as_ptr(),
            txins_enc.len(),
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let deposit_amount = (Coin::new(input_coin_sum).expect("correct coin")
            - info.min_fee_computed.to_coin())
        .expect("init");
        let account = match (maccount, txaux) {
            (Some(mut a), _) => {
                a.deposit(deposit_amount);
                Some(a)
            }
            (
                None,
                TxAux::DepositStakeTx {
                    tx:
                        DepositBondTx {
                            to_staked_account, ..
                        },
                    ..
                },
            ) => Some(StakedState::new_init(
                deposit_amount,
                info.previous_block_time,
                to_staked_account,
                true,
            )),
            (_, _) => unreachable!("one shouldn't call this with other variants"),
        };
        let fee = info.min_fee_computed;
        Ok((fee, account))
    } else {
        Err(Error::from(error_code))
    }
}

pub fn check_withdraw_tx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    mut account: StakedState,
    info: ChainInfo,
    txdb: Arc<Tree>,
) -> Result<(Fee, Option<StakedState>), Error> {
    let account_enc: Vec<u8> = account.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let sealed_log_size = size_of::<sgx_sealed_data_t>() + txaux_enc.len();
    let mut sealed_log: Vec<u8> = vec![0u8; sealed_log_size];
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut actual_fee_paid = 0;
    let mut error_code = -1;
    let result = unsafe {
        ecall_check_withdraw_tx(
            eid,
            &mut retval,
            &mut actual_fee_paid,
            sealed_log.as_mut_ptr(),
            sealed_log_size as u32,
            &mut error_code,
            info_enc.as_ptr(),
            info_enc.len(),
            txaux_enc.as_ptr(),
            txaux_enc.len(),
            account_enc.as_ptr(),
            account_enc.len(),
        )
    };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        let fee = Fee::new(
            Coin::new(actual_fee_paid).expect("fee should not be larger than coin supply"),
        );
        account.withdraw();
        let _ = txdb
            .insert(&txaux.tx_id(), sealed_log)
            .map_err(|_| Error::IoError)?;
        Ok((fee, Some(account)))
    } else {
        Err(Error::from(error_code))
    }
}
