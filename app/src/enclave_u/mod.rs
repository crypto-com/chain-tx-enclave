pub mod init_enclave;

use sgx_types::*;

use chain_core::init::coin::Coin;
use chain_core::state::account::DepositBondTx;
use chain_core::state::account::StakedState;
use chain_core::tx::fee::Fee;
use chain_core::tx::TxAux;
use chain_core::ChainInfo;
use chain_tx_validation::TxWithOutputs;
use parity_codec::Encode;

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
        chain_info: *const u8,
        chain_info_len: usize,
        txaux: *const u8,
        txaux_len: usize,
        account: *const u8,
        account_len: usize,
    ) -> sgx_status_t;

}

pub fn check_initchain(eid: sgx_enclave_id_t, chain_hex_id: u8) -> Result<(), ()> {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { ecall_initchain(eid, &mut retval, chain_hex_id) };
    if retval == sgx_status_t::SGX_SUCCESS && result == retval {
        Ok(())
    } else {
        Err(())
    }
}

pub fn check_transfertx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    txins: Vec<TxWithOutputs>,
    info: ChainInfo,
) -> Result<(Fee, Option<StakedState>), ()> {
    let txins_enc: Vec<u8> = txins.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut actual_fee_paid = 0;
    let result = unsafe {
        ecall_check_transfer_tx(
            eid,
            &mut retval,
            &mut actual_fee_paid,
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
        Ok((fee, None))
    } else {
        Err(())
    }
}

pub fn check_deposit_tx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    txins: Vec<TxWithOutputs>,
    maccount: Option<StakedState>,
    info: ChainInfo,
) -> Result<(Fee, Option<StakedState>), ()> {
    let txins_enc: Vec<u8> = txins.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut input_coin_sum = 0;
    let result = unsafe {
        ecall_check_deposit_tx(
            eid,
            &mut retval,
            &mut input_coin_sum,
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
        Err(())
    }
}

pub fn check_withdraw_tx(
    eid: sgx_enclave_id_t,
    txaux: TxAux,
    mut account: StakedState,
    info: ChainInfo,
) -> Result<(Fee, Option<StakedState>), ()> {
    let account_enc: Vec<u8> = account.encode();
    let txaux_enc: Vec<u8> = txaux.encode();
    let info_enc: Vec<u8> = info.encode();
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let mut actual_fee_paid = 0;
    let result = unsafe {
        ecall_check_withdraw_tx(
            eid,
            &mut retval,
            &mut actual_fee_paid,
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
        Ok((fee, Some(account)))
    } else {
        Err(())
    }
}