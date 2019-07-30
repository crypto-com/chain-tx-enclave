use crate::enclave_u::init_enclave::init_enclave;
use crate::enclave_u::{check_initchain, check_withdraw_tx};
use chain_core::common::MerkleTree;
use chain_core::init::address::RedeemAddress;
use chain_core::init::coin::Coin;
use chain_core::state::account::{
    StakedState, StakedStateAddress, StakedStateOpWitness, WithdrawUnbondedTx,
};
use chain_core::tx::fee::Fee;
use chain_core::tx::witness::tree::RawPubkey;
use chain_core::tx::witness::EcdsaSignature;
use chain_core::tx::PlainTxAux;
use chain_core::tx::TransactionId;
use chain_core::tx::TxObfuscated;
use chain_core::tx::{
    data::{
        access::{TxAccess, TxAccessPolicy},
        address::ExtendedAddr,
        attribute::TxAttributes,
        input::TxoIndex,
        output::TxOut,
        TxId,
    },
    TxAux,
};
use chain_core::ChainInfo;
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use log::{debug, error, info};
use parity_codec::Encode;
use secp256k1::{key::PublicKey, key::SecretKey, Message, Secp256k1, Signing};
use sled::Db;

pub fn get_ecdsa_witness<C: Signing>(
    secp: &Secp256k1<C>,
    txid: &TxId,
    secret_key: &SecretKey,
) -> EcdsaSignature {
    let message = Message::from_slice(&txid[..]).expect("32 bytes");
    let sig = secp.sign_recoverable(&message, &secret_key);
    return sig;
}

fn get_account(account_address: &RedeemAddress) -> StakedState {
    StakedState::new_init(
        Coin::one(),
        0,
        StakedStateAddress::from(*account_address),
        false,
    )
}

const TEST_NETWORK_ID: u8 = 0xab;

/// Unfortunately the usual Rust unit-test facility can't be used with Baidu SGX SDK,
/// so this has to be run as a normal app
pub fn test_sealing() {
    let mut builder = Builder::new();

    builder
        .filter(None, LevelFilter::Debug)
        .write_style(WriteStyle::Always)
        .init();
    let db = Db::start_default(".enclave-test").expect("failed to open a storage path");
    let metadb = db
        .open_tree(crate::META_KEYSPACE)
        .expect("failed to open a meta keyspace");
    let txdb = db
        .open_tree(crate::TX_KEYSPACE)
        .expect("failed to open a tx keyspace");

    let enclave = match init_enclave(metadb) {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };
    assert!(check_initchain(enclave.geteid(), TEST_NETWORK_ID).is_ok());

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&[0xcd; 32]).expect("32 bytes, within curve order");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let addr = RedeemAddress::from(&public_key);

    let merkle_tree = MerkleTree::new(vec![RawPubkey::from(public_key.serialize())]);

    let eaddr = ExtendedAddr::OrTree(merkle_tree.root_hash());
    let tx0 = WithdrawUnbondedTx::new(
        0,
        vec![TxOut::new_with_timelock(eaddr, Coin::one(), 0)],
        TxAttributes::new_with_access(
            TEST_NETWORK_ID,
            vec![TxAccessPolicy::new(public_key.clone(), TxAccess::AllData)],
        ),
    );
    let txid = &tx0.id();
    let witness0 = StakedStateOpWitness::new(get_ecdsa_witness(&secp, &txid, &secret_key));
    let withdrawtx = TxAux::WithdrawUnbondedStakeTx {
        txid: tx0.id(),
        no_of_outputs: tx0.outputs.len() as TxoIndex,
        witness: witness0,
        payload: TxObfuscated {
            key_from: 0,
            nonce: [0u8; 12],
            txpayload: PlainTxAux::WithdrawUnbondedStakeTx(tx0).encode(),
        },
    };
    let account = get_account(&addr);
    let info = ChainInfo {
        min_fee_computed: Fee::new(Coin::zero()),
        chain_hex_id: TEST_NETWORK_ID,
        previous_block_time: 1,
        unbonding_period: 0,
    };
    let tb = txdb.get(&txid);
    match tb {
        Ok(None) => {
            debug!("new tx not in DB yet");
        }
        _ => {
            assert!(false, "new tx already in db");
        }
    };
    let r = check_withdraw_tx(enclave.geteid(), withdrawtx, account, info, txdb.clone());
    assert!(r.is_ok());
    let ta = txdb.get(&txid);
    match ta {
        Ok(Some(_)) => {
            debug!("new tx in DB!");
        }
        _ => {
            assert!(false, "new tx not in db");
        }
    };

    db.drop_tree(crate::META_KEYSPACE).expect("test meta tx");
    db.drop_tree(crate::TX_KEYSPACE).expect("test cleanup tx");
}
