mod enclave_u;

use enclave_u_common::{storage_path, META_KEYSPACE, TX_KEYSPACE};
use enclave_u_common::enclave_u::{init_enclave, QUERY_TOKEN_KEY};
use log::{error, info};
use sled::Db;
use crate::enclave_u::check_initchain;

fn main() {
    env_logger::init();
    let db = Db::start_default(storage_path()).expect("failed to open a storage path");
    let metadb = db
        .open_tree(META_KEYSPACE)
        .expect("failed to open a meta keyspace");
    let _txdb = db
        .open_tree(TX_KEYSPACE)
        .expect("failed to open a tx keyspace");

    let enclave = match init_enclave(metadb, true, QUERY_TOKEN_KEY) {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };
    // FIXME: it's just a dummy now
    assert!(check_initchain(enclave.geteid(), 0xab).is_ok());

}

