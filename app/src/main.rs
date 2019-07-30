mod enclave_u;
mod server;
#[cfg(feature = "sgx-test")]
mod test;

use crate::enclave_u::init_enclave::init_enclave;
use crate::server::TxValidationServer;
use log::{error, info};
use sled::Db;
use std::env;
use std::thread;

/// TODO: connection string as env variable?
fn storage_path() -> String {
    match std::env::var("TX_ENCLAVE_STORAGE") {
        Ok(path) => path,
        Err(_) => ".enclave".to_owned(),
    }
}

const META_KEYSPACE: &[u8] = b"meta";
const TX_KEYSPACE: &[u8] = b"tx";

#[cfg(feature = "sgx-test")]
fn main() {
    test::test_sealing();
}

#[cfg(not(feature = "sgx-test"))]
fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("Please provide the ZMQ connection string (e.g. \"tcp://127.0.0.1:25933\") as the first argument");
        return;
    }
    let db = Db::start_default(storage_path()).expect("failed to open a storage path");
    let metadb = db
        .open_tree(META_KEYSPACE)
        .expect("failed to open a meta keyspace");
    let txdb = db
        .open_tree(TX_KEYSPACE)
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

    let child_t = thread::spawn(move || {
        let mut server =
            TxValidationServer::new(&args[1], enclave, txdb).expect("could not start a zmq server");
        info!("starting zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}
