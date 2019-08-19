mod enclave_u;

use enclave_u::run_server;
use enclave_u_common::enclave_u::{init_enclave, QUERY_TOKEN_KEY};
use enclave_u_common::{storage_path, META_KEYSPACE};
use log::{error, info, warn};
use sgx_types::sgx_status_t;
use sled::Db;
use std::env;
use std::net::TcpListener;
use std::os::unix::io::AsRawFd;
use std::time::Duration;

const TIMEOUT_SEC: u64 = 5;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("Please provide the address:port to listen on (e.g. \"0.0.0.0:3443\") as the first argument");
        return;
    }
    let db = Db::start_default(storage_path()).expect("failed to open a storage path");
    let metadb = db
        .open_tree(META_KEYSPACE)
        .expect("failed to open a meta keyspace");

    let enclave = match init_enclave(metadb.clone(), true, QUERY_TOKEN_KEY) {
        Ok(r) => {
            info!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            error!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    // needs to get a lock in enclave_u mod -- FIXME: I guess this is broken if sled is simultaneously opened by tx-validation and tx-query?
    drop(db);
    drop(metadb);

    info!("Running TX Decryption Query server...");
    let listener = TcpListener::bind(&args[1]).expect("failed to bind the TCP socket");
    // FIXME: thread pool + rate-limiting
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("new client connection");
                let _ = stream.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
                let _ = stream.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
                let mut retval = sgx_status_t::SGX_SUCCESS;
                let result =
                    unsafe { run_server(enclave.geteid(), &mut retval, stream.as_raw_fd()) };
                match result {
                    sgx_status_t::SGX_SUCCESS => {
                        info!("client query finished");
                    }
                    e => {
                        warn!("client query failed: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("connection failed: {}", e);
            }
        }
    }
}
