mod enclave_u;
mod server;

use crate::enclave_u::init_enclave::init_enclave;
use crate::server::TxValidationServer;
use log::{error, info};
use std::env;
use std::thread;

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("Please provide the ZMQ connection string (e.g. \"tcp://127.0.0.1:25933\") as the first argument");
        return;
    }
    let enclave = match init_enclave() {
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
            TxValidationServer::new(&args[1], enclave).expect("could not start a zmq server");
        info!("starting zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}
