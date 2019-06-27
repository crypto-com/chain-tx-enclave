mod enclave_u;
mod server;

use crate::enclave_u::init_enclave::init_enclave;
use crate::server::TxValidationServer;
use std::env;
use std::thread;

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    let args: Vec<String> = env::args().collect();

    let child_t = thread::spawn(move || {
        let mut server =
            TxValidationServer::new(&args[1], enclave).expect("could not start a zmq server");
        server.execute()
    });
    child_t.join().expect("server thread failed");
}
