use zmq::{Socket, Context, REP, Error};
use crate::enclave_u::initchain;
use sgx_urts::SgxEnclave;

pub const FLAGS: i32 = 0;

pub struct TxValidationServer {
	    socket: Socket,
	    enclave: SgxEnclave
	}

impl TxValidationServer {
    pub fn new(connection_str: &str, enclave: SgxEnclave) -> Result<TxValidationServer, Error> {
        let ctx = Context::new();
        let socket = ctx.socket(REP)?;
        socket.bind(connection_str)?;
        Ok(TxValidationServer {
            socket,
            enclave
        })
    }

    pub fn execute(&mut self) {
        loop {
            if let Ok(msg) = self.socket.recv_bytes(FLAGS) {
                unimplemented!("FIXME")
            }
        }
    }
}