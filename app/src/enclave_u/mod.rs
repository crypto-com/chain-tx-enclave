pub mod init_enclave;

use sgx_types::*;

extern {
    fn ecall_initchain(eid: sgx_enclave_id_t,
                    retval: *mut sgx_status_t,
                    chain_hex_id: u8) -> sgx_status_t;
}

pub fn initchain(eid: sgx_enclave_id_t, chain_hex_id: u8) -> bool {
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let result = unsafe {
        ecall_initchain(eid, &mut retval, chain_hex_id)
    };
    retval == sgx_status_t::SGX_SUCCESS && result == retval
}