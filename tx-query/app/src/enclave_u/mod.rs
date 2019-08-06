use sgx_types::*;

extern "C" {
    fn ecall_initchain(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        chain_hex_id: u8,
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
