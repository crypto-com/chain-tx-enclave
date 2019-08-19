use chain_core::tx::data::TxId;
use enclave_u_common::{storage_path, TX_KEYSPACE};
use log::{debug, error, trace};
use parity_scale_codec::{Decode, Encode};
use sgx_types::*;
use sled::{ConfigBuilder, Db, Tree};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::io::IntoRawFd;
use std::sync::Arc;

fn init_tx_db() -> Arc<Tree> {
    let config = ConfigBuilder::default()
        .path(storage_path())
        .read_only(true);

    let db = Db::start(config.build()).expect("failed to open a storage path");
    db.open_tree(TX_KEYSPACE)
        .expect("failed to open a tx keyspace")
}

thread_local! {
    static TXDB: Arc<Tree> = init_tx_db();
}

fn lookup_txids(txids: &[TxId]) -> Option<Vec<Vec<u8>>> {
    let mut result = Vec::with_capacity(txids.len());
    let r = TXDB.with(|txdb| {
        for txid in txids.iter() {
            if let Ok(Some(txin)) = txdb.get(txid) {
                result.push(txin.to_vec());
            } else {
                return None;
            }
        }
        return Some(result);
    });
    r
}

#[no_mangle]
pub extern "C" fn ocall_get_txs(
    txids: *const u8,
    txids_len: u32,
    txs: *mut u8,
    txs_len: u32,
) -> sgx_status_t {
    let mut txids_slice = unsafe { std::slice::from_raw_parts(txids, txids_len as usize) };
    let txids_i: Result<Vec<TxId>, parity_scale_codec::Error> = Decode::decode(&mut txids_slice);
    if let Ok(Some(txs_r)) = txids_i.map(|txids| lookup_txids(&txids)) {
        let txs_enc = txs_r.encode();
        if txs_enc.len() > (txs_len as usize) {
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        } else {
            unsafe {
                std::ptr::copy(txs_enc.as_ptr(), txs, txs_enc.len());
            }
        }
    } else {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    sgx_status_t::SGX_SUCCESS
}

extern "C" {
    pub fn run_server(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        socket_fd: c_int,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn ocall_sgx_init_quote(
    ret_ti: *mut sgx_target_info_t,
    ret_gid: *mut sgx_epid_group_id_t,
) -> sgx_status_t {
    trace!("Entering ocall_sgx_init_quote");
    unsafe { sgx_init_quote(ret_ti, ret_gid) }
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_key(ias_key: *mut u8, ias_key_len: u32) -> sgx_status_t {
    let ias_key_org = std::env::var("IAS_API_KEY").expect("IAS key not set");
    if ias_key_org.len() != (ias_key_len as usize) {
        error!("invalid ias key length");
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    unsafe {
        std::ptr::copy(ias_key_org.as_ptr(), ias_key, ias_key_len as usize);
    }

    sgx_status_t::SGX_SUCCESS
}

pub fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

#[no_mangle]
pub extern "C" fn ocall_get_ias_socket(ret_fd: *mut c_int) -> sgx_status_t {
    let port = 443;
    let hostname = "api.trustedservices.intel.com";
    let addr = lookup_ipv4(hostname, port);
    let sock = TcpStream::connect(&addr).expect("[-] Connect tls server failed!");

    unsafe {
        *ret_fd = sock.into_raw_fd();
    }

    sgx_status_t::SGX_SUCCESS
}

fn decode_hex_digit(digit: char) -> u8 {
    match digit {
        '0'...'9' => digit as u8 - '0' as u8,
        'a'...'f' => digit as u8 - 'a' as u8 + 10,
        'A'...'F' => digit as u8 - 'A' as u8 + 10,
        _ => panic!(),
    }
}

pub fn get_spid() -> sgx_spid_t {
    let mut spid = sgx_spid_t::default();
    let spid_hex = std::env::var("SPID").expect("SPID not set");
    let hex = spid_hex.trim();

    if hex.len() != 32 {
        panic!("Input spid len ({}) is incorrect!", hex.len());
    }

    let decoded_vec = decode_hex(hex);

    spid.id.copy_from_slice(&decoded_vec[..16]);

    spid
}

pub fn decode_hex(hex: &str) -> Vec<u8> {
    let mut r: Vec<u8> = Vec::new();
    let mut chars = hex.chars().enumerate();
    loop {
        let (pos, first) = match chars.next() {
            None => break,
            Some(elt) => elt,
        };
        if first == ' ' {
            continue;
        }
        let (_, second) = match chars.next() {
            None => panic!("pos = {}d", pos),
            Some(elt) => elt,
        };
        r.push((decode_hex_digit(first) << 4) | decode_hex_digit(second));
    }
    r
}

#[no_mangle]
pub extern "C" fn ocall_get_quote(
    p_sigrl: *const u8,
    sigrl_len: u32,
    p_report: *const sgx_report_t,
    quote_type: sgx_quote_sign_type_t,
    p_nonce: *const sgx_quote_nonce_t,
    p_qe_report: *mut sgx_report_t,
    p_quote: *mut u8,
    _maxlen: u32,
    p_quote_len: *mut u32,
) -> sgx_status_t {
    trace!("Entering ocall_get_quote");

    let mut real_quote_len: u32 = 0;

    let ret = unsafe { sgx_calc_quote_size(p_sigrl, sigrl_len, &mut real_quote_len as *mut u32) };

    if ret != sgx_status_t::SGX_SUCCESS {
        error!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    debug!("quote size = {}", real_quote_len);
    unsafe {
        *p_quote_len = real_quote_len;
    }

    let spid: sgx_spid_t = get_spid();

    let p_spid = &spid as *const sgx_spid_t;

    let ret = unsafe {
        sgx_get_quote(
            p_report,
            quote_type,
            p_spid,
            p_nonce,
            p_sigrl,
            sigrl_len,
            p_qe_report,
            p_quote as *mut sgx_quote_t,
            real_quote_len,
        )
    };

    if ret != sgx_status_t::SGX_SUCCESS {
        error!("sgx_calc_quote_size returned {}", ret);
        return ret;
    }

    debug!("sgx_calc_quote_size returned {}", ret);
    ret
}

#[no_mangle]
pub extern "C" fn ocall_get_update_info(
    platform_blob: *const sgx_platform_info_t,
    enclave_trusted: i32,
    update_info: *mut sgx_update_info_bit_t,
) -> sgx_status_t {
    unsafe { sgx_report_attestation_status(platform_blob, enclave_trusted, update_info) }
}
