#![crate_name = "txqueryenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(proc_macro_hygiene)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_rand::*;
use sgx_tcrypto::*;
use sgx_tse::*;
use sgx_types::*;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::prelude::v1::*;
use std::ptr;
use std::str;
use std::string::String;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;
mod cert;
use chain_core::state::account::WithdrawUnbondedTx;
use chain_core::tx::data::attribute::TxAttributes;
use chain_core::tx::data::Tx;
use chain_core::tx::data::TxId;
use chain_core::tx::TxWithOutputs;
use enclave_protocol::{DecryptionRequest, DecryptionRequestBody, DecryptionResponse};
use parity_scale_codec::{Decode, Encode};
use secp256k1::{key::PublicKey, Secp256k1};
use sgx_tseal::SgxSealedData;

pub const IAS_HOSTNAME: &'static str = "api.trustedservices.intel.com";
#[cfg(not(feature = "production"))]
pub const API_SUFFIX: &'static str = "/sgx/dev";
#[cfg(feature = "production")]
pub const API_SUFFIX: &'static str = "/sgx";
pub const SIGRL_SUFFIX: &'static str = "/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/attestation/v3/report";
pub const CERTEXPIRYDAYS: i64 = 90i64;
const TIMEOUT_SEC: u64 = 5;

extern "C" {
    pub fn ocall_get_txs(
        ret_val: *mut sgx_status_t,
        txids: *const u8,
        txids_len: u32,
        txs: *mut u8,
        txs_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_key(
        ret_val: *mut sgx_status_t,
        ias_key: *mut u8,
        ias_key_len: u32,
    ) -> sgx_status_t;
    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;
    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
    // println!("parse_response_attn_report");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    // println!("parse result {:?}", result);

    // FIXME: // FIXME: check respp.code!!!
    let mut len_num: u32 = 0;

    let mut sig = String::new();
    let mut cert = String::new();
    let mut attn_report = String::new();

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
        match h.name {
            "Content-Length" => {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                // println!("content length = {}", len_num);
            }
            "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
            "X-IASReport-Signing-Certificate" => {
                cert = str::from_utf8(h.value).unwrap().to_string()
            }
            _ => (),
        }
    }

    // Remove %0A from cert, and only obtain the signing cert
    cert = cert.replace("%0A", "");
    cert = cert::percent_decode(cert);
    let v: Vec<&str> = cert.split("-----").collect();
    let sig_cert = v[2].to_string();

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        attn_report = str::from_utf8(resp_body).unwrap().to_string();
        // println!("Attestation report: {}", attn_report);
    }

    // len_num == 0
    (attn_report, sig, sig_cert)
}

fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
    // println!("parse_response_sigrl");
    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut respp = httparse::Response::new(&mut headers);
    let result = respp.parse(resp);
    // println!("parse result {:?}", result);
    // println!("parse response{:?}", respp);

    // FIXME: check respp.code!!!
    let mut len_num: u32 = 0;

    for i in 0..respp.headers.len() {
        let h = respp.headers[i];
        if h.name == "content-length" {
            let len_str = String::from_utf8(h.value.to_vec()).unwrap();
            len_num = len_str.parse::<u32>().unwrap();
            // println!("content length = {}", len_num);
        }
    }

    if len_num != 0 {
        let header_len = result.unwrap().unwrap();
        let resp_body = &resp[header_len..];
        // println!("Base64-encoded SigRL: {:?}", resp_body);

        return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
    }

    // len_num == 0
    Vec::new()
}

pub fn make_ias_client_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

    config
}

pub fn get_sigrl_from_intel(ias_key: &str, fd: c_int, gid: u32) -> Vec<u8> {
    // println!("get_sigrl_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();

    let req = format!("GET {}{}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
                        API_SUFFIX,
                        SIGRL_SUFFIX,
                        gid,
                        IAS_HOSTNAME,
                        ias_key);

    // println!("{}", req);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    // println!("write complete");

    match tls.read_to_end(&mut plaintext) {
        Ok(_) => (),
        Err(e) => {
            // println!("get_sigrl_from_intel tls.read_to_end: {:?}", e);
            panic!(e);
        }
    }
    // println!("read_to_end complete");

    parse_response_sigrl(&plaintext)
}

pub fn get_report_from_intel(ias_key: &str, fd: c_int, quote: Vec<u8>) -> (String, String, String) {
    // println!("get_report_from_intel fd = {:?}", fd);
    let config = make_ias_client_config();
    let encoded_quote = base64::encode(&quote[..]);
    let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

    let req = format!("POST {}{} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                           API_SUFFIX,
                           REPORT_SUFFIX,
                           IAS_HOSTNAME,
                           ias_key,
                           encoded_json.len(),
                           encoded_json);

    // println!("{}", req);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(IAS_HOSTNAME).unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::new(fd).unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);

    let _result = tls.write(req.as_bytes());
    let mut plaintext = Vec::new();

    // println!("write complete");

    tls.read_to_end(&mut plaintext).unwrap();
    // println!("read_to_end complete");

    let (attn_report, sig, cert) = parse_response_attn_report(&plaintext);

    (attn_report, sig, cert)
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

#[allow(const_err)]
pub fn create_attestation_report(
    pub_k: &sgx_ec256_public_t,
    ias_key: &str,
    sign_type: sgx_quote_sign_type_t,
) -> Result<(String, String, String), sgx_status_t> {
    // Workflow:
    // (1) ocall to get the target_info structure (ti) and epid group id (eg)
    // (1.5) get sigrl
    // (2) call sgx_create_report with ti+data, produce an sgx_report_t
    // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)

    // (1) get ti + eg
    let mut ti: sgx_target_info_t = sgx_target_info_t::default();
    let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        ocall_sgx_init_quote(
            &mut rt as *mut sgx_status_t,
            &mut ti as *mut sgx_target_info_t,
            &mut eg as *mut sgx_epid_group_id_t,
        )
    };

    // println!("eg = {:?}", eg);

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let eg_num = as_u32_le(&eg);

    // (1.5) get sigrl
    let mut ias_sock: i32 = 0;

    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    //println!("Got ias_sock = {}", ias_sock);

    // Now sigrl_vec is the revocation list, a vec<u8>
    let sigrl_vec: Vec<u8> = get_sigrl_from_intel(ias_key, ias_sock, eg_num);

    // (2) Generate the report
    // Fill ecc256 public key into report_data
    let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    report_data.d[..32].clone_from_slice(&pub_k_gx);
    report_data.d[32..].clone_from_slice(&pub_k_gy);

    let rep = match rsgx_create_report(&ti, &report_data) {
        Ok(r) => {
            // println!("Report creation => success {:?}", r.body.mr_signer.m);
            Some(r)
        }
        Err(e) => {
            // println!("Report creation => failed {:?}", e);
            return Err(e);
        }
    };

    let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut quote_nonce.rand);
    // println!("rand finished");
    let mut qe_report = sgx_report_t::default();
    const RET_QUOTE_BUF_LEN: u32 = 2048;
    let mut return_quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
    let mut quote_len: u32 = 0;

    // (3) Generate the quote
    // Args:
    //       1. sigrl: ptr + len
    //       2. report: ptr 432bytes
    //       3. linkable: u32, unlinkable=0, linkable=1
    //       4. spid: sgx_spid_t ptr 16bytes (retrieved inside the app)
    //       5. sgx_quote_nonce_t ptr 16bytes
    //       6. p_sig_rl + sigrl size ( same to sigrl)
    //       7. [out]p_qe_report need further check
    //       8. [out]p_quote
    //       9. quote_size
    let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
        (ptr::null(), 0)
    } else {
        (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
    };
    let p_report = (&rep.unwrap()) as *const sgx_report_t;
    let quote_type = sign_type;

    let p_nonce = &quote_nonce as *const sgx_quote_nonce_t;
    let p_qe_report = &mut qe_report as *mut sgx_report_t;
    let p_quote = return_quote_buf.as_mut_ptr();
    let maxlen = RET_QUOTE_BUF_LEN;
    let p_quote_len = &mut quote_len as *mut u32;

    let result = unsafe {
        ocall_get_quote(
            &mut rt as *mut sgx_status_t,
            p_sigrl,
            sigrl_len,
            p_report,
            quote_type,
            p_nonce,
            p_qe_report,
            p_quote,
            maxlen,
            p_quote_len,
        )
    };

    if result != sgx_status_t::SGX_SUCCESS {
        return Err(result);
    }
    if rt != sgx_status_t::SGX_SUCCESS {
        // println!("ocall_get_quote returned {}", rt);
        return Err(rt);
    }

    // Added 09-28-2018
    // Perform a check on qe_report to verify if the qe_report is valid
    match rsgx_verify_report(&qe_report) {
        Ok(()) => {
            // println!("rsgx_verify_report passed!")
        }
        Err(x) => {
            // println!("rsgx_verify_report failed with {:?}", x);
            return Err(x);
        }
    }

    // Check if the qe_report is produced on the same platform
    if ti.mr_enclave.m != qe_report.body.mr_enclave.m
        || ti.attributes.flags != qe_report.body.attributes.flags
        || ti.attributes.xfrm != qe_report.body.attributes.xfrm
    {
        // println!("qe_report does not match current target_info!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    // println!("qe_report check passed");

    // Debug
    // for i in 0..quote_len {
    //     print!("{:02X}", unsafe {*p_quote.offset(i as isize)});
    // }
    // println!("");

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.

    let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
    rhs_vec.extend(&return_quote_buf[..quote_len as usize]);
    let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).unwrap();
    let lhs_hash = &qe_report.body.report_data.d[..32];

    // println!("rhs hash = {:02X}", rhs_hash.iter().format(""));
    // println!("report hs= {:02X}", lhs_hash.iter().format(""));

    if rhs_hash != lhs_hash {
        // println!("Quote is tampered!");
        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
    }

    let quote_vec: Vec<u8> = return_quote_buf[..quote_len as usize].to_vec();
    let res =
        unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

    if res != sgx_status_t::SGX_SUCCESS {
        return Err(res);
    }

    if rt != sgx_status_t::SGX_SUCCESS {
        return Err(rt);
    }

    let (attn_report, sig, cert) = get_report_from_intel(ias_key, ias_sock, quote_vec);
    Ok((attn_report, sig, cert))
}

#[inline]
fn check_unseal(
    view_key: PublicKey,
    txids: &[TxId],
    mut sealed_logs: Vec<Vec<u8>>,
) -> Option<Vec<TxWithOutputs>> {
    let mut return_result = Vec::with_capacity(sealed_logs.len());
    for (txid, sealed_log) in txids.iter().zip(sealed_logs.iter_mut()) {
        if sealed_log.len() >= (std::u32::MAX as usize) {
            return None;
        }
        let opt = unsafe {
            SgxSealedData::<[u8]>::from_raw_sealed_data_t(
                sealed_log.as_mut_ptr() as *mut sgx_sealed_data_t,
                sealed_log.len() as u32,
            )
        };
        let sealed_data = match opt {
            Some(x) => x,
            None => {
                return None;
            }
        };
        let result = sealed_data.unseal_data();
        let unsealed_data = match result {
            Ok(x) => x,
            Err(_) => {
                return None;
            }
        };
        if unsealed_data.get_additional_txt() != txid {
            // TODO: zeroize unsealed_data
            return None;
        }
        let otx = TxWithOutputs::decode(&mut unsealed_data.get_decrypt_txt());
        let push: bool;
        match &otx {
            Ok(TxWithOutputs::Transfer(Tx {
                attributes: TxAttributes { allowed_view, .. },
                ..
            })) => {
                // TODO: policy != alldata
                push = allowed_view.iter().any(|x| x.view_key == view_key);
            }
            Ok(TxWithOutputs::StakeWithdraw(WithdrawUnbondedTx {
                attributes: TxAttributes { allowed_view, .. },
                ..
            })) => {
                // TODO: policy != alldata
                push = allowed_view.iter().any(|x| x.view_key == view_key);
            }
            _ => {
                return None;
            }
        }
        if push {
            return_result.push(otx.unwrap());
        }
    }
    Some(return_result)
}

fn process_request(body: &DecryptionRequestBody) -> Option<DecryptionResponse> {
    let txids_enc = body.txs.encode();
    // TODO: check tx size
    let mut inputs_buf = vec![0u8; body.txs.len() * 8000];
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ocall_get_txs(
            &mut rt as *mut sgx_status_t,
            txids_enc.as_ptr(),
            txids_enc.len() as u32,
            inputs_buf.as_mut_ptr(),
            inputs_buf.len() as u32,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS || rt != sgx_status_t::SGX_SUCCESS {
        return None;
    }
    let inputs_enc: Result<Vec<Vec<u8>>, parity_scale_codec::Error> =
        Decode::decode(&mut inputs_buf.as_slice());
    if let Ok(inputs) = inputs_enc {
        check_unseal(body.view_key, &body.txs, inputs).map(|txs| DecryptionResponse { txs })
    } else {
        None
    }
}

#[no_mangle]
pub extern "C" fn run_server(socket_fd: c_int) -> sgx_status_t {
    // FIXME: cache cert+attestation report
    let mut ias_key = "00000000000000000000000000000000".to_owned();
    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let result = unsafe {
        ocall_get_ias_key(
            &mut rt as *mut sgx_status_t,
            ias_key.as_mut_ptr(),
            ias_key.len() as u32,
        )
    };
    if result != sgx_status_t::SGX_SUCCESS
        || rt != sgx_status_t::SGX_SUCCESS
        || !ias_key.chars().all(|x| x.is_alphanumeric())
    {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }

    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let (attn_report, sig, cert) = match create_attestation_report(
        &pub_k,
        &ias_key,
        sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE,
    ) {
        Ok(r) => r,
        Err(e) => {
            // println!("Error in create_attestation_report: {:?}", e);
            return e;
        }
    };

    let payload = attn_report + "|" + &sig + "|" + &cert;
    let (key_der, cert_der) = match cert::gen_ecc_cert(payload, &prv_k, &pub_k, &ecc_handle) {
        Ok(r) => r,
        Err(e) => {
            // println!("Error in gen_ecc_cert: {:?}", e);
            return e;
        }
    };
    let _result = ecc_handle.close();

    // FIXME: client auth?
    let authenticator = rustls::NoClientAuth::new();
    let mut cfg = rustls::ServerConfig::new(authenticator);
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();

    let mut sess = rustls::ServerSession::new(&Arc::new(cfg));
    let mut conn = TcpStream::new(socket_fd).unwrap();
    let _ = conn.set_read_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
    let _ = conn.set_write_timeout(Some(Duration::new(TIMEOUT_SEC, 0)));
    let mut tls = rustls::Stream::new(&mut sess, &mut conn);
    let mut challenge = [0u8; 32];
    let mut os_rng = os::SgxRng::new().unwrap();
    os_rng.fill_bytes(&mut challenge);
    if let Err(_) = tls.write(&challenge[..]) {
        let _ = conn.shutdown(Shutdown::Both);
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let mut plain = vec![0; 1024];
    match tls.read(&mut plain) {
        Ok(_) => {
            if let Ok(dr) = DecryptionRequest::decode(&mut plain.as_slice()) {
                if dr
                    .verify(&Secp256k1::verification_only(), challenge)
                    .is_err()
                {
                    let _ = conn.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
                if let Some(reply) = process_request(&dr.body) {
                    let _ = tls.write(&reply.encode());
                } else {
                    let _ = conn.shutdown(Shutdown::Both);
                    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
                }
            } else {
                let _ = conn.shutdown(Shutdown::Both);
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
        }
        Err(_) => {
            // println!("Error in read_to_end: {:?}", e);
            let _ = conn.shutdown(Shutdown::Both);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    sgx_status_t::SGX_SUCCESS
}
