//! Integration tests

#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, trivial_casts, unused_qualifications)]

#[cfg(feature = "untested")]
use cipher::common::getrandom::SysRng;
use cipher::common::Generate;
use log::trace;
use once_cell::sync::Lazy;
use rsa::{pkcs1v15, RsaPublicKey};
use sha2::{Digest, Sha256};
use signature::hazmat::PrehashVerifier;
use std::{env, ops::Range, str::FromStr, sync::Mutex, time::Duration};
use x509_cert::{der::Encode, name::Name, serial_number::SerialNumber, time::Validity};
use yubikey::{
    certificate::{yubikey_signer, Certificate},
    piv::{self, AlgorithmId, Key, ManagementSlotId, RetiredSlotId, SlotId},
    Error, MgmKey, PinPolicy, Serial, TouchPolicy, YubiKey,
};

/// Read a DER tag+length and return the byte range of the full TLV and the offset after it.
fn der_tlv_range(data: &[u8], start: usize) -> (Range<usize>, usize) {
    let mut pos = start + 1; // skip tag
    let len = if data[pos] < 0x80 {
        let l = data[pos] as usize;
        pos += 1;
        l
    } else {
        let num_bytes = (data[pos] & 0x7f) as usize;
        pos += 1;
        let mut l = 0usize;
        for i in 0..num_bytes {
            l = (l << 8) | data[pos + i] as usize;
        }
        pos += num_bytes;
        l
    };
    let end = pos + len;
    (start..end, end)
}

/// Extract the raw TBS certificate byte range and signature bytes from a DER-encoded certificate.
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
fn extract_tbs_and_signature(data: &[u8]) -> (Range<usize>, &[u8]) {
    // Skip outer SEQUENCE tag+length
    let content_start = if data[1] < 0x80 {
        2
    } else {
        2 + (data[1] & 0x7f) as usize
    };
    // First element: TBS Certificate SEQUENCE
    let (tbs_range, after_tbs) = der_tlv_range(data, content_start);
    // Second element: Signature Algorithm SEQUENCE — skip it
    let (_, after_sig_alg) = der_tlv_range(data, after_tbs);
    // Third element: Signature Value BIT STRING
    let (sig_range, _) = der_tlv_range(data, after_sig_alg);
    // BIT STRING content starts with a pad-bits byte (0x00), skip it
    let sig_content_start = if data[sig_range.start + 1] < 0x80 {
        sig_range.start + 2 + 1 // tag + 1-byte length + pad byte
    } else {
        let num = (data[sig_range.start + 1] & 0x7f) as usize;
        sig_range.start + 2 + num + 1 // tag + length-of-length + length bytes + pad byte
    };
    (tbs_range, &data[sig_content_start..sig_range.end])
}

static YUBIKEY: Lazy<Mutex<YubiKey>> = Lazy::new(|| {
    // Only show logs if `RUST_LOG` is set
    if env::var("RUST_LOG").is_ok() {
        env_logger::builder().format_timestamp(None).init();
    }

    let yubikey = if let Ok(serial) = env::var("YUBIKEY_SERIAL") {
        let serial = Serial::from_str(&serial).unwrap();
        YubiKey::open_by_serial(serial).unwrap()
    } else {
        YubiKey::open().unwrap()
    };

    trace!("serial: {}", yubikey.serial());
    trace!("version: {}", yubikey.version());

    Mutex::new(yubikey)
});

//
// CCCID support
//

#[test]
#[ignore]
fn test_get_cccid() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    match yubikey.cccid() {
        Ok(cccid) => trace!("CCCID: {:?}", cccid),
        Err(Error::NotFound) => trace!("CCCID not found"),
        Err(err) => panic!("error getting CCCID: {err:?}"),
    }
}

//
// CHUID support
//

#[test]
#[ignore]
fn test_get_chuid() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };

    match yubikey.chuid() {
        Ok(chuid) => trace!("CHUID: {:?}", chuid),
        Err(Error::NotFound) => trace!("CHUID not found"),
        Err(err) => panic!("error getting CHUID: {err:?}"),
    }
}

//
// Device config support
//

#[test]
#[ignore]
fn test_get_config() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let config_result = yubikey.config();
    assert!(config_result.is_ok());
    trace!("config: {:?}", config_result.unwrap());
}

//
// Cryptographic key support
//

#[test]
#[ignore]
fn test_list_keys() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let keys_result = Key::list(&mut yubikey);
    assert!(keys_result.is_ok());
    trace!("keys: {:?}", keys_result.unwrap());
}

//
// PIN support
//

#[test]
#[ignore]
fn test_verify_pin() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    assert!(yubikey.verify_pin(b"000000").is_err());
    assert!(yubikey.verify_pin(b"123456").is_ok());
}

//
// Management key support
//

#[cfg(feature = "untested")]
#[test]
#[ignore]
fn test_set_mgmkey() {
    let mut rng = SysRng;
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let default_key = MgmKey::get_default(&yubikey).unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(&default_key).is_ok());

    // Set a protected management key.
    assert!(MgmKey::generate_for(&yubikey, &mut rng)
        .unwrap()
        .set_protected(&mut yubikey)
        .is_ok());
    let protected = MgmKey::get_protected(&mut yubikey).unwrap();
    assert!(yubikey.authenticate(&default_key).is_err());
    assert!(yubikey.authenticate(&protected).is_ok());

    // Set a manual management key.
    let manual = MgmKey::generate_for(&yubikey, &mut rng).unwrap();
    assert!(manual.set_manual(&mut yubikey, false).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(&default_key).is_err());
    assert!(yubikey.authenticate(&protected).is_err());
    assert!(yubikey.authenticate(&manual).is_ok());

    // Set back to the default management key.
    assert!(MgmKey::set_default(&mut yubikey).is_ok());
    assert!(MgmKey::get_protected(&mut yubikey).is_err());
    assert!(yubikey.authenticate(&protected).is_err());
    assert!(yubikey.authenticate(&manual).is_err());
    assert!(yubikey.authenticate(&default_key).is_ok());
}

//
// Certificate support
//

fn generate_self_signed_cert<KT: yubikey_signer::KeyType>() -> Certificate {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let default_key = MgmKey::get_default(&yubikey).unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(&default_key).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        KT::ALGORITHM,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    // 0x80 0x00 ... (20bytes) is invalid because of high MSB (serial will keep the sign)
    // we'll limit ourselves to 19 bytes serial.
    let serial = <[u8; 19]>::generate();
    let serial = SerialNumber::new(&serial[..]).expect("serial can't be more than 20 bytes long");
    let validity = Validity::from_now(Duration::new(500000, 0)).unwrap();

    // Generate a self-signed certificate for the new key.
    let cert_result = Certificate::generate_self_signed::<_, KT>(
        &mut yubikey,
        slot,
        serial,
        validity,
        Name::from_str("CN=testSubject").expect("parse name"),
        generated,
        |_builder| Ok(()),
    );

    assert!(cert_result.is_ok());
    let cert = cert_result.unwrap();
    trace!("cert: {:?}", cert);
    cert
}

#[test]
#[ignore]
fn generate_self_signed_rsa_cert() {
    let cert = generate_self_signed_cert::<yubikey_signer::YubiRsa<yubikey_signer::Rsa1024>>();

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey = RsaPublicKey::try_from(cert.subject_pki()).expect("valid rsa key");
    let pubkey = pkcs1v15::VerifyingKey::<Sha256>::new(pubkey);

    let data = cert.cert.to_der().expect("serialize certificate");
    let tbs_cert_len = u16::from_be_bytes(data[6..8].try_into().unwrap()) as usize;
    let msg = &data[4..8 + tbs_cert_len];
    let sig = pkcs1v15::Signature::try_from(&data[data.len() - 128..]).unwrap();
    let hash = Sha256::digest(msg);

    assert!(pubkey.verify_prehash(&hash, &sig).is_ok());
}

#[test]
#[ignore]
fn generate_rsa3072() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let version = yubikey.version();
    let default_key = MgmKey::get_default(&yubikey).unwrap();

    assert!(yubikey.authenticate(&default_key).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::Rsa3072,
        PinPolicy::Default,
        TouchPolicy::Default,
    );

    match generated {
        Ok(key) => {
            let pubkey = key.subject_public_key;
            assert!(pubkey.bit_len() > 3072)
        }
        Err(e) => assert!((version.major, version.minor) < (5, 7) && e == Error::AlgorithmError),
    }
}

#[test]
#[ignore]
fn generate_self_signed_ec_cert() {
    let cert = generate_self_signed_cert::<p256::NistP256>();

    //
    // Verify that the certificate is signed correctly
    //

    let vk = p256::ecdsa::VerifyingKey::try_from(cert.subject_pki()).expect("ecdsa key expected");

    let data = cert.cert.to_der().expect("serialize certificate");
    let tbs_cert_len = data[6] as usize;
    let sig_algo_len = data[7 + tbs_cert_len + 1] as usize;
    let sig_start = 7 + tbs_cert_len + 2 + sig_algo_len + 3;
    let msg = &data[4..7 + tbs_cert_len];
    let sig = p256::ecdsa::Signature::from_der(&data[sig_start..]).unwrap();

    use p256::ecdsa::signature::Verifier;
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
#[ignore]
fn generate_self_signed_cv_cert() {
    let cert = generate_self_signed_cert::<ed25519_dalek::SigningKey>();

    //
    // Verify that the certificate is signed correctly
    //

    let pubkey =
        ed25519_dalek::VerifyingKey::try_from(cert.subject_pki()).expect("ed25519 key expected");

    // Extract raw TBS bytes and signature from the DER-encoded certificate.
    // YubiKey PIV pre-hashes TBS with SHA-512 before Ed25519 signing,
    // so we must extract the original TBS bytes to reproduce that hash.
    let data = cert.cert.to_der().expect("serialize certificate");
    let (tbs_range, sig_bytes) = extract_tbs_and_signature(&data);
    let sig = ed25519_dalek::Signature::from_slice(sig_bytes).unwrap();

    // YubiKey PIV signs SHA-512(TBS) as the Ed25519 message, so verify against the hash.
    use ed25519_dalek::Verifier;
    use sha2::Sha512;
    let hash = Sha512::digest(&data[tbs_range]);
    assert!(pubkey.verify(&hash, &sig).is_ok());
}

#[test]
fn test_slot_id_display() {
    assert_eq!(format!("{}", SlotId::Authentication), "Authentication");
    assert_eq!(format!("{}", SlotId::Signature), "Signature");
    assert_eq!(format!("{}", SlotId::KeyManagement), "KeyManagement");
    assert_eq!(
        format!("{}", SlotId::CardAuthentication),
        "CardAuthentication"
    );
    assert_eq!(format!("{}", SlotId::Attestation), "Attestation");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R1)), "R1");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R2)), "R2");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R3)), "R3");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R4)), "R4");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R5)), "R5");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R6)), "R6");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R7)), "R7");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R8)), "R8");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R9)), "R9");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R10)), "R10");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R11)), "R11");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R12)), "R12");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R13)), "R13");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R14)), "R14");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R15)), "R15");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R16)), "R16");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R17)), "R17");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R18)), "R18");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R19)), "R19");
    assert_eq!(format!("{}", SlotId::Retired(RetiredSlotId::R20)), "R20");

    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Pin)),
        "Pin"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Puk)),
        "Puk"
    );
    assert_eq!(
        format!("{}", SlotId::Management(ManagementSlotId::Management)),
        "Management"
    );
}

//
// Metadata
//

#[test]
#[ignore]
fn test_read_metadata() {
    let mut yubikey = match YUBIKEY.lock() {
        Ok(yubikey) => yubikey,
        Err(poison) => poison.into_inner(),
    };
    let default_key = MgmKey::get_default(&yubikey).unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(&default_key).is_ok());

    let slot = SlotId::Retired(RetiredSlotId::R1);

    // Generate a new key in the selected slot.
    let generated = piv::generate(
        &mut yubikey,
        slot,
        AlgorithmId::EccP256,
        PinPolicy::Default,
        TouchPolicy::Default,
    )
    .unwrap();

    match piv::metadata(&mut yubikey, slot) {
        Ok(metadata) => assert_eq!(metadata.public, Some(generated)),
        Err(Error::NotSupported) => {
            // Some YubiKeys don't support metadata
            eprintln!("metadata not supported by this YubiKey");
        }
        Err(err) => panic!("{}", err),
    }
}

#[test]
#[ignore]
fn test_read_metadata_missing_key() {
    let mut yubikey = YUBIKEY.lock().unwrap();
    let default_key = MgmKey::get_default(&yubikey).unwrap();

    assert!(yubikey.verify_pin(b"123456").is_ok());
    assert!(yubikey.authenticate(&default_key).is_ok());

    // we assume that at least one of these slots is empty
    let slots_to_check = [
        RetiredSlotId::R10,
        RetiredSlotId::R11,
        RetiredSlotId::R12,
        RetiredSlotId::R13,
        RetiredSlotId::R14,
        RetiredSlotId::R15,
        RetiredSlotId::R16,
        RetiredSlotId::R17,
        RetiredSlotId::R18,
        RetiredSlotId::R19,
        RetiredSlotId::R20,
    ];

    for slot in slots_to_check {
        let slot = SlotId::Retired(slot);

        match piv::metadata(&mut yubikey, slot) {
            Ok(_) => {
                eprintln!("Key {} exists", slot);
            }
            Err(Error::NotSupported) => {
                // Some YubiKeys don't support metadata
                eprintln!("metadata not supported by this YubiKey");
                return;
            }
            Err(Error::NotFound) => {
                eprintln!("Key {} doesn't exist, ok.", slot);
                return;
            }
            Err(err) => panic!("{}", err),
        }
    }

    panic!("No empty slots to check");
}

#[test]
fn test_parse_cert_from_der() {
    let bob_der = std::fs::read("tests/assets/Bob.der").expect(".der file not found");
    let cert = Certificate::from_bytes(bob_der).expect("Failed to parse valid certificate");
    assert_eq!(
        cert.subject(),
        "CN=Bob",
        "Subject is {} should be CN=Bob",
        cert.subject()
    );
    assert_eq!(
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA",
        "Issuer is {} should be {}",
        cert.issuer(),
        "CN=Ferdinand Linnenberg CA"
    );
}
