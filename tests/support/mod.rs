//! Throwaway signing keys for the FCM (RS256) and APNS (ES256) tests,
//! generated at test time so no private key is ever committed to the
//! repository or shipped in the crate tarball.

#![allow(dead_code)]

use std::sync::OnceLock;

use aws_lc_rs::encoding::AsDer;
use base64::Engine;

fn pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A fresh RSA-2048 private key, PKCS#8 PEM. Generated once per test binary.
pub fn rsa_private_key_pem() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = aws_lc_rs::rsa::KeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048)
            .expect("generate RSA test key");
        let der = key.as_der().expect("encode RSA test key");
        pem("PRIVATE KEY", der.as_ref())
    })
}

/// A fresh P-256 private key, PKCS#8 PEM (the form `jsonwebtoken`'s
/// `EncodingKey::from_ec_pem` and Apple's `.p8` files use).
pub fn ec_private_key_pem() -> &'static str {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let doc = aws_lc_rs::signature::EcdsaKeyPair::generate_pkcs8(
            &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("generate P-256 test key");
        pem("PRIVATE KEY", doc.as_ref())
    })
}
