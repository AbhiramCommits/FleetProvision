//! TPM quote construction, digest computation, and signature verification.

use crate::types::TpmQuote;
use crate::AttestError;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Quote digest: SHA-256 over `index_byte || pcr_value` for each selected PCR,
/// in ascending index order.
pub fn compute_quote_digest(
    selection: &[u8],
    values: &BTreeMap<String, String>,
) -> Result<String, AttestError> {
    let mut indices: Vec<u8> = selection.to_vec();
    indices.sort_unstable();
    indices.dedup();
    let mut hasher = Sha256::new();
    for index in indices {
        let value = values
            .get(&index.to_string())
            .ok_or(AttestError::MissingPcr(index))?;
        let bytes =
            hex::decode(value).map_err(|e| AttestError::BadDigest(value.clone(), e.to_string()))?;
        if bytes.len() != 32 {
            return Err(AttestError::BadDigest(
                value.clone(),
                "expected 32 bytes".into(),
            ));
        }
        hasher.update([index]);
        hasher.update(bytes);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Message signed by the AK: the raw nonce bytes followed by the raw quote
/// digest bytes. ECDSA-SHA256 hashes this message internally.
pub fn quote_message(nonce_hex: &str, digest_hex: &str) -> Result<Vec<u8>, AttestError> {
    let nonce = hex::decode(nonce_hex).map_err(|e| AttestError::BadNonce(e.to_string()))?;
    let digest = hex::decode(digest_hex)
        .map_err(|e| AttestError::BadDigest(digest_hex.into(), e.to_string()))?;
    let mut message = nonce;
    message.extend(digest);
    Ok(message)
}

pub fn sign_quote(
    key: &SigningKey,
    nonce_hex: &str,
    digest_hex: &str,
) -> Result<String, AttestError> {
    let message = quote_message(nonce_hex, digest_hex)?;
    let signature: Signature = key.sign(&message);
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_der().as_bytes()))
}

/// Verify the quote signature using the AK certificate's public key. The
/// caller is responsible for separately validating the AK certificate chain.
pub fn verify_quote_signature(ak_cert_pem: &str, quote: &TpmQuote) -> Result<(), AttestError> {
    let der = pem::parse(ak_cert_pem)
        .map_err(|e| AttestError::AkCertificate(format!("PEM parse: {e}")))?
        .into_contents();
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| AttestError::AkCertificate(format!("X.509 parse: {e}")))?;
    let verifying_key = VerifyingKey::from_public_key_der(cert.public_key().raw)
        .map_err(|e| AttestError::AkCertificate(format!("public key: {e}")))?;
    let sig_der = base64::engine::general_purpose::STANDARD
        .decode(&quote.signature)
        .map_err(|e| AttestError::QuoteSignature(e.to_string()))?;
    let signature =
        Signature::from_der(&sig_der).map_err(|e| AttestError::QuoteSignature(e.to_string()))?;
    let message = quote_message(&quote.nonce, &quote.digest)?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|e| AttestError::QuoteSignature(e.to_string()))
}

pub fn decode_key(pem_str: &str) -> Result<SigningKey, AttestError> {
    SigningKey::from_pkcs8_pem(pem_str).map_err(|e| AttestError::Key(format!("PKCS#8 parse: {e}")))
}

/// Encode a P-256 signing key as PKCS#8 PEM (test/simulated TPM material).
pub fn encode_key(key: &SigningKey) -> Result<String, AttestError> {
    key.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map(|zeroizing| zeroizing.to_string())
        .map_err(|e| AttestError::Key(e.to_string()))
}
