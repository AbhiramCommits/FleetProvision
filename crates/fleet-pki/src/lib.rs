//! FleetProvision internal certificate authority.
//!
//! The CA hierarchy is deliberately small: an offline root, an online
//! intermediate used for everyday issuance, and short-lived leaf certificates
//! bound to node identity through DNS and SPIFFE-like URI SANs.

use rand::RngCore;

/// Generate a random 128-bit certificate serial number, encoded as lowercase
/// hex. RFC 5280 requires positive integers; the top bit is therefore cleared.
pub fn random_serial_hex() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[0] &= 0x7f;
    // A zero serial is illegal; force a non-zero leading byte.
    if bytes[0] == 0 {
        bytes[0] = 1;
    }
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn serials_are_128_bit_and_nonzero() {
        let mut seen = HashSet::new();
        for _ in 0..256 {
            let serial = random_serial_hex();
            assert_eq!(serial.len(), 32);
            let first = u8::from_str_radix(&serial[..2], 16).unwrap();
            assert_eq!(first & 0x80, 0, "top bit must be clear for a positive int");
            assert_ne!(first, 0, "serial must be non-zero");
            assert!(seen.insert(serial), "serials must not repeat");
        }
    }
}
