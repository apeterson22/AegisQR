use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const ESL_MAGIC: u8 = 0xAE;
pub const ESL_VERSION: u8 = 0x01;
pub const ESL_PACKET_LEN: usize = 89;

pub const ESL_FLAG_ASSOCIATE_GATED: u8 = 1 << 0;
pub const ESL_FLAG_SALE_ACTIVE: u8 = 1 << 1;
pub const ESL_FLAG_HAS_EXPIRY: u8 = 1 << 2;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EslData {
    pub retailer_id_hash: u32,
    pub sku_numeric: u64,
    pub store_id: u16,
    pub price_cents: u32,
    pub expires_at: u32,
    pub is_associate_gated: bool,
    pub is_sale_active: bool,
}

/// Encodes and signs an Electronic Shelf Label (ESL) compact 89-byte binary packet.
pub fn encode_esl_packet(data: &EslData, signing_key_bytes: &[u8]) -> Result<Vec<u8>> {
    let signing_key = SigningKey::from_bytes(
        signing_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid signing key length (must be 32 bytes)"))?,
    );

    let mut buf = Vec::with_capacity(ESL_PACKET_LEN);
    buf.push(ESL_MAGIC);
    buf.push(ESL_VERSION);

    let mut flags = 0u8;
    if data.is_associate_gated {
        flags |= ESL_FLAG_ASSOCIATE_GATED;
    }
    if data.is_sale_active {
        flags |= ESL_FLAG_SALE_ACTIVE;
    }
    if data.expires_at > 0 {
        flags |= ESL_FLAG_HAS_EXPIRY;
    }
    buf.push(flags);

    buf.extend_from_slice(&data.retailer_id_hash.to_be_bytes());
    buf.extend_from_slice(&data.sku_numeric.to_be_bytes());
    buf.extend_from_slice(&data.store_id.to_be_bytes());
    buf.extend_from_slice(&data.price_cents.to_be_bytes());
    buf.extend_from_slice(&data.expires_at.to_be_bytes());

    // Sign the 25-byte header/data section
    let sig: Signature = signing_key.sign(&buf);
    buf.extend_from_slice(&sig.to_bytes());

    debug_assert_eq!(buf.len(), ESL_PACKET_LEN);
    Ok(buf)
}

/// Decodes and verifies an Electronic Shelf Label (ESL) binary packet.
pub fn decode_esl_packet(
    packet: &[u8],
    verifying_key_bytes: &[u8],
    current_time_secs: u64,
) -> Result<EslData> {
    if packet.len() != ESL_PACKET_LEN {
        bail!(
            "invalid ESL packet length: expected {} bytes, got {}",
            ESL_PACKET_LEN,
            packet.len()
        );
    }

    if packet[0] != ESL_MAGIC {
        bail!(
            "invalid ESL packet magic: expected 0x{:02X}, got 0x{:02X}",
            ESL_MAGIC,
            packet[0]
        );
    }
    if packet[1] != ESL_VERSION {
        bail!("unsupported ESL packet version: {}", packet[1]);
    }

    let flags = packet[2];
    let is_associate_gated = (flags & ESL_FLAG_ASSOCIATE_GATED) != 0;
    let is_sale_active = (flags & ESL_FLAG_SALE_ACTIVE) != 0;
    let has_expiry = (flags & ESL_FLAG_HAS_EXPIRY) != 0;

    let retailer_id_hash = u32::from_be_bytes(packet[3..7].try_into().unwrap());
    let sku_numeric = u64::from_be_bytes(packet[7..15].try_into().unwrap());
    let store_id = u16::from_be_bytes(packet[15..17].try_into().unwrap());
    let price_cents = u32::from_be_bytes(packet[17..21].try_into().unwrap());
    let expires_at = u32::from_be_bytes(packet[21..25].try_into().unwrap());

    if has_expiry && expires_at > 0 && current_time_secs > (expires_at as u64) {
        bail!(
            "ESL packet has expired (expired at {}, current time {})",
            expires_at,
            current_time_secs
        );
    }

    let ver_key = VerifyingKey::from_bytes(
        verifying_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid verifying key length (must be 32 bytes)"))?,
    )?;

    let header_data = &packet[0..25];
    let sig = Signature::from_slice(&packet[25..89]).context("invalid ESL signature format")?;

    ver_key
        .verify(header_data, &sig)
        .context("ESL packet cryptographic signature verification failed")?;

    Ok(EslData {
        retailer_id_hash,
        sku_numeric,
        store_id,
        price_cents,
        expires_at,
        is_associate_gated,
        is_sale_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esl_roundtrip_and_verify() {
        let key_bytes = [0x07u8; 32];
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let pubkey_bytes = signing_key.verifying_key().to_bytes();

        let data = EslData {
            retailer_id_hash: 0xA1B2C3D4,
            sku_numeric: 100234567890,
            store_id: 452,
            price_cents: 1999, // $19.99
            expires_at: 2000000000,
            is_associate_gated: false,
            is_sale_active: true,
        };

        let packet = encode_esl_packet(&data, &key_bytes).unwrap();
        assert_eq!(packet.len(), ESL_PACKET_LEN);

        let decoded = decode_esl_packet(&packet, &pubkey_bytes, 1700000000).unwrap();
        assert_eq!(decoded, data);

        // Test tampering rejection
        let mut tampered = packet.clone();
        tampered[20] ^= 0xFF; // tamper price
        assert!(decode_esl_packet(&tampered, &pubkey_bytes, 1700000000).is_err());
    }
}
