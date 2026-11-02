use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::{verify_retail_payload, RetailPayload, TrustStore};

/// Validates standard GS1 GTIN check digit (GTIN-8, GTIN-12/UPC, GTIN-13/EAN, GTIN-14).
pub fn validate_gtin_check_digit(gtin: &str) -> bool {
    let clean: String = gtin.chars().filter(|c| c.is_ascii_digit()).collect();
    if clean.len() < 8 || clean.len() > 14 {
        return false;
    }

    let digits: Vec<u32> = clean.chars().map(|c| c.to_digit(10).unwrap()).collect();
    let n = digits.len();
    let check_digit = digits[n - 1];

    let mut sum = 0;
    // Iterate from right to left (excluding the check digit)
    let mut multiplier = 3;
    for i in (0..n - 1).rev() {
        sum += digits[i] * multiplier;
        multiplier = if multiplier == 3 { 1 } else { 3 };
    }

    let calculated_check = (10 - (sum % 10)) % 10;
    calculated_check == check_digit
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gs1DigitalLink {
    pub domain: String,
    pub gtin: String,
    pub serial: Option<String>,
    pub lot: Option<String>,
    pub store_gln: Option<String>,
    pub raw_url: String,
    pub aegis_payload_b64: Option<String>,
}

/// Parses a GS1 Digital Link standard URI (e.g. `https://brand.com/01/00012345678905/21/SER12345?p=...`).
pub fn parse_gs1_digital_link(url: &str) -> Result<Gs1DigitalLink> {
    let trimmed = url.trim();
    let (url_without_query, query_part) = match trimmed.split_once('?') {
        Some((path, q)) => (path, Some(q)),
        None => (trimmed, None),
    };

    let domain = if let Some(stripped) = url_without_query.strip_prefix("https://") {
        stripped.split('/').next().unwrap_or("")
    } else if let Some(stripped) = url_without_query.strip_prefix("http://") {
        stripped.split('/').next().unwrap_or("")
    } else {
        url_without_query.split('/').next().unwrap_or("")
    };

    let segments: Vec<&str> = url_without_query
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    let mut gtin: Option<String> = None;
    let mut serial: Option<String> = None;

    // Standard GS1 Digital Link path pairs: /01/{gtin}/21/{serial}
    let mut i = 0;
    while i < segments.len() {
        if segments[i] == "01" && i + 1 < segments.len() {
            gtin = Some(segments[i + 1].to_string());
            i += 2;
        } else if segments[i] == "21" && i + 1 < segments.len() {
            serial = Some(segments[i + 1].to_string());
            i += 2;
        } else {
            i += 1;
        }
    }

    let gtin_val = gtin.ok_or_else(|| {
        anyhow::anyhow!("GS1 Digital Link URI does not contain AI 01 GTIN segment")
    })?;

    let mut lot: Option<String> = None;
    let mut store_gln: Option<String> = None;
    let mut aegis_payload_b64: Option<String> = None;

    if let Some(query) = query_part {
        for param in query.split('&') {
            if let Some((k, v)) = param.split_once('=') {
                match k {
                    "10" => lot = Some(v.to_string()),
                    "414" => store_gln = Some(v.to_string()),
                    "p" => aegis_payload_b64 = Some(v.to_string()),
                    _ => {}
                }
            }
        }
    }

    Ok(Gs1DigitalLink {
        domain: domain.to_string(),
        gtin: gtin_val,
        serial,
        lot,
        store_gln,
        raw_url: trimmed.to_string(),
        aegis_payload_b64,
    })
}

/// Builds a GS1 Digital Link standard URI containing both GS1 path components and Aegis cryptographic payload.
pub fn build_gs1_digital_link(
    base_domain: &str,
    gtin: &str,
    serial: Option<&str>,
    lot: Option<&str>,
    store_gln: Option<&str>,
    aegis_payload_b64: &str,
) -> Result<String> {
    let clean_domain = base_domain.trim_end_matches('/');
    let mut path = format!("{clean_domain}/01/{gtin}");
    if let Some(s) = serial {
        path.push_str(&format!("/21/{s}"));
    }

    let mut query_params = Vec::new();
    if let Some(l) = lot {
        query_params.push(format!("10={l}"));
    }
    if let Some(g) = store_gln {
        query_params.push(format!("414={g}"));
    }
    query_params.push(format!("p={aegis_payload_b64}"));

    Ok(format!("{}?{}", path, query_params.join("&")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedGs1Product {
    pub gtin: String,
    pub serial: Option<String>,
    pub lot: Option<String>,
    pub store_gln: Option<String>,
    pub verified_retail_payload: RetailPayload,
    pub check_digit_valid: bool,
    pub path_gtin_matches_payload: bool,
}

/// Verifies a complete GS1 Digital Link URI:
/// 1. Validates standard GS1 syntax and GTIN check digit.
/// 2. Cryptographically verifies the embedded Ed25519 signature payload in `?p=`.
/// 3. Confirms the URI path GTIN matches the payload SKU/UPC.
pub fn verify_gs1_digital_link(
    url: &str,
    trust_store: &TrustStore,
    current_time_secs: u64,
) -> Result<VerifiedGs1Product> {
    let gs1 = parse_gs1_digital_link(url)?;
    let check_digit_valid = validate_gtin_check_digit(&gs1.gtin);

    let p_b64 = gs1.aegis_payload_b64.as_ref().ok_or_else(|| {
        anyhow::anyhow!("GS1 Digital Link missing 'p' cryptographic envelope parameter")
    })?;

    let verified_payload = verify_retail_payload(p_b64, trust_store, current_time_secs)?;

    // Verify URI path GTIN matches SKU or UPC in the signed envelope
    let gtin_normalized = gs1.gtin.trim_start_matches('0');
    let sku_normalized = verified_payload.sku.trim_start_matches('0');
    let upc_normalized = verified_payload
        .upc
        .as_deref()
        .map(|u| u.trim_start_matches('0'))
        .unwrap_or("");

    let path_gtin_matches = gtin_normalized == sku_normalized
        || (!upc_normalized.is_empty() && gtin_normalized == upc_normalized);

    if !path_gtin_matches {
        bail!(
            "Tamper alert: GS1 path GTIN '{}' does not match cryptographically signed SKU '{}'",
            gs1.gtin,
            verified_payload.sku
        );
    }

    Ok(VerifiedGs1Product {
        gtin: gs1.gtin,
        serial: gs1.serial,
        lot: gs1.lot,
        store_gln: gs1.store_gln,
        verified_retail_payload: verified_payload,
        check_digit_valid,
        path_gtin_matches_payload: path_gtin_matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gtin_check_digit() {
        assert!(validate_gtin_check_digit("00012345678905")); // GTIN-14
        assert!(validate_gtin_check_digit("012345678905")); // GTIN-12 / UPC
        assert!(validate_gtin_check_digit("9780201379624")); // GTIN-13 / ISBN
        assert!(!validate_gtin_check_digit("00012345678901")); // bad check digit
    }

    #[test]
    fn test_gs1_roundtrip() {
        let url =
            "https://aegisqr.app/01/012345678905/21/SER-9021?10=LOT-4A&414=STORE-01&p=TEST_PAYLOAD";
        let parsed = parse_gs1_digital_link(url).unwrap();
        assert_eq!(parsed.gtin, "012345678905");
        assert_eq!(parsed.serial.as_deref(), Some("SER-9021"));
        assert_eq!(parsed.lot.as_deref(), Some("LOT-4A"));
        assert_eq!(parsed.store_gln.as_deref(), Some("STORE-01"));
        assert_eq!(parsed.aegis_payload_b64.as_deref(), Some("TEST_PAYLOAD"));

        let built = build_gs1_digital_link(
            "https://aegisqr.app",
            "012345678905",
            Some("SER-9021"),
            Some("LOT-4A"),
            Some("STORE-01"),
            "TEST_PAYLOAD",
        )
        .unwrap();
        assert_eq!(built, url);
    }
}
