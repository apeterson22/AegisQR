use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use anyhow::{bail, Context, Result};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const ROOT_LICENSE_PUBKEY: &str = "66be7e332c7a453332bd9d0a7f7db055f5c5ef1a06ada66d98b39fb6810c473a";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct CustomerInfo {
    pub organization: String,
    pub domain: String,
    pub contact_email: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PlanInfo {
    pub tier: String,
    pub seats: u32,
    pub usage: Vec<String>,
    pub support_level: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ValidityInfo {
    pub issued_at: String, // ISO 8601, e.g. "2026-05-25T00:00:00Z"
    pub expires_at: String, // ISO 8601
    pub grace_days: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FeaturesInfo {
    pub commercial_use: bool,
    pub offline_use: bool,
    pub enterprise_strict_mode: bool,
    pub scenario_reports: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignatureInfo {
    pub alg: String,
    pub kid: String,
    pub sig: String, // base64url encoded
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LicenseFile {
    pub schema: String,
    pub license_id: String,
    pub customer: CustomerInfo,
    pub plan: PlanInfo,
    pub validity: ValidityInfo,
    pub features: FeaturesInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LicenseStatus {
    pub status: String, // "valid", "expired", "grace_period", "unlicensed"
    pub license_id: Option<String>,
    pub organization: Option<String>,
    pub tier: Option<String>,
    pub seats: Option<u32>,
    pub expires_at: Option<String>,
    pub days_remaining: Option<i64>,
}

pub fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

pub fn parse_iso8601_to_unix(s: &str) -> Result<u64> {
    if s.len() < 20 || !s.ends_with('Z') {
        bail!("invalid ISO 8601 format (must end with Z)");
    }
    let parts: Vec<&str> = s[..s.len() - 1].split('T').collect();
    if parts.len() != 2 {
        bail!("invalid ISO 8601 format");
    }
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if date_parts.len() != 3 || time_parts.len() != 3 {
        bail!("invalid ISO 8601 format");
    }
    let year: i32 = date_parts[0].parse().context("invalid year")?;
    let month: u32 = date_parts[1].parse().context("invalid month")?;
    let day: u32 = date_parts[2].parse().context("invalid day")?;
    let hour: u64 = time_parts[0].parse().context("invalid hour")?;
    let min: u64 = time_parts[1].parse().context("invalid min")?;
    let sec: u64 = time_parts[2].parse().context("invalid sec")?;

    let mut days = 0;
    for y in 1970..year {
        if is_leap_year(y) {
            days += 366;
        } else {
            days += 365;
        }
    }
    let month_days = if is_leap_year(year) {
        [0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 1..month {
        days += month_days[m as usize];
    }
    days += day as u64 - 1;

    Ok(days * 86400 + hour * 3600 + min * 60 + sec)
}

pub fn get_license_search_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(val) = std::env::var("AEGISQR_LICENSE_PATH") {
        paths.push(PathBuf::from(val));
    }
    paths.push(PathBuf::from("/etc/aegisqr/license.aqlic"));
    if let Ok(home) = std::env::var("HOME") {
        paths.push(PathBuf::from(format!("{}/.config/aegisqr/license.aqlic", home)));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        paths.push(PathBuf::from(format!("{}/.config/aegisqr/license.aqlic", userprofile)));
    }
    paths.push(PathBuf::from("./license.aqlic"));
    paths.push(PathBuf::from("./.aegisqr.aqlic"));
    paths
}

pub fn get_trusted_keys_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.push(PathBuf::from("/etc/aegisqr/trusted_keys.d"));
    if let Ok(home) = std::env::var("HOME") {
        dirs.push(PathBuf::from(format!("{}/.config/aegisqr/trusted_keys.d", home)));
    }
    if let Ok(userprofile) = std::env::var("USERPROFILE") {
        dirs.push(PathBuf::from(format!("{}/.config/aegisqr/trusted_keys.d", userprofile)));
    }
    dirs.push(PathBuf::from("./trusted_keys.d"));
    dirs
}

pub fn load_trusted_keys() -> BTreeMap<String, Vec<u8>> {
    let mut keys = BTreeMap::new();
    // 1. Load the hardcoded root verification key
    if let Ok(root_bytes) = hex::decode(ROOT_LICENSE_PUBKEY) {
        keys.insert("license-root-2026".to_string(), root_bytes);
    }
    // 2. Load keys from dynamic rotation directories
    for dir in get_trusted_keys_dirs() {
        if dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                            if let Ok(content) = fs::read_to_string(&path) {
                                if let Ok(bytes) = hex::decode(content.trim()) {
                                    keys.insert(stem.to_string(), bytes);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    keys
}

pub fn check_license_integrity(license: &LicenseFile) -> Result<()> {
    let signature_info = license.signature.as_ref().context("license is unsigned")?;
    if signature_info.alg != "Ed25519" {
        bail!("unsupported license signature algorithm: {}", signature_info.alg);
    }

    let trusted_keys = load_trusted_keys();
    let pubkey_bytes = trusted_keys
        .get(&signature_info.kid)
        .ok_or_else(|| anyhow::anyhow!("unknown license signing key ID (kid): {}", signature_info.kid))?;

    // Create canonical representation by removing signature field
    let mut canonical = license.clone();
    canonical.signature = None;
    let canonical_bytes = serde_json::to_vec(&canonical).context("failed to serialize canonical license")?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signature_info.sig)
        .context("invalid base64url license signature")?;

    let ver_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into()?)
        .context("invalid public key format")?;
    let signature = Signature::from_slice(&sig_bytes).context("invalid signature format")?;

    ver_key
        .verify(&canonical_bytes, &signature)
        .context("cryptographic offline license signature verification failed")?;

    Ok(())
}

pub fn verify_license_status(current_time_secs: u64) -> LicenseStatus {
    let mut _found_path = None;
    let mut loaded_license: Option<LicenseFile> = None;

    for path in get_license_search_paths() {
        if path.is_file() {
            if let Ok(bytes) = fs::read(path.clone()) {
                if let Ok(lic) = serde_json::from_slice::<LicenseFile>(&bytes) {
                    if check_license_integrity(&lic).is_ok() {
                        _found_path = Some(path);
                        loaded_license = Some(lic);
                        break;
                    }
                }
            }
        }
    }

    let lic = match loaded_license {
        Some(l) => l,
        None => return LicenseStatus {
            status: "unlicensed".to_string(),
            license_id: None,
            organization: None,
            tier: None,
            seats: None,
            expires_at: None,
            days_remaining: None,
        },
    };

    let expires_secs = match parse_iso8601_to_unix(&lic.validity.expires_at) {
        Ok(t) => t,
        Err(_) => return LicenseStatus {
            status: "unlicensed".to_string(),
            license_id: None,
            organization: None,
            tier: None,
            seats: None,
            expires_at: None,
            days_remaining: None,
        },
    };

    let grace_secs = lic.validity.grace_days as u64 * 86400;

    let time_diff = expires_secs as i64 - current_time_secs as i64;
    let days_remaining = time_diff / 86400;

    let status = if current_time_secs < expires_secs {
        "valid".to_string()
    } else if current_time_secs < expires_secs + grace_secs {
        "grace_period".to_string()
    } else {
        "expired".to_string()
    };

    LicenseStatus {
        status,
        license_id: Some(lic.license_id),
        organization: Some(lic.customer.organization),
        tier: Some(lic.plan.tier),
        seats: Some(lic.plan.seats),
        expires_at: Some(lic.validity.expires_at),
        days_remaining: Some(days_remaining),
    }
}

pub fn handle_license_reminders(current_time_secs: u64) {
    let status = verify_license_status(current_time_secs);
    match status.status.as_str() {
        "grace_period" => {
            let grace_limit = status.days_remaining.unwrap_or(0) + 30; // simple fallback
            eprintln!(
                "WARNING: License expired. Running in grace period: {} days remaining.",
                grace_limit
            );
        }
        "expired" | "unlicensed" => {
            // Humorous weekly reminder based on unix time day mod 7
            let epoch_days = current_time_secs / 86400;
            let day_of_week = (epoch_days + 4) % 7; // 0 = Sunday, 1 = Monday, ..., 6 = Saturday
            if day_of_week == 1 {
                eprintln!(
                    "Weekly unlicensed trial reminder: The developers are running critically low on premium roasted coffee beans. Please donate at https://aegisqr.app/donate to prevent the code from becoming sleepy! ☕"
                );
            }
        }
        _ => {}
    }
}
