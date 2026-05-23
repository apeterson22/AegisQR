use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use aegisqr_core::{
    approve_capsule, deny_execution_message, export_qr_packets, import_qr_packets, inspect_full,
    pack_to_file, stage_capsule, unpack_capsule, verify_capsule, AicxSidecar, ClientPolicy,
    CompressionProfile, PackOptions, PayloadType, TrustStore,
};
use aegisqr_repo::{
    validate_handoff_package, AuthConfig, AuthType, HandoffPackage, HandoffState,
    RepositoryCoordinates,
};
use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

fn main() -> Result<()> {
    println!("AegisQR Interface — Enterprise Edition");
    println!("Secure defaults: scan/decrypt/restore never execute payloads.");

    loop {
        match prompt_menu()? {
            MenuAction::Pack => {
                if let Err(err) = run_pack() {
                    eprintln!("Pack failed: {err:#}");
                }
            }
            MenuAction::Inspect => {
                if let Err(err) = run_inspect() {
                    eprintln!("Inspect failed: {err:#}");
                }
            }
            MenuAction::Verify => {
                if let Err(err) = run_verify() {
                    eprintln!("Verify failed: {err:#}");
                }
            }
            MenuAction::Unpack => {
                if let Err(err) = run_unpack(false) {
                    eprintln!("Unpack failed: {err:#}");
                }
            }
            MenuAction::Stage => {
                if let Err(err) = run_unpack(true) {
                    eprintln!("Stage failed: {err:#}");
                }
            }
            MenuAction::ExportQr => {
                if let Err(err) = run_export_qr() {
                    eprintln!("Export failed: {err:#}");
                }
            }
            MenuAction::ImportQr => {
                if let Err(err) = run_import_qr() {
                    eprintln!("Import failed: {err:#}");
                }
            }
            MenuAction::Approve => {
                if let Err(err) = run_approve() {
                    eprintln!("Approve failed: {err:#}");
                }
            }
            MenuAction::Handoff => {
                if let Err(err) = run_handoff() {
                    eprintln!("Handoff failed: {err:#}");
                }
            }
            MenuAction::Exit => break,
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum MenuAction {
    Pack,
    Inspect,
    Verify,
    Unpack,
    Stage,
    ExportQr,
    ImportQr,
    Approve,
    Handoff,
    Exit,
}

fn prompt_menu() -> Result<MenuAction> {
    println!();
    println!("Choose an action:");
    println!("  1) Pack");
    println!("  2) Inspect");
    println!("  3) Verify");
    println!("  4) Unpack");
    println!("  5) Stage");
    println!("  6) Export QR");
    println!("  7) Import QR");
    println!("  8) Approve capsule");
    println!("  9) Prepare handoff");
    println!(" 10) Exit");

    let choice = read_line("Enter number")?;
    match choice.trim() {
        "1" => Ok(MenuAction::Pack),
        "2" => Ok(MenuAction::Inspect),
        "3" => Ok(MenuAction::Verify),
        "4" => Ok(MenuAction::Unpack),
        "5" => Ok(MenuAction::Stage),
        "6" => Ok(MenuAction::ExportQr),
        "7" => Ok(MenuAction::ImportQr),
        "8" => Ok(MenuAction::Approve),
        "9" => Ok(MenuAction::Handoff),
        "10" => Ok(MenuAction::Exit),
        _ => bail!("invalid menu choice"),
    }
}

fn run_pack() -> Result<()> {
    let input = read_existing_path("Input file/directory path")?;
    let out = read_path("Output bundle path (.aqr)")?;
    let mut passphrase = read_passphrase("Passphrase")?;
    let mut passphrase_confirm = read_passphrase("Confirm passphrase")?;
    if passphrase != passphrase_confirm {
        passphrase.zeroize();
        passphrase_confirm.zeroize();
        bail!("passphrases do not match");
    }
    passphrase_confirm.zeroize();

    let compression = parse_compression(&read_line("Compression [none|fast|balanced|qr-basic]")?)?;
    let is_aicx = parse_yes_no(&read_line("Treat input as AICX archive? [y/N]")?)?;
    let payload_type = if is_aicx {
        Some(PayloadType::AicxArchive)
    } else {
        None
    };

    let aicx_sidecar = if is_aicx && parse_yes_no(&read_line("Embed AICX sidecar JSON? [y/N]")?)? {
        let sidecar_path = read_existing_path("AICX sidecar JSON path")?;
        let bytes = fs::read(&sidecar_path)?;
        Some(serde_json::from_slice::<AicxSidecar>(&bytes)?)
    } else {
        None
    };

    let auto_execute_capable = parse_yes_no(&read_line(
        "Mark capsule auto-execute capable metadata? [y/N]",
    )?)?;
    let auto_execute_requested = if auto_execute_capable {
        parse_yes_no(&read_line("Request auto-execution metadata? [y/N]")?)?
    } else {
        false
    };

    let options = PackOptions {
        compression,
        auto_execute_capable,
        auto_execute_requested,
        payload_type,
        aicx_sidecar,
        ..PackOptions::default()
    };

    let cap = pack_to_file(&input, &out, &passphrase, options)?;
    passphrase.zeroize();

    println!("Packed {} -> {}", input.display(), out.display());
    println!("bundle_id={}", cap.public_header.bundle_id);
    Ok(())
}

fn run_inspect() -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;
    let report = inspect_full(&bundle)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn run_verify() -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;
    let strict_trust = parse_yes_no(&read_line("Require strict trust store validation? [y/N]")?)?;
    let trust_store =
        if strict_trust || parse_yes_no(&read_line("Provide trust store file? [y/N]")?)? {
            let path = read_existing_path("Trust store JSON path")?;
            let bytes = fs::read(path)?;
            Some(serde_json::from_slice::<TrustStore>(&bytes)?)
        } else {
            None
        };

    verify_capsule(&bundle, trust_store.as_ref(), strict_trust)?;
    println!("Verification succeeded");
    Ok(())
}

fn run_unpack(stage_only: bool) -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;
    let out = read_path("Output directory path")?;
    let mut passphrase = read_passphrase("Passphrase")?;

    if stage_only {
        stage_capsule(&bundle, &out, &passphrase)?;
        println!("Staged to {}", out.display());
        println!("{}", deny_execution_message(&ClientPolicy::default(), true));
    } else {
        unpack_capsule(&bundle, &out, &passphrase)?;
        println!("Unpacked to {}", out.display());
    }
    passphrase.zeroize();
    Ok(())
}

fn run_export_qr() -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;
    let out = read_path("Output QR directory path")?;
    let packet_size = parse_packet_size(&read_line("Packet size bytes [default 800]")?)?;
    let png = parse_yes_no(&read_line("Generate PNG QR images? [y/N]")?)?;
    export_qr_packets(&bundle, &out, packet_size, png)?;
    println!("Exported QR packets to {}", out.display());
    Ok(())
}

fn run_import_qr() -> Result<()> {
    let qr_dir = read_existing_path("QR packet directory path")?;
    if !qr_dir.is_dir() {
        bail!("QR packet path must be a directory");
    }
    let out = read_path("Output reconstructed capsule path")?;
    import_qr_packets(&qr_dir, &out)?;
    println!("Imported QR packets -> {}", out.display());
    Ok(())
}

fn run_approve() -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;

    let approver_id = {
        let v = read_line("Approver ID (must match an entry in enterprise_policy.approvers)")?;
        if v.is_empty() {
            bail!("approver ID cannot be empty");
        }
        v
    };

    let key_path = read_existing_path("Signing key file path (hex-encoded 32-byte Ed25519 seed)")?;
    let seed = load_signing_key(&key_path)?;

    let overwrite = parse_yes_no(&read_line("Overwrite input bundle? [y/N]")?)?;
    let out = if overwrite {
        bundle.clone()
    } else {
        read_path("Output bundle path")?
    };

    let token = approve_capsule(&bundle, &approver_id, &seed, &out)?;
    println!("Approval token appended");
    println!("  approver_id : {}", token.approver_id);
    println!("  approved_at : {}", token.approved_at);
    println!("  bundle_id   : {}", token.bundle_id);
    println!("Written to {}", out.display());
    Ok(())
}

fn run_handoff() -> Result<()> {
    let bundle = read_existing_path("Bundle path (.aqr)")?;

    // Extract embedded AICX sidecar.
    let capsule = aegisqr_core::read_capsule_file(&bundle)?;
    let aicx_sidecar = capsule.agent_index.aicx_sidecar.ok_or_else(|| {
        anyhow::anyhow!("no AICX sidecar embedded — pack with an AICX sidecar JSON first")
    })?;

    println!("Target repository coordinates:");
    let repo_type_str = read_line("Repo type [artifactory|nexus]")?;
    let repo_type = match repo_type_str.trim().to_ascii_lowercase().as_str() {
        "nexus" => aegisqr_core::RepoType::Nexus,
        _ => aegisqr_core::RepoType::Artifactory,
    };
    let base_url = {
        let v = read_line("Base URL (e.g. https://repo.example.com)")?;
        if v.is_empty() {
            bail!("base URL cannot be empty");
        }
        v
    };
    let repository = read_line("Repository name")?;
    let group = read_line("Group / namespace")?;
    let name = read_line("Artifact name")?;
    let version = read_line("Version")?;
    let classifier = {
        let v = read_line("Classifier (optional, press Enter to skip)")?;
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };

    let target_coords = RepositoryCoordinates {
        repo_type,
        base_url,
        repository,
        group,
        name,
        version,
        classifier,
    };

    let trust_store = if parse_yes_no(&read_line("Provide trust store file? [y/N]")?)? {
        let path = read_existing_path("Trust store JSON path")?;
        let bytes = fs::read(path)?;
        Some(serde_json::from_slice::<TrustStore>(&bytes)?)
    } else {
        None
    };

    let out = read_path("Output handoff-package.json path [handoff-package.json]")
        .unwrap_or_else(|_| PathBuf::from("handoff-package.json"));

    let pkg = HandoffPackage {
        capsule_path: bundle,
        aicx_sidecar,
        audit_log: capsule.audit_log,
        approval_tokens: vec![],
        target_coords,
        auth_config: Some(AuthConfig {
            auth_type: AuthType::Bearer,
            token: None,
        }),
        serialization_profile: aegisqr_repo::SerializationProfile::Json,
    };

    let result = validate_handoff_package(&pkg, trust_store.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&result.event)?);

    match &result.state {
        HandoffState::Approved => println!("\nState: APPROVED — ready for plugin ingestion"),
        HandoffState::AwaitingApproval => {
            println!("\nState: AWAITING APPROVAL — add more approval tokens first")
        }
        HandoffState::Failed(msg) => println!("\nState: FAILED — {msg}"),
        other => println!("\nState: {}", serde_json::to_string(other)?),
    }

    let dry_run = parse_yes_no(&read_line("Dry run only? (skip writing file) [y/N]")?)?;
    if !dry_run {
        let json = serde_json::to_string_pretty(&pkg)?;
        fs::write(&out, json)?;
        println!("Written to {}", out.display());
    }
    Ok(())
}

/// Reads and hex-decodes a 32-byte Ed25519 seed from `path`.
fn load_signing_key(path: &std::path::Path) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)?;
    let bytes = hex::decode(raw.trim())
        .map_err(|e| anyhow::anyhow!("signing key file is not valid hex: {e}"))?;
    if bytes.len() != 32 {
        bail!(
            "signing key must be 32 bytes ({} bytes decoded, expected 32)",
            bytes.len()
        );
    }
    Ok(bytes)
}

fn read_path(prompt: &str) -> Result<PathBuf> {
    let line = read_line(prompt)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        bail!("path cannot be empty");
    }
    Ok(PathBuf::from(trimmed))
}

fn read_existing_path(prompt: &str) -> Result<PathBuf> {
    let path = read_path(prompt)?;
    if !path.exists() {
        bail!("path does not exist: {}", path.display());
    }
    Ok(path)
}

fn read_passphrase(prompt: &str) -> Result<String> {
    let pass = rpassword::prompt_password(format!("{prompt}: "))?;
    if pass.is_empty() {
        bail!("passphrase cannot be empty");
    }
    Ok(pass)
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{prompt}: ");
    io::stdout().flush().context("failed to flush prompt")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("failed to read input")?;
    Ok(input.trim().to_string())
}

fn parse_packet_size(value: &str) -> Result<usize> {
    if value.trim().is_empty() {
        return Ok(800);
    }
    let parsed = value
        .trim()
        .parse::<usize>()
        .context("packet size must be an integer")?;
    if parsed == 0 {
        bail!("packet size must be greater than zero");
    }
    Ok(parsed)
}

fn parse_yes_no(value: &str) -> Result<bool> {
    let v = value.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "n" | "no" => Ok(false),
        "y" | "yes" => Ok(true),
        _ => bail!("expected y/yes or n/no"),
    }
}

fn parse_compression(value: &str) -> Result<CompressionProfile> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "balanced" => Ok(CompressionProfile::Balanced),
        "none" => Ok(CompressionProfile::None),
        "fast" => Ok(CompressionProfile::Fast),
        "qr-basic" => Ok(CompressionProfile::QrBasic),
        _ => bail!("invalid compression profile"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_packet_size_defaults_and_rejects_zero() {
        assert_eq!(parse_packet_size("").unwrap(), 800);
        assert_eq!(parse_packet_size("512").unwrap(), 512);
        assert!(parse_packet_size("0").is_err());
    }

    #[test]
    fn parse_yes_no_accepts_common_inputs() {
        assert!(parse_yes_no("y").unwrap());
        assert!(parse_yes_no("YES").unwrap());
        assert!(!parse_yes_no("").unwrap());
        assert!(!parse_yes_no("no").unwrap());
        assert!(parse_yes_no("maybe").is_err());
    }

    #[test]
    fn parse_compression_choices() {
        assert!(matches!(
            parse_compression("").unwrap(),
            CompressionProfile::Balanced
        ));
        assert!(matches!(
            parse_compression("fast").unwrap(),
            CompressionProfile::Fast
        ));
        assert!(parse_compression("ultra").is_err());
    }
}
