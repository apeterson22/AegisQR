use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use aegisqr_core::{
    deny_execution_message, export_qr_packets, import_qr_packets, inspect_header, pack_to_file,
    stage_capsule, unpack_capsule, verify_capsule, ClientPolicy, CompressionProfile, PackOptions,
    PayloadType, TrustStore,
};
use anyhow::{bail, Context, Result};
use zeroize::Zeroize;

fn main() -> Result<()> {
    println!("AegisQR Interface");
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
    println!("  8) Exit");

    let choice = read_line("Enter number")?;
    match choice.trim() {
        "1" => Ok(MenuAction::Pack),
        "2" => Ok(MenuAction::Inspect),
        "3" => Ok(MenuAction::Verify),
        "4" => Ok(MenuAction::Unpack),
        "5" => Ok(MenuAction::Stage),
        "6" => Ok(MenuAction::ExportQr),
        "7" => Ok(MenuAction::ImportQr),
        "8" => Ok(MenuAction::Exit),
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
    let payload_type = if parse_yes_no(&read_line("Treat input as AICX archive? [y/N]")?)? {
        Some(PayloadType::AicxArchive)
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
    let header = inspect_header(&bundle)?;
    println!("{}", serde_json::to_string_pretty(&header)?);
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
