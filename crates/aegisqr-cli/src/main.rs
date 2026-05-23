use std::fs;
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
use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "aegisqr")]
#[command(about = "AegisQR secure QR-native capsule CLI — AICX/Enterprise edition")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Pack(PackArgs),
    Inspect {
        bundle: PathBuf,
    },
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        strict_trust: bool,
        #[arg(long)]
        trust_store: Option<PathBuf>,
    },
    Unpack(UnpackArgs),
    Stage(UnpackArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    /// Append a signed approval token to a capsule.
    ///
    /// The signing key file must contain a hex-encoded 32-byte Ed25519 seed
    /// (64 ASCII hex characters).  Generate one with `aegisqr keygen`.
    Approve(ApproveArgs),
    /// Validate and prepare a handoff package for the Artifactory/Nexus plugin.
    ///
    /// Reads the capsule, extracts the embedded AICX sidecar, validates all
    /// approval tokens, and writes a `handoff-package.json` for the plugin.
    Handoff(HandoffArgs),
    /// Generate a new Ed25519 signing key (hex-encoded 32-byte seed).
    Keygen {
        /// Output file path for the hex-encoded key seed.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args, Debug)]
struct PackArgs {
    input: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    passphrase: String,
    #[arg(long, default_value = "balanced")]
    compression: String,
    #[arg(long)]
    aicx: bool,
    /// Path to an AICX sidecar JSON file to embed in the capsule.
    ///
    /// Required when `--aicx` is set and sidecar validation is desired.
    /// The sidecar's `manifest_hash` must match the BLAKE3 hash of the
    /// `.aicx` archive if the field is non-empty.
    #[arg(long)]
    aicx_sidecar: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    auto_execute_capable: bool,
    #[arg(long, default_value_t = false)]
    auto_execute_requested: bool,
}

#[derive(Args, Debug)]
struct UnpackArgs {
    bundle: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long)]
    passphrase: String,
}

#[derive(Subcommand, Debug)]
enum ExportSub {
    Qr {
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 800)]
        packet_size: usize,
        #[arg(long, default_value_t = false)]
        png: bool,
    },
}

#[derive(Args, Debug)]
struct ExportArgs {
    #[command(subcommand)]
    sub: ExportSub,
}

#[derive(Args, Debug)]
struct ImportArgs {
    #[command(subcommand)]
    sub: ImportSub,
}

#[derive(Subcommand, Debug)]
enum ImportSub {
    Qr {
        qr_dir: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Args, Debug)]
struct ApproveArgs {
    bundle: PathBuf,
    /// Approver identity string (must match an entry in the capsule's
    /// `enterprise_policy.approvers` to count towards the minimum).
    #[arg(long)]
    signer_id: String,
    /// Path to the hex-encoded 32-byte Ed25519 signing key seed file.
    #[arg(long)]
    signing_key: PathBuf,
    /// Output path.  Defaults to overwriting the input bundle.
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct HandoffArgs {
    bundle: PathBuf,
    /// Path to a JSON file containing `RepositoryCoordinates`.
    #[arg(long)]
    target_coords: PathBuf,
    /// Output path for the handoff-package.json.
    #[arg(long, default_value = "handoff-package.json")]
    out: PathBuf,
    /// Validate only; do not write the handoff package.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
    #[arg(long)]
    trust_store: Option<PathBuf>,
    /// Preferred serialization profile (`json` or `toon`).
    #[arg(long, default_value = "json")]
    serialization_profile: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Pack(args) => {
            let compression = parse_compression(&args.compression);
            let payload_type = if args.aicx {
                Some(PayloadType::AicxArchive)
            } else {
                None
            };
            let aicx_sidecar = if let Some(path) = args.aicx_sidecar {
                let bytes = fs::read(&path)?;
                Some(serde_json::from_slice::<AicxSidecar>(&bytes)?)
            } else {
                None
            };
            let mut passphrase = args.passphrase;
            let options = PackOptions {
                compression,
                auto_execute_capable: args.auto_execute_capable,
                auto_execute_requested: args.auto_execute_requested,
                payload_type,
                aicx_sidecar,
                ..PackOptions::default()
            };
            let cap = pack_to_file(&args.input, &args.out, &passphrase, options)?;
            passphrase.zeroize();
            println!("Packed {} -> {}", args.input.display(), args.out.display());
            println!("bundle_id={}", cap.public_header.bundle_id);
        }

        Commands::Inspect { bundle } => {
            let report = inspect_full(&bundle)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }

        Commands::Verify {
            bundle,
            strict_trust,
            trust_store,
        } => {
            let trust = if let Some(path) = trust_store {
                let bytes = fs::read(path)?;
                Some(serde_json::from_slice::<TrustStore>(&bytes)?)
            } else {
                None
            };
            verify_capsule(&bundle, trust.as_ref(), strict_trust)?;
            println!("Verification succeeded");
        }

        Commands::Unpack(args) => {
            let mut passphrase = args.passphrase;
            unpack_capsule(&args.bundle, &args.out, &passphrase)?;
            passphrase.zeroize();
            println!("Unpacked to {}", args.out.display());
        }

        Commands::Stage(args) => {
            let mut passphrase = args.passphrase;
            stage_capsule(&args.bundle, &args.out, &passphrase)?;
            passphrase.zeroize();
            println!("Staged to {}", args.out.display());
            println!("{}", deny_execution_message(&ClientPolicy::default(), true));
        }

        Commands::Export(args) => match args.sub {
            ExportSub::Qr {
                bundle,
                out,
                packet_size,
                png,
            } => {
                export_qr_packets(&bundle, &out, packet_size, png)?;
                println!("Exported QR packets to {}", out.display());
            }
        },

        Commands::Import(args) => match args.sub {
            ImportSub::Qr { qr_dir, out } => {
                import_qr_packets(&qr_dir, &out)?;
                println!("Imported QR packets -> {}", out.display());
            }
        },

        Commands::Approve(args) => {
            let seed = load_signing_key(&args.signing_key)?;
            let out = args.out.as_ref().unwrap_or(&args.bundle);
            let token = approve_capsule(&args.bundle, &args.signer_id, &seed, out)?;
            println!("Approval token appended");
            println!("approver_id={}", token.approver_id);
            println!("approved_at={}", token.approved_at);
            println!("bundle_id={}", token.bundle_id);
            println!("Written to {}", out.display());
        }

        Commands::Handoff(args) => {
            let coords_bytes = fs::read(&args.target_coords)?;
            let target_coords = serde_json::from_slice::<RepositoryCoordinates>(&coords_bytes)?;

            let trust = if let Some(path) = args.trust_store {
                let bytes = fs::read(path)?;
                Some(serde_json::from_slice::<TrustStore>(&bytes)?)
            } else {
                None
            };

            // Extract AICX sidecar from the capsule agent_index.
            let capsule = aegisqr_core::read_capsule_file(&args.bundle)?;
            let aicx_sidecar = capsule.agent_index.aicx_sidecar.ok_or_else(|| {
                anyhow::anyhow!(
                    "no AICX sidecar embedded in capsule — pack with --aicx-sidecar first"
                )
            })?;

            let serialization_profile = parse_serialization_profile(&args.serialization_profile);

            let pkg = HandoffPackage {
                capsule_path: args.bundle.clone(),
                aicx_sidecar,
                audit_log: capsule.audit_log,
                approval_tokens: vec![], // external tokens; capsule tokens are read internally
                target_coords,
                auth_config: Some(AuthConfig {
                    auth_type: AuthType::Bearer,
                    token: None, // plugin fills this from its credential store
                }),
                serialization_profile,
            };

            let result = validate_handoff_package(&pkg, trust.as_ref())?;
            let state_json = serde_json::to_string_pretty(&result.event)?;
            println!("{state_json}");

            match &result.state {
                HandoffState::Approved => {
                    println!("\nHandoff state: APPROVED — ready for plugin ingestion")
                }
                HandoffState::AwaitingApproval => println!("\nHandoff state: AWAITING APPROVAL"),
                HandoffState::Failed(msg) => bail!("Handoff validation failed: {msg}"),
                other => println!("\nHandoff state: {}", serde_json::to_string(other)?),
            }

            if !args.dry_run {
                let json = serde_json::to_string_pretty(&pkg)?;
                fs::write(&args.out, json)?;
                println!("Written to {}", args.out.display());
            }
        }

        Commands::Keygen { out } => {
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);
            let hex_key = hex::encode(seed);
            fs::write(&out, &hex_key)?;
            println!("Ed25519 key seed written to {}", out.display());
            println!("Keep this file secret — it is your signing credential.");
        }
    }

    Ok(())
}

fn parse_compression(s: &str) -> CompressionProfile {
    match s {
        "none" => CompressionProfile::None,
        "fast" => CompressionProfile::Fast,
        "balanced" => CompressionProfile::Balanced,
        "qr-basic" => CompressionProfile::QrBasic,
        _ => CompressionProfile::Balanced,
    }
}

fn parse_serialization_profile(s: &str) -> aegisqr_repo::SerializationProfile {
    match s.to_ascii_lowercase().as_str() {
        "toon" => aegisqr_repo::SerializationProfile::Toon,
        _ => aegisqr_repo::SerializationProfile::Json,
    }
}

/// Reads a hex-encoded 32-byte Ed25519 seed from `path`.
fn load_signing_key(path: &PathBuf) -> Result<Vec<u8>> {
    let raw = fs::read_to_string(path)?;
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed)
        .map_err(|e| anyhow::anyhow!("signing key file is not valid hex: {e}"))?;
    if bytes.len() != 32 {
        bail!(
            "signing key must be a 32-byte Ed25519 seed ({} bytes after hex decode, expected 32)",
            bytes.len()
        );
    }
    Ok(bytes)
}
