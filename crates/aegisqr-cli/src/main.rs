use std::fs;
use std::io::{self, BufRead, IsTerminal, Read};
use std::path::{Path, PathBuf};

use aegisqr_core::{
    deny_execution_message, export_qr_packets, import_qr_packets, pack_to_file, stage_capsule,
    unpack_capsule, verify_capsule, ClientPolicy, CompressionProfile, PackOptions, PayloadType,
    TrustStore,
};
use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use zeroize::Zeroize;

const PASSPHRASE_ENV_VAR: &str = "AEGISQR_PASSPHRASE";
const MAX_STDIN_PASSPHRASE_BYTES: u64 = 4096;
const PASSPHRASE_HELP: &str =
    "Passphrases are never accepted on the command line. By default, AegisQR prompts with hidden \
input. For automation, pipe the passphrase over stdin and pass --passphrase-stdin. \
AEGISQR_PASSPHRASE is rejected because environment variables may be exposed to other processes.";

#[derive(Parser, Debug)]
#[command(name = "aegisqr")]
#[command(version = "0.1.0-featured")]
#[command(about = "AegisQR secure QR-native capsule CLI")]
#[command(after_help = PASSPHRASE_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    #[command(after_help = PASSPHRASE_HELP)]
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
    #[command(after_help = PASSPHRASE_HELP)]
    Unpack(UnpackArgs),
    #[command(after_help = PASSPHRASE_HELP)]
    Stage(UnpackArgs),
    Export(ExportArgs),
    Import(ImportArgs),
    PackRetail(Box<PackRetailArgs>),
    VerifyRetail(VerifyRetailArgs),
    PackGs1(Box<PackGs1Args>),
    VerifyGs1(VerifyGs1Args),
    Esl {
        #[command(subcommand)]
        sub: EslSub,
    },
    Custody {
        #[command(subcommand)]
        sub: CustodySub,
    },
    ScanDaemon(ScanDaemonArgs),
    License {
        #[command(subcommand)]
        sub: LicenseSub,
    },
}

#[derive(Subcommand, Debug)]
enum LicenseSub {
    Status {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Install {
        path: PathBuf,
    },
    Show {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct PackArgs {
    input: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[arg(long, default_value = "balanced")]
    compression: String,
    #[arg(long)]
    aicx: bool,
    #[arg(long)]
    aicx_sidecar: Option<PathBuf>,
    #[arg(long, default_value_t = false)]
    aicx_strict: bool,
    #[arg(long, default_value_t = false)]
    auto_execute_capable: bool,
    #[arg(long, default_value_t = false)]
    auto_execute_requested: bool,
    #[command(flatten)]
    passphrase: PassphraseArgs,
}

#[derive(Args, Debug)]
struct PackRetailArgs {
    #[arg(long)]
    retailer_id: String,
    #[arg(long)]
    sku: String,
    #[arg(long)]
    upc: Option<String>,
    #[arg(long)]
    store_id: String,
    #[arg(long)]
    aisle: Option<String>,
    #[arg(long)]
    bay: Option<String>,
    #[arg(long)]
    shelf: Option<String>,
    #[arg(long)]
    campaign_id: Option<String>,
    #[arg(long)]
    experience_id: Option<String>,
    #[arg(long)]
    role: Option<String>,
    #[arg(long, default_value_t = 1)]
    label_version: u32,
    #[arg(long, default_value_t = 0)]
    expires_in_secs: u64,
    #[arg(long)]
    fallback_url_id: Option<String>,
    #[arg(long)]
    privkey: String,
    #[arg(long)]
    kid: String,
    #[arg(long, default_value = "https://aegisqr.app/qr/product")]
    base_url: String,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct VerifyRetailArgs {
    #[arg(long)]
    url_file: PathBuf,
    #[arg(long)]
    pubkey: String,
    #[arg(long)]
    kid: String,
    #[arg(long, default_value_t = false)]
    authenticated_associate: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct PackGs1Args {
    #[arg(long, default_value = "https://id.aegisqr.app")]
    domain: String,
    #[arg(long)]
    gtin: String,
    #[arg(long)]
    serial: Option<String>,
    #[arg(long)]
    lot: Option<String>,
    #[arg(long)]
    store_gln: Option<String>,
    #[arg(long)]
    retailer_id: String,
    #[arg(long)]
    store_id: String,
    #[arg(long)]
    sku: Option<String>,
    #[arg(long)]
    privkey: String,
    #[arg(long)]
    kid: String,
    #[arg(long, default_value_t = 0)]
    expires_in_secs: u64,
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct VerifyGs1Args {
    #[arg(long)]
    url_file: Option<PathBuf>,
    #[arg(long)]
    url: Option<String>,
    #[arg(long)]
    pubkey: String,
    #[arg(long)]
    kid: String,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum EslSub {
    Pack {
        #[arg(long)]
        sku: u64,
        #[arg(long, default_value_t = 0)]
        retailer_id_hash: u32,
        #[arg(long, default_value_t = 1)]
        store_id: u16,
        #[arg(long)]
        price_cents: u32,
        #[arg(long, default_value_t = 0)]
        expires_at: u32,
        #[arg(long, default_value_t = false)]
        associate_gated: bool,
        #[arg(long, default_value_t = false)]
        sale_active: bool,
        #[arg(long)]
        privkey: String,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        packet_file: Option<PathBuf>,
        #[arg(long)]
        packet_hex: Option<String>,
        #[arg(long)]
        pubkey: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum CustodySub {
    CreateManifest {
        #[arg(long)]
        manifest_id: String,
        #[arg(long)]
        sender_agent: String,
        #[arg(long)]
        receiver_agent: String,
        #[arg(long)]
        capsule_id: String,
        #[arg(long)]
        hash: String,
        #[arg(long)]
        geofence: Option<String>,
        #[arg(long)]
        temp_max: Option<f32>,
        #[arg(long)]
        sender_privkey: String,
        #[arg(long)]
        out: PathBuf,
    },
    CreateReceipt {
        #[arg(long)]
        receipt_id: String,
        #[arg(long)]
        manifest_file: PathBuf,
        #[arg(long, default_value = "accepted")]
        status: String,
        #[arg(long)]
        receiver_privkey: String,
        #[arg(long)]
        out: PathBuf,
    },
    VerifyHandoff {
        #[arg(long)]
        manifest_file: PathBuf,
        #[arg(long)]
        receipt_file: PathBuf,
        #[arg(long)]
        sender_pubkey: String,
        #[arg(long)]
        receiver_pubkey: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Args, Debug)]
struct ScanDaemonArgs {
    #[arg(long)]
    input_file: Option<PathBuf>,
    #[arg(long)]
    pubkey: Option<String>,
    #[arg(long, default_value = "default-kid")]
    kid: String,
    #[arg(long, default_value_t = false)]
    continuous: bool,
    #[arg(long, default_value_t = false)]
    json: bool,
}

#[derive(Args, Debug)]
struct UnpackArgs {
    bundle: PathBuf,
    #[arg(long)]
    out: PathBuf,
    #[command(flatten)]
    passphrase: PassphraseArgs,
}

#[derive(Args, Debug, Default)]
struct PassphraseArgs {
    #[arg(
        long,
        help = "Read the passphrase from stdin instead of prompting",
        long_help = "Read the passphrase from stdin instead of prompting. \
If this flag is not set, AegisQR prompts with hidden input when run interactively. \
AEGISQR_PASSPHRASE is intentionally rejected because environment variables may be exposed to other processes."
    )]
    passphrase_stdin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PassphraseSource {
    Prompt,
    Stdin,
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

fn main() -> Result<()> {
    let current_time_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    aegisqr_core::license::handle_license_reminders(current_time_secs);

    let cli = parse_cli()?;
    match cli.command {
        Commands::Pack(args) => {
            let compression = parse_compression(&args.compression)?;
            let is_aicx = args.aicx || args.aicx_sidecar.is_some();
            let payload_type = if is_aicx {
                Some(PayloadType::AicxArchive)
            } else {
                None
            };
            let mut passphrase = resolve_passphrase(&args.passphrase, true)?;
            let options = PackOptions {
                compression,
                auto_execute_capable: args.auto_execute_capable,
                auto_execute_requested: args.auto_execute_requested,
                payload_type,
                aicx_sidecar_path: args.aicx_sidecar.clone(),
                aicx_strict: args.aicx_strict,
                ..PackOptions::default()
            };
            let cap = pack_to_file(&args.input, &args.out, &passphrase, options)?;
            passphrase.zeroize();
            println!("Packed {} -> {}", args.input.display(), args.out.display());
            println!("bundle_id={}", cap.public_header.bundle_id);
        }
        Commands::Inspect { bundle } => {
            let capsule = aegisqr_core::read_capsule_file(&bundle)?;
            println!("{}", serde_json::to_string_pretty(&capsule)?);
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
            let mut passphrase = resolve_passphrase(&args.passphrase, false)?;
            unpack_capsule(&args.bundle, &args.out, &passphrase)?;
            passphrase.zeroize();
            println!("Unpacked to {}", args.out.display());
        }
        Commands::Stage(args) => {
            let mut passphrase = resolve_passphrase(&args.passphrase, false)?;
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
        Commands::PackRetail(args) => {
            let privkey_bytes = hex::decode(&args.privkey).context("invalid hex private key")?;
            let issued_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expires_at = if args.expires_in_secs > 0 {
                issued_at + args.expires_in_secs
            } else {
                0
            };
            let payload = aegisqr_core::RetailPayload {
                retailer_id: args.retailer_id,
                sku: args.sku,
                upc: args.upc,
                store_id: args.store_id,
                aisle: args.aisle,
                bay: args.bay,
                shelf: args.shelf,
                campaign_id: args.campaign_id,
                experience_id: args.experience_id,
                role: args.role,
                label_version: args.label_version,
                issued_at,
                expires_at,
                fallback_url_id: args.fallback_url_id,
            };
            let token = aegisqr_core::sign_retail_payload(payload, &privkey_bytes, args.kid)?;
            let base_url = args.base_url.trim_end_matches('/');
            let separator = if base_url.contains('?') { "&p=" } else { "?p=" };
            let url = format!("{}{}{}", base_url, separator, token);
            if let Some(parent) = args.out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&args.out, url.as_bytes())?;
            println!("Created retail signed deep-link at: {}", args.out.display());
            println!("URL: {}", url);
        }
        Commands::VerifyRetail(args) => {
            let url_str =
                fs::read_to_string(&args.url_file).context("failed to read retail URL file")?;
            let url = url_str.trim();
            let query_part = url
                .split("?p=")
                .nth(1)
                .or_else(|| url.split("&p=").nth(1))
                .ok_or_else(|| {
                    anyhow::anyhow!("URL does not contain signed payload query parameter 'p'")
                })?;
            let pubkey_bytes = hex::decode(&args.pubkey).context("invalid hex public key")?;
            let mut trust_store = aegisqr_core::TrustStore::default();
            trust_store.add_signer(args.kid, pubkey_bytes);
            let current_time_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let payload =
                aegisqr_core::verify_retail_payload(query_part, &trust_store, current_time_secs)?;
            aegisqr_core::authorize_retail_action(&payload, args.authenticated_associate)?;
            if args.json {
                let out_json = serde_json::json!({
                    "verification": "succeeded",
                    "payload": payload
                });
                println!("{}", serde_json::to_string_pretty(&out_json)?);
            } else {
                println!("Verification Succeeded!");
                println!("Payload: {:?}", payload);
            }
        }
        Commands::PackGs1(args) => {
            if !aegisqr_core::validate_gtin_check_digit(&args.gtin) {
                bail!("Invalid GTIN check digit for '{}'", args.gtin);
            }
            let privkey_bytes = hex::decode(&args.privkey).context("invalid hex private key")?;
            let issued_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let expires_at = if args.expires_in_secs > 0 {
                issued_at + args.expires_in_secs
            } else {
                0
            };
            let sku = args.sku.unwrap_or_else(|| args.gtin.clone());
            let payload = aegisqr_core::RetailPayload {
                retailer_id: args.retailer_id,
                sku,
                upc: Some(args.gtin.clone()),
                store_id: args.store_id,
                aisle: None,
                bay: None,
                shelf: None,
                campaign_id: None,
                experience_id: None,
                role: None,
                label_version: 1,
                issued_at,
                expires_at,
                fallback_url_id: None,
            };
            let token = aegisqr_core::sign_retail_payload(payload, &privkey_bytes, args.kid)?;
            let url = aegisqr_core::build_gs1_digital_link(
                &args.domain,
                &args.gtin,
                args.serial.as_deref(),
                args.lot.as_deref(),
                args.store_gln.as_deref(),
                &token,
            )?;
            if let Some(parent) = args.out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&args.out, url.as_bytes())?;
            println!("Created GS1 Digital Link at: {}", args.out.display());
            println!("URL: {}", url);
        }
        Commands::VerifyGs1(args) => {
            let url = if let Some(path) = args.url_file {
                fs::read_to_string(&path)
                    .context("failed to read GS1 URL file")?
                    .trim()
                    .to_string()
            } else if let Some(u) = args.url {
                u.trim().to_string()
            } else {
                bail!("Either --url or --url-file must be provided");
            };
            let pubkey_bytes = hex::decode(&args.pubkey).context("invalid hex public key")?;
            let mut trust_store = aegisqr_core::TrustStore::default();
            trust_store.add_signer(args.kid, pubkey_bytes);
            let current_time_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let verified =
                aegisqr_core::verify_gs1_digital_link(&url, &trust_store, current_time_secs)?;
            if args.json {
                let out_json = serde_json::json!({
                    "verification": "succeeded",
                    "gs1": {
                        "gtin": verified.gtin,
                        "serial": verified.serial,
                        "lot": verified.lot,
                        "store_gln": verified.store_gln,
                        "check_digit_valid": verified.check_digit_valid,
                        "path_gtin_matches_payload": verified.path_gtin_matches_payload,
                    },
                    "retail_payload": verified.verified_retail_payload,
                });
                println!("{}", serde_json::to_string_pretty(&out_json)?);
            } else {
                println!("GS1 Digital Link Verification Succeeded!");
                println!("GTIN: {}", verified.gtin);
                if let Some(serial) = verified.serial {
                    println!("Serial: {}", serial);
                }
                if let Some(lot) = verified.lot {
                    println!("Lot: {}", lot);
                }
                println!("Payload: {:?}", verified.verified_retail_payload);
            }
        }
        Commands::Esl { sub } => match sub {
            EslSub::Pack {
                sku,
                retailer_id_hash,
                store_id,
                price_cents,
                expires_at,
                associate_gated,
                sale_active,
                privkey,
                out,
            } => {
                let privkey_bytes = hex::decode(&privkey).context("invalid hex private key")?;
                let data = aegisqr_core::EslData {
                    retailer_id_hash,
                    sku_numeric: sku,
                    store_id,
                    price_cents,
                    expires_at,
                    is_associate_gated: associate_gated,
                    is_sale_active: sale_active,
                };
                let packet = aegisqr_core::encode_esl_packet(&data, &privkey_bytes)?;
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&out, &packet)?;
                let hex_str = hex::encode(&packet);
                println!("Encoded ESL 89-byte packet to: {}", out.display());
                println!("Hex: {}", hex_str);
            }
            EslSub::Verify {
                packet_file,
                packet_hex,
                pubkey,
                json,
            } => {
                let raw_bytes = if let Some(path) = packet_file {
                    let bytes = fs::read(&path).context("failed to read ESL packet file")?;
                    if bytes.len() == aegisqr_core::ESL_PACKET_LEN {
                        bytes
                    } else if let Ok(s) = std::str::from_utf8(&bytes) {
                        let trimmed = s.trim();
                        hex::decode(trimmed).context("failed to parse packet file as hex")?
                    } else {
                        bytes
                    }
                } else if let Some(hex_str) = packet_hex {
                    hex::decode(hex_str.trim()).context("failed to decode hex packet")?
                } else {
                    bail!("Either --packet-file or --packet-hex must be provided");
                };

                let pubkey_bytes = hex::decode(&pubkey).context("invalid hex public key")?;
                let current_time_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let esl_data =
                    aegisqr_core::decode_esl_packet(&raw_bytes, &pubkey_bytes, current_time_secs)?;

                if json {
                    let out_json = serde_json::json!({
                        "verification": "succeeded",
                        "esl": esl_data,
                    });
                    println!("{}", serde_json::to_string_pretty(&out_json)?);
                } else {
                    println!("ESL Packet Verification Succeeded!");
                    println!("SKU: {}", esl_data.sku_numeric);
                    println!("Store ID: {}", esl_data.store_id);
                    println!("Price Cents: {}", esl_data.price_cents);
                    println!("Associate Gated: {}", esl_data.is_associate_gated);
                    println!("Sale Active: {}", esl_data.is_sale_active);
                    println!("Expires At: {}", esl_data.expires_at);
                }
            }
        },
        Commands::Custody { sub } => match sub {
            CustodySub::CreateManifest {
                manifest_id,
                sender_agent,
                receiver_agent,
                capsule_id,
                hash,
                geofence,
                temp_max,
                sender_privkey,
                out,
            } => {
                let privkey_bytes =
                    hex::decode(&sender_privkey).context("invalid hex sender private key")?;
                let created_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let mut manifest = aegisqr_core::CustodyTransferManifest {
                    manifest_id,
                    sender_agent_id: sender_agent,
                    receiver_agent_id: receiver_agent,
                    capsule_id,
                    payload_blake3_hash: hash,
                    created_at,
                    geofence,
                    temperature_max_celsius: temp_max,
                    sender_signature: None,
                };
                manifest.sign(&privkey_bytes)?;
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&out, serde_json::to_string_pretty(&manifest)?)?;
                println!("Created Custody Manifest at: {}", out.display());
            }
            CustodySub::CreateReceipt {
                receipt_id,
                manifest_file,
                status,
                receiver_privkey,
                out,
            } => {
                let manifest_bytes =
                    fs::read(&manifest_file).context("failed to read manifest file")?;
                let manifest: aegisqr_core::CustodyTransferManifest =
                    serde_json::from_slice(&manifest_bytes)
                        .context("invalid manifest json format")?;
                let privkey_bytes =
                    hex::decode(&receiver_privkey).context("invalid hex receiver private key")?;
                let signed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let mut receipt = aegisqr_core::CustodyTransferReceipt {
                    receipt_id,
                    manifest_id: manifest.manifest_id,
                    receiver_agent_id: manifest.receiver_agent_id,
                    status,
                    verified_hash: manifest.payload_blake3_hash,
                    signed_at,
                    receiver_signature: None,
                };
                receipt.sign(&privkey_bytes)?;
                if let Some(parent) = out.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&out, serde_json::to_string_pretty(&receipt)?)?;
                println!("Created Custody Receipt at: {}", out.display());
            }
            CustodySub::VerifyHandoff {
                manifest_file,
                receipt_file,
                sender_pubkey,
                receiver_pubkey,
                json,
            } => {
                let manifest_bytes =
                    fs::read(&manifest_file).context("failed to read manifest file")?;
                let manifest: aegisqr_core::CustodyTransferManifest =
                    serde_json::from_slice(&manifest_bytes)?;
                let receipt_bytes =
                    fs::read(&receipt_file).context("failed to read receipt file")?;
                let receipt: aegisqr_core::CustodyTransferReceipt =
                    serde_json::from_slice(&receipt_bytes)?;
                let sender_pub =
                    hex::decode(&sender_pubkey).context("invalid hex sender public key")?;
                let receiver_pub =
                    hex::decode(&receiver_pubkey).context("invalid hex receiver public key")?;
                aegisqr_core::verify_complete_custody_handoff(
                    &manifest,
                    &receipt,
                    &sender_pub,
                    &receiver_pub,
                )?;
                if json {
                    let out_json = serde_json::json!({
                        "verification": "succeeded",
                        "manifest_id": manifest.manifest_id,
                        "receipt_id": receipt.receipt_id,
                        "verified_hash": manifest.payload_blake3_hash,
                        "status": receipt.status,
                    });
                    println!("{}", serde_json::to_string_pretty(&out_json)?);
                } else {
                    println!("Custody Bilateral Handoff Verification Succeeded!");
                    println!("Manifest ID: {}", manifest.manifest_id);
                    println!("Receipt ID:  {}", receipt.receipt_id);
                    println!("Status:      {}", receipt.status);
                    println!("Hash:        {}", manifest.payload_blake3_hash);
                }
            }
        },
        Commands::ScanDaemon(args) => {
            let trust_store = if let Some(pk_hex) = &args.pubkey {
                let pk = hex::decode(pk_hex).context("invalid hex public key")?;
                let mut ts = aegisqr_core::TrustStore::default();
                ts.add_signer(args.kid.clone(), pk);
                Some(ts)
            } else {
                None
            };

            let lines_iter: Box<dyn Iterator<Item = io::Result<String>>> =
                if let Some(path) = args.input_file {
                    let file = fs::File::open(&path)?;
                    Box::new(io::BufReader::new(file).lines())
                } else {
                    Box::new(io::stdin().lock().lines())
                };

            for line_res in lines_iter {
                let line = match line_res {
                    Ok(l) => l,
                    Err(e) => {
                        eprintln!("Scan error: {e}");
                        break;
                    }
                };
                let raw_line = line.trim();
                if raw_line.is_empty() {
                    continue;
                }

                let current_time_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();

                // 1. Try GS1 Digital Link
                if raw_line.contains("/01/") {
                    if let Some(ts) = &trust_store {
                        match aegisqr_core::verify_gs1_digital_link(raw_line, ts, current_time_secs)
                        {
                            Ok(v) => {
                                if args.json {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "status": "valid",
                                            "kind": "gs1_digital_link",
                                            "gtin": v.gtin,
                                            "serial": v.serial,
                                            "lot": v.lot,
                                            "payload": v.verified_retail_payload,
                                        })
                                    );
                                } else {
                                    println!(
                                        "[GS1 VALID] GTIN: {} | SKU: {}",
                                        v.gtin, v.verified_retail_payload.sku
                                    );
                                }
                                continue;
                            }
                            Err(e) => {
                                if args.json {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "status": "invalid",
                                            "kind": "gs1_digital_link",
                                            "error": e.to_string(),
                                        })
                                    );
                                } else {
                                    eprintln!("[GS1 ERROR] {e}");
                                }
                                continue;
                            }
                        }
                    }
                }

                // 2. Try Retail Payload Deep Link (?p=)
                if raw_line.contains("?p=") || raw_line.contains("&p=") {
                    if let Some(ts) = &trust_store {
                        let query_part = raw_line
                            .split("?p=")
                            .nth(1)
                            .or_else(|| raw_line.split("&p=").nth(1))
                            .unwrap_or("");
                        match aegisqr_core::verify_retail_payload(query_part, ts, current_time_secs)
                        {
                            Ok(payload) => {
                                if args.json {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "status": "valid",
                                            "kind": "retail_payload",
                                            "payload": payload,
                                        })
                                    );
                                } else {
                                    println!(
                                        "[RETAIL VALID] Retailer: {} | SKU: {}",
                                        payload.retailer_id, payload.sku
                                    );
                                }
                                continue;
                            }
                            Err(e) => {
                                if args.json {
                                    println!(
                                        "{}",
                                        serde_json::json!({
                                            "status": "invalid",
                                            "kind": "retail_payload",
                                            "error": e.to_string(),
                                        })
                                    );
                                } else {
                                    eprintln!("[RETAIL ERROR] {e}");
                                }
                                continue;
                            }
                        }
                    }
                }

                // 3. Try ESL packet if hex string of 89 bytes (178 hex characters)
                if raw_line.len() == aegisqr_core::ESL_PACKET_LEN * 2 {
                    if let (Some(pk_hex), Ok(pkt_bytes)) = (&args.pubkey, hex::decode(raw_line)) {
                        if let Ok(pk) = hex::decode(pk_hex) {
                            match aegisqr_core::decode_esl_packet(
                                &pkt_bytes,
                                &pk,
                                current_time_secs,
                            ) {
                                Ok(data) => {
                                    if args.json {
                                        println!(
                                            "{}",
                                            serde_json::json!({
                                                "status": "valid",
                                                "kind": "esl_packet",
                                                "data": data,
                                            })
                                        );
                                    } else {
                                        println!(
                                            "[ESL VALID] SKU: {} | Price: ${:.2}",
                                            data.sku_numeric,
                                            data.price_cents as f64 / 100.0
                                        );
                                    }
                                    continue;
                                }
                                Err(e) => {
                                    if args.json {
                                        println!(
                                            "{}",
                                            serde_json::json!({
                                                "status": "invalid",
                                                "kind": "esl_packet",
                                                "error": e.to_string(),
                                            })
                                        );
                                    } else {
                                        eprintln!("[ESL ERROR] {e}");
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                }

                // 4. Fallback check for GTIN check digit
                let is_digits = raw_line.chars().all(|c| c.is_ascii_digit());
                if is_digits && raw_line.len() >= 8 && raw_line.len() <= 14 {
                    let valid = aegisqr_core::validate_gtin_check_digit(raw_line);
                    if args.json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "status": if valid { "valid" } else { "invalid" },
                                "kind": "gtin_barcode",
                                "gtin": raw_line,
                                "check_digit_valid": valid,
                            })
                        );
                    } else if valid {
                        println!("[BARCODE VALID] GTIN: {}", raw_line);
                    } else {
                        eprintln!("[BARCODE INVALID] GTIN check digit mismatch: {}", raw_line);
                    }
                    continue;
                }

                // Unknown barcode/scan
                if args.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "status": "unrecognized",
                            "raw": raw_line,
                        })
                    );
                } else {
                    println!("[SCAN UNRECOGNIZED] {}", raw_line);
                }
            }
        }
        Commands::License { sub } => match sub {
            LicenseSub::Status { json } => {
                let current_time_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_secs();
                let status = aegisqr_core::license::verify_license_status(current_time_secs);
                if json {
                    println!("{}", serde_json::to_string_pretty(&status)?);
                } else {
                    println!("License Status: {}", status.status.to_uppercase());
                    if let Some(org) = status.organization {
                        println!("Organization:   {}", org);
                    }
                    if let Some(tier) = status.tier {
                        println!("Tier:           {}", tier);
                    }
                    if let Some(seats) = status.seats {
                        println!("Seats:          {}", seats);
                    }
                    if let Some(expires) = status.expires_at {
                        println!("Expires At:     {}", expires);
                    }
                    if let Some(rem) = status.days_remaining {
                        println!("Days Remaining: {}", rem);
                    }
                }
            }
            LicenseSub::Install { path } => {
                let bytes = fs::read(&path).context("failed to read source license file")?;
                let lic: aegisqr_core::license::LicenseFile =
                    serde_json::from_slice(&bytes).context("invalid license file format")?;
                aegisqr_core::license::check_license_integrity(&lic)
                    .context("license integrity check failed (invalid signature or unknown key)")?;

                let mut installed = false;

                // Try /etc/aegisqr
                if fs::create_dir_all("/etc/aegisqr").is_ok()
                    && fs::write("/etc/aegisqr/license.aqlic", &bytes).is_ok()
                {
                    installed = true;
                    println!("Installed license to /etc/aegisqr/license.aqlic");
                }

                if !installed {
                    // Fallback to home folder
                    if let Ok(home) = std::env::var("HOME") {
                        let user_dir = format!("{}/.config/aegisqr", home);
                        let user_path = format!("{}/license.aqlic", user_dir);
                        fs::create_dir_all(&user_dir)?;
                        fs::write(&user_path, &bytes)?;
                        installed = true;
                        println!("Installed license to {}", user_path);
                    } else if let Ok(userprofile) = std::env::var("USERPROFILE") {
                        let user_dir = format!("{}/.config/aegisqr", userprofile);
                        let user_path = format!("{}/license.aqlic", user_dir);
                        fs::create_dir_all(&user_dir)?;
                        fs::write(&user_path, &bytes)?;
                        installed = true;
                        println!("Installed license to {}", user_path);
                    }
                }

                if !installed {
                    fs::write("./license.aqlic", &bytes)?;
                    println!("Installed license to ./license.aqlic");
                }
            }
            LicenseSub::Show { json } => {
                let mut found = false;
                for path in aegisqr_core::license::get_license_search_paths() {
                    if path.is_file() {
                        let content = fs::read_to_string(&path)?;
                        if json {
                            println!("{}", content.trim());
                        } else {
                            let lic: aegisqr_core::license::LicenseFile =
                                serde_json::from_str(&content)?;
                            println!("{:#?}", lic);
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    bail!("No installed license found.");
                }
            }
        },
    }

    Ok(())
}

fn parse_cli() -> Result<Cli> {
    let command = if let Some(bin_name) = std::env::args_os()
        .next()
        .as_deref()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
    {
        Cli::command().bin_name(bin_name.to_string())
    } else {
        Cli::command()
    };
    Ok(Cli::from_arg_matches(&command.get_matches())?)
}

fn resolve_passphrase(args: &PassphraseArgs, confirm: bool) -> Result<String> {
    match select_passphrase_source(
        args,
        std::env::var_os(PASSPHRASE_ENV_VAR).is_some(),
        io::stdin().is_terminal(),
    )? {
        PassphraseSource::Prompt => {
            if confirm {
                read_passphrase_with_confirmation("Passphrase", "Confirm passphrase")
            } else {
                read_passphrase_prompt("Passphrase")
            }
        }
        PassphraseSource::Stdin => read_passphrase_from_stdin(),
    }
}

fn select_passphrase_source(
    args: &PassphraseArgs,
    env_present: bool,
    stdin_is_terminal: bool,
) -> Result<PassphraseSource> {
    if args.passphrase_stdin {
        Ok(PassphraseSource::Stdin)
    } else if env_present {
        bail!(
            "{PASSPHRASE_ENV_VAR} is not supported because environment variables may be exposed to other processes; pipe the passphrase over stdin with --passphrase-stdin"
        )
    } else if stdin_is_terminal {
        Ok(PassphraseSource::Prompt)
    } else {
        bail!("passphrase required: rerun interactively to be prompted or pass --passphrase-stdin")
    }
}

fn read_passphrase_prompt(prompt: &str) -> Result<String> {
    ensure_non_empty(
        rpassword::prompt_password(format!("{prompt}: "))?,
        "prompted passphrase",
    )
}

fn read_passphrase_with_confirmation(prompt: &str, confirm_prompt: &str) -> Result<String> {
    let mut passphrase = read_passphrase_prompt(prompt)?;
    let mut passphrase_confirm = read_passphrase_prompt(confirm_prompt)?;
    if passphrase != passphrase_confirm {
        passphrase.zeroize();
        passphrase_confirm.zeroize();
        bail!("passphrases do not match");
    }
    passphrase_confirm.zeroize();
    Ok(passphrase)
}

fn read_passphrase_from_stdin() -> Result<String> {
    let mut passphrase = String::new();
    io::stdin()
        .lock()
        .take(MAX_STDIN_PASSPHRASE_BYTES + 1)
        .read_to_string(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
    if passphrase.len() as u64 > MAX_STDIN_PASSPHRASE_BYTES {
        passphrase.zeroize();
        bail!(
            "stdin passphrase exceeds {MAX_STDIN_PASSPHRASE_BYTES} bytes; passphrases must stay reasonably small"
        );
    }
    ensure_non_empty(
        normalize_passphrase_from_stdin(passphrase),
        "stdin passphrase",
    )
}

fn normalize_passphrase_from_stdin(mut passphrase: String) -> String {
    let normalized = passphrase.trim_end_matches(['\r', '\n']).to_string();
    passphrase.zeroize();
    normalized
}

fn parse_compression(value: &str) -> Result<CompressionProfile> {
    match value {
        "none" => Ok(CompressionProfile::None),
        "fast" => Ok(CompressionProfile::Fast),
        "balanced" => Ok(CompressionProfile::Balanced),
        "qr-basic" => Ok(CompressionProfile::QrBasic),
        other => bail!("invalid compression profile: {other}"),
    }
}

fn ensure_non_empty(mut passphrase: String, source: &str) -> Result<String> {
    if passphrase.is_empty() {
        passphrase.zeroize();
        bail!("{source} cannot be empty");
    }
    Ok(passphrase)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdin_flag_takes_priority() {
        let args = PassphraseArgs {
            passphrase_stdin: true,
        };
        assert_eq!(
            select_passphrase_source(&args, true, true).unwrap(),
            PassphraseSource::Stdin
        );
    }

    #[test]
    fn env_is_rejected_due_to_exposure_risk() {
        let args = PassphraseArgs::default();
        let err = select_passphrase_source(&args, true, false).unwrap_err();
        assert!(err.to_string().contains(PASSPHRASE_ENV_VAR));
        assert!(err.to_string().contains("--passphrase-stdin"));
    }

    #[test]
    fn prompt_is_used_interactively_without_automation_input() {
        let args = PassphraseArgs::default();
        assert_eq!(
            select_passphrase_source(&args, false, true).unwrap(),
            PassphraseSource::Prompt
        );
    }

    #[test]
    fn non_interactive_runs_require_stdin() {
        let args = PassphraseArgs::default();
        assert!(select_passphrase_source(&args, false, false)
            .unwrap_err()
            .to_string()
            .contains("--passphrase-stdin"));
    }

    #[test]
    fn stdin_normalization_strips_all_trailing_newlines() {
        assert_eq!(
            normalize_passphrase_from_stdin("secret\r\n".to_string()),
            "secret"
        );
        assert_eq!(
            normalize_passphrase_from_stdin("secret\n\n".to_string()),
            "secret"
        );
        assert_eq!(
            normalize_passphrase_from_stdin("secret\n".to_string()),
            "secret"
        );
        assert_eq!(
            normalize_passphrase_from_stdin("secret".to_string()),
            "secret"
        );
    }

    #[test]
    fn invalid_compression_profile_is_rejected() {
        assert!(parse_compression("definitely-not-real")
            .unwrap_err()
            .to_string()
            .contains("invalid compression profile"));
    }

    #[test]
    fn old_passphrase_flag_is_rejected() {
        assert!(Cli::try_parse_from([
            "aegisqr",
            "pack",
            "input.txt",
            "--out",
            "bundle.aqr",
            "--passphrase",
            "secret",
        ])
        .is_err());
    }

    #[test]
    fn cli_parses_pack_gs1() {
        let cli = Cli::try_parse_from([
            "aegisqr",
            "pack-gs1",
            "--gtin",
            "00012345678905",
            "--retailer-id",
            "walmart-us",
            "--store-id",
            "1001",
            "--privkey",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "--kid",
            "test-kid",
            "--out",
            "/tmp/out.url",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parses_esl() {
        let cli_pack = Cli::try_parse_from([
            "aegisqr",
            "esl",
            "pack",
            "--sku",
            "987654321",
            "--price-cents",
            "1999",
            "--privkey",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "--out",
            "/tmp/esl.bin",
        ]);
        assert!(cli_pack.is_ok());

        let cli_verify = Cli::try_parse_from([
            "aegisqr",
            "esl",
            "verify",
            "--packet-hex",
            "ae0100...",
            "--pubkey",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ]);
        assert!(cli_verify.is_ok());
    }

    #[test]
    fn cli_parses_custody() {
        let cli = Cli::try_parse_from([
            "aegisqr",
            "custody",
            "create-manifest",
            "--manifest-id",
            "m-1",
            "--sender-agent",
            "drone-01",
            "--receiver-agent",
            "dock-09",
            "--capsule-id",
            "cap-123",
            "--hash",
            "abcdef123456",
            "--sender-privkey",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "--out",
            "/tmp/manifest.json",
        ]);
        assert!(cli.is_ok());
    }

    #[test]
    fn cli_parses_scan_daemon() {
        let cli = Cli::try_parse_from([
            "aegisqr",
            "scan-daemon",
            "--input-file",
            "/tmp/stream.log",
            "--continuous",
            "--json",
        ]);
        assert!(cli.is_ok());
    }
}
