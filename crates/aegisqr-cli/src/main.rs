use std::fs;
use std::io::{self, IsTerminal, Read};
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
            println!("Verification Succeeded!");
            println!("Payload: {:?}", payload);
        }
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
}
