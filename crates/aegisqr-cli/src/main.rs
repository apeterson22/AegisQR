use std::fs;
use std::io::{self, IsTerminal, Read};
use std::path::PathBuf;

use aegisqr_core::{
    deny_execution_message, export_qr_packets, import_qr_packets, inspect_header, pack_to_file,
    stage_capsule, unpack_capsule, verify_capsule, ClientPolicy, CompressionProfile, PackOptions,
    PayloadType, TrustStore,
};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroize;

const PASSPHRASE_ENV_VAR: &str = "AEGISQR_PASSPHRASE";
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
    #[arg(long, default_value_t = false)]
    auto_execute_capable: bool,
    #[arg(long, default_value_t = false)]
    auto_execute_requested: bool,
    #[command(flatten)]
    passphrase: PassphraseArgs,
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
    let cli = Cli::parse();
    match cli.command {
        Commands::Pack(args) => {
            let compression = match args.compression.as_str() {
                "none" => CompressionProfile::None,
                "fast" => CompressionProfile::Fast,
                "balanced" => CompressionProfile::Balanced,
                "qr-basic" => CompressionProfile::QrBasic,
                _ => CompressionProfile::Balanced,
            };
            let payload_type = if args.aicx {
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
                ..PackOptions::default()
            };
            let cap = pack_to_file(&args.input, &args.out, &passphrase, options)?;
            passphrase.zeroize();
            println!("Packed {} -> {}", args.input.display(), args.out.display());
            println!("bundle_id={}", cap.public_header.bundle_id);
        }
        Commands::Inspect { bundle } => {
            let header = inspect_header(&bundle)?;
            println!("{}", serde_json::to_string_pretty(&header)?);
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
    }

    Ok(())
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
        .read_to_string(&mut passphrase)
        .context("failed to read passphrase from stdin")?;
    ensure_non_empty(
        normalize_passphrase_from_stdin(passphrase),
        "stdin passphrase",
    )
}

fn normalize_passphrase_from_stdin(mut passphrase: String) -> String {
    if passphrase.ends_with('\n') {
        passphrase.pop();
        if passphrase.ends_with('\r') {
            passphrase.pop();
        }
    }
    passphrase
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
    fn stdin_normalization_strips_single_trailing_newline() {
        assert_eq!(
            normalize_passphrase_from_stdin("secret\r\n".to_string()),
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
