use std::fs;
use std::path::PathBuf;

use aegisqr_core::{
    decrypt_agent_index, deny_execution_message, export_qr_packets, import_qr_packets,
    inspect_header, pack_to_file, stage_capsule, unpack_capsule, verify_capsule, ClientPolicy,
    CompressionProfile, PackOptions, PayloadType, TrustStore,
};
use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(name = "aegisqr")]
#[command(about = "AegisQR secure QR-native capsule CLI")]
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
            let mut passphrase = args.passphrase;
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
    }

    let _ = decrypt_agent_index;
    Ok(())
}
