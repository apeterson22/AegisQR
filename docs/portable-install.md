# Portable Install

## Portable bundle contents

Portable release bundles contain:

- `aegisqr` or `aegisqr.exe`
- `manifest.json`
- `trust-store.example.json`

GitHub release assets also publish a top-level `SHA256SUMS` file for checksum verification.

## Install from GitHub Releases

### Linux and macOS

```bash
./packaging/install.sh
./packaging/install.sh --version v0.1.0
./packaging/install.sh --install-dir /media/USB/aegisqr --bin-dir /media/USB/bin
```

### Windows

```powershell
./packaging/install.ps1
./packaging/install.ps1 -Version v0.1.0
./packaging/install.ps1 -InstallDir E:\aegisqr -BinDir E:\bin
```

## Install from a local archive

The installers also accept a local bundle archive or direct archive URL. This is useful for air-gapped handoff, SD cards, or QR-delivered media staging.

Remote archive installs must use HTTPS. For direct archive URLs outside the GitHub release flow, provide an explicit checksum unless you intentionally bypass verification with the installer skip-checksum flag.

```bash
./packaging/install.sh --archive ./aegisqr-x86_64-unknown-linux-gnu.tar.gz --install-dir /tmp/aegisqr
./packaging/install.sh --archive https://example.invalid/aegisqr-x86_64-unknown-linux-gnu.tar.gz --archive-sha256 <sha256> --install-dir /tmp/aegisqr
```

```powershell
./packaging/install.ps1 -Archive .\aegisqr-x86_64-pc-windows-msvc.zip -InstallDir C:\AegisQR
./packaging/install.ps1 -Archive https://example.invalid/aegisqr-x86_64-pc-windows-msvc.zip -ArchiveSha256 <sha256> -InstallDir C:\AegisQR
```

## Source builds on minimal hosts

Source builds require:

- Rust stable with `cargo`, `rustfmt`, and `clippy`
- A working C linker/toolchain for crates like `zstd-sys`

On minimal or immutable hosts such as Ubuntu Core, prefer GitHub Actions or a portable release bundle unless you intentionally provision a user-local toolchain.
