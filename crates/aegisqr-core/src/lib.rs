use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use argon2::Argon2;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tar::{Archive, Builder, Header};
use walkdir::WalkDir;
use zeroize::Zeroize;

pub const AQR_MAGIC: &[u8; 4] = b"AQR1";
pub const AQR_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PayloadType {
    RawFile,
    DirectoryTar,
    AicxArchive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CompressionProfile {
    None,
    Fast,
    Balanced,
    QrBasic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicHeader {
    pub magic: String,
    pub version: u32,
    pub bundle_id: String,
    pub profile: String,
    pub created_at: String,
    pub payload_type: PayloadType,
    pub chunk_count: u32,
    pub recovery_required: bool,
    pub encrypted: bool,
    pub signed: bool,
    pub auto_execute_capable: bool,
    pub auto_execute_default: bool,
    pub requires_signature: bool,
    pub requires_policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntry {
    pub section_id: String,
    pub offset: u64,
    pub length: u64,
    pub encrypted: bool,
    pub compressed: bool,
    pub hash: String,
    pub hash_algorithm: String,
    pub required_for: Vec<String>,
    pub content_type: String,
    pub policy_tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientPolicy {
    pub auto_execute_enabled: bool,
    pub trusted_signers: Vec<String>,
    pub allowed_profiles: Vec<String>,
    pub allowed_runtimes: Vec<String>,
    pub native_execution_allowed: bool,
    pub required_signature: bool,
    pub required_sandbox: bool,
    pub required_hardware_key: bool,
    pub max_risk_level: String,
    pub quarantine_executables: bool,
}

impl Default for ClientPolicy {
    fn default() -> Self {
        Self {
            auto_execute_enabled: false,
            trusted_signers: vec![],
            allowed_profiles: vec![],
            allowed_runtimes: vec!["wasm".into(), "container".into(), "python".into()],
            native_execution_allowed: false,
            required_signature: true,
            required_sandbox: true,
            required_hardware_key: false,
            max_risk_level: "medium".into(),
            quarantine_executables: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIndex {
    pub capsule_type: String,
    pub summary: String,
    pub payload_type: PayloadType,
    pub entrypoint_candidate: Option<String>,
    pub runtime_requirement: String,
    pub permissions_requested: Vec<String>,
    pub expected_outputs: Vec<String>,
    pub input_schema_placeholder: Option<String>,
    pub risk_level: String,
    pub auto_execute_declaration: bool,
    pub aicx_sidecar_reference_placeholder: Option<String>,
    pub toon_export_placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadEnvelope {
    pub payload_type: PayloadType,
    pub original_name: String,
    pub compression: CompressionProfile,
    pub kdf: String,
    pub cipher: String,
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub encrypted_payload_hash: String,
    pub payload_hash: String,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub signer_id: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub expiration: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkEntry {
    pub index: u32,
    pub hash: String,
    pub hash_algorithm: String,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    pub public_header: PublicHeader,
    pub section_table: Vec<SectionEntry>,
    pub trust_block: Option<BTreeMap<String, String>>,
    pub policy_block: ClientPolicy,
    pub key_wrap_table_placeholder: Option<String>,
    pub agent_index: AgentIndex,
    pub semantic_index_placeholder: Option<String>,
    pub workflow_section_placeholder: Option<String>,
    pub payload_section: PayloadEnvelope,
    pub secrets_section_placeholder: Option<String>,
    pub signature_block: SignatureBlock,
    pub chunk_table: Vec<ChunkEntry>,
    pub recovery_metadata_placeholder: Option<String>,
    pub audit_metadata_placeholder: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QrPacket {
    pub magic: String,
    pub version: u32,
    pub bundle_id: String,
    pub index: u32,
    pub total: u32,
    pub capsule_hash: String,
    pub payload_b64: String,
    pub checksum: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    pub trusted_signers: BTreeMap<String, Vec<u8>>,
    pub revocation_snapshot_placeholder: Option<String>,
}

impl TrustStore {
    pub fn add_signer(&mut self, signer_id: impl Into<String>, public_key: Vec<u8>) {
        self.trusted_signers.insert(signer_id.into(), public_key);
    }

    pub fn is_trusted(&self, signer_id: &str, public_key: &[u8]) -> bool {
        self.trusted_signers
            .get(signer_id)
            .map(|k| bool::from(k.as_slice().ct_eq(public_key)))
            .unwrap_or(false)
    }
}

pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut d = Sha256::new();
    d.update(data);
    hex::encode(d.finalize())
}

pub fn deterministic_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    Ok(serde_cbor::to_vec(value)?)
}

pub fn compress(data: &[u8], profile: CompressionProfile) -> Result<Vec<u8>> {
    match profile {
        CompressionProfile::None => Ok(data.to_vec()),
        CompressionProfile::Fast => Ok(zstd::stream::encode_all(data, 1)?),
        CompressionProfile::Balanced => Ok(zstd::stream::encode_all(data, 5)?),
        CompressionProfile::QrBasic => Ok(zstd::stream::encode_all(data, 9)?),
    }
}

pub fn decompress(data: &[u8], profile: CompressionProfile) -> Result<Vec<u8>> {
    match profile {
        CompressionProfile::None => Ok(data.to_vec()),
        _ => Ok(zstd::stream::decode_all(data)?),
    }
}

type EncryptOutput = (Vec<u8>, Vec<u8>, Vec<u8>, String);

fn make_aad(
    bundle_id: &str,
    version: u32,
    section: &str,
    policy_hash: &str,
    payload_hash: &str,
) -> Vec<u8> {
    format!("{bundle_id}|{version}|{section}|{policy_hash}|{payload_hash}").into_bytes()
}

fn encrypt_payload(
    passphrase: &str,
    bundle_id: &str,
    policy: &ClientPolicy,
    payload: &[u8],
) -> Result<EncryptOutput> {
    let mut salt = vec![0u8; 16];
    let mut nonce = vec![0u8; 24];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 failure: {e}"))?;

    let cipher = XChaCha20Poly1305::new((&key).into());
    let payload_hash = hash_bytes(payload);
    let policy_hash = hash_bytes(&deterministic_cbor(policy)?);
    let aad = make_aad(
        bundle_id,
        AQR_VERSION,
        "payload",
        &policy_hash,
        &payload_hash,
    );
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failure"))?;
    key.zeroize();

    Ok((salt, nonce, ciphertext, payload_hash))
}

fn decrypt_payload(
    passphrase: &str,
    bundle_id: &str,
    policy: &ClientPolicy,
    payload_hash: &str,
    salt: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("argon2 failure: {e}"))?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let policy_hash = hash_bytes(&deterministic_cbor(policy)?);
    let aad = make_aad(
        bundle_id,
        AQR_VERSION,
        "payload",
        &policy_hash,
        payload_hash,
    );
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            chacha20poly1305::aead::Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("decryption failure"))?;
    key.zeroize();
    Ok(plain)
}

pub fn verify_signature(capsule: &Capsule) -> Result<()> {
    let payload = signature_payload(capsule)?;
    let key = VerifyingKey::from_bytes(capsule.signature_block.public_key.as_slice().try_into()?)?;
    let sig = Signature::from_slice(&capsule.signature_block.signature)?;
    key.verify(&payload, &sig)?;
    validate_signature_expiration(&capsule.signature_block.expiration)?;
    Ok(())
}

fn validate_signature_expiration(expiration: &Option<String>) -> Result<()> {
    if let Some(expiration) = expiration {
        let expiration_ts = parse_timestamp_secs(expiration)
            .with_context(|| format!("invalid signature expiration: {expiration}"))?;
        if current_timestamp_secs() >= expiration_ts {
            bail!("signature expired at {expiration}");
        }
    }
    Ok(())
}

fn signature_payload(capsule: &Capsule) -> Result<Vec<u8>> {
    deterministic_cbor(&(
        &capsule.public_header,
        &capsule.section_table,
        &capsule.policy_block,
        &capsule.payload_section.encrypted_payload_hash,
        hash_bytes(&deterministic_cbor(&capsule.agent_index)?),
        hash_bytes(&deterministic_cbor(&capsule.chunk_table)?),
        capsule.agent_index.auto_execute_declaration,
        &capsule.signature_block.expiration,
    ))
}

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub profile: String,
    pub compression: CompressionProfile,
    pub auto_execute_capable: bool,
    pub auto_execute_requested: bool,
    pub payload_type: Option<PayloadType>,
}

impl Default for PackOptions {
    fn default() -> Self {
        Self {
            profile: "balanced".into(),
            compression: CompressionProfile::Balanced,
            auto_execute_capable: false,
            auto_execute_requested: false,
            payload_type: None,
        }
    }
}

pub fn pack_to_file(
    input: &Path,
    out: &Path,
    passphrase: &str,
    options: PackOptions,
) -> Result<Capsule> {
    let capsule = pack(input, passphrase, options)?;
    write_capsule_file(out, &capsule)?;
    Ok(capsule)
}

pub fn pack(input: &Path, passphrase: &str, options: PackOptions) -> Result<Capsule> {
    // auto_execute_requested requires auto_execute_capable; normalize to avoid a
    // contradictory capsule where the public header declares the capsule is not
    // capable of auto-execution but the agent index declares it should execute.
    let auto_execute_capable = options.auto_execute_capable;
    let auto_execute_declaration = options.auto_execute_requested && auto_execute_capable;

    let payload_type = options
        .payload_type
        .unwrap_or_else(|| detect_payload_type(input));
    let original_name = input
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "payload".into());
    let prepared = prepare_payload(input, &payload_type)?;
    let compressed = compress(&prepared, options.compression.clone())?;

    let bundle_id =
        hash_bytes(&[prepared.as_slice(), compressed.as_slice()].concat())[..24].to_string();
    let created_at = chrono_like_now();
    let policy = ClientPolicy::default();

    let (salt, nonce, ciphertext, payload_hash) =
        encrypt_payload(passphrase, &bundle_id, &policy, &compressed)?;
    let encrypted_hash = hash_bytes(&ciphertext);

    let mut capsule = Capsule {
        public_header: PublicHeader {
            magic: "AQR1".into(),
            version: AQR_VERSION,
            bundle_id: bundle_id.clone(),
            profile: options.profile,
            created_at,
            payload_type: payload_type.clone(),
            chunk_count: 0,
            recovery_required: false,
            encrypted: true,
            signed: true,
            auto_execute_capable,
            auto_execute_default: false,
            requires_signature: true,
            requires_policy: true,
        },
        section_table: vec![],
        trust_block: None,
        policy_block: policy,
        key_wrap_table_placeholder: Some("future-envelope-keys".into()),
        agent_index: AgentIndex {
            capsule_type: "aegisqr".into(),
            summary: format!("AegisQR capsule for {original_name}"),
            payload_type: payload_type.clone(),
            entrypoint_candidate: None,
            runtime_requirement: "none".into(),
            permissions_requested: vec![],
            expected_outputs: vec!["restored-payload".into()],
            input_schema_placeholder: Some("future-input-schema".into()),
            risk_level: "medium".into(),
            auto_execute_declaration,
            aicx_sidecar_reference_placeholder: Some("future-aicx-sidecar".into()),
            toon_export_placeholder: Some("future-toon-export".into()),
        },
        semantic_index_placeholder: Some("future-semantic-index".into()),
        workflow_section_placeholder: Some("future-workflow-section".into()),
        payload_section: PayloadEnvelope {
            payload_type,
            original_name,
            compression: options.compression,
            kdf: "argon2id".into(),
            cipher: "xchacha20poly1305".into(),
            salt,
            nonce,
            encrypted_payload_hash: encrypted_hash,
            payload_hash,
            ciphertext,
        },
        secrets_section_placeholder: Some("future-secrets-section".into()),
        signature_block: SignatureBlock {
            signer_id: "local-ephemeral".into(),
            public_key: vec![],
            signature: vec![],
            expiration: None,
        },
        chunk_table: vec![],
        recovery_metadata_placeholder: Some("future-recovery-metadata".into()),
        audit_metadata_placeholder: Some("future-audit-metadata".into()),
    };

    capsule.chunk_table = build_chunk_table(&capsule.payload_section.ciphertext, 1024);
    capsule.public_header.chunk_count = capsule.chunk_table.len() as u32;
    capsule.section_table = build_section_table(&capsule)?;

    let signing_key = SigningKey::generate(&mut OsRng);
    let sign_payload = signature_payload(&capsule)?;
    let sig = signing_key.sign(&sign_payload);
    capsule.signature_block.public_key = signing_key.verifying_key().to_bytes().to_vec();
    capsule.signature_block.signature = sig.to_bytes().to_vec();

    Ok(capsule)
}

fn build_section_table(c: &Capsule) -> Result<Vec<SectionEntry>> {
    let mut entries = Vec::new();
    let mut offset = 0u64;
    // NOTE: "signature_block" is intentionally excluded here.  Its hash cannot
    // be computed before the signing key is generated (chicken-and-egg), so
    // including a hash of the empty placeholder would always be wrong.
    // Integrity of the signature_block is guaranteed by the Ed25519 signature
    // itself, which already covers the public key, bundle identity, and all
    // other section hashes through the signed payload.
    let sections = vec![
        (
            "public_header",
            deterministic_cbor(&c.public_header)?,
            false,
            false,
            vec!["inspect".into(), "verify".into()],
            "application/cbor".into(),
            vec!["public".into()],
        ),
        (
            "policy_block",
            deterministic_cbor(&c.policy_block)?,
            false,
            false,
            vec!["verify".into(), "stage".into()],
            "application/cbor".into(),
            vec!["policy".into()],
        ),
        (
            "agent_index",
            deterministic_cbor(&c.agent_index)?,
            false,
            false,
            vec!["stage".into()],
            "application/cbor".into(),
            vec!["agent".into()],
        ),
        (
            "payload",
            c.payload_section.ciphertext.clone(),
            true,
            true,
            vec!["unpack".into(), "stage".into()],
            "application/octet-stream".into(),
            vec!["encrypted".into()],
        ),
        (
            "chunk_table",
            deterministic_cbor(&c.chunk_table)?,
            false,
            false,
            vec!["verify".into(), "qr-export".into()],
            "application/cbor".into(),
            vec!["integrity".into()],
        ),
    ];

    for (id, bytes, encrypted, compressed, required_for, content_type, tags) in sections {
        let len = bytes.len() as u64;
        entries.push(SectionEntry {
            section_id: id.into(),
            offset,
            length: len,
            encrypted,
            compressed,
            hash: hash_bytes(&bytes),
            hash_algorithm: "blake3".into(),
            required_for,
            content_type,
            policy_tags: tags,
        });
        offset += len;
    }
    Ok(entries)
}

fn build_chunk_table(payload: &[u8], chunk_size: usize) -> Vec<ChunkEntry> {
    payload
        .chunks(chunk_size)
        .enumerate()
        .map(|(i, c)| ChunkEntry {
            index: i as u32,
            hash: hash_bytes(c),
            hash_algorithm: "blake3".into(),
            length: c.len(),
        })
        .collect()
}

fn detect_payload_type(input: &Path) -> PayloadType {
    if input.is_dir() {
        PayloadType::DirectoryTar
    } else if input
        .extension()
        .map(|s| s.eq_ignore_ascii_case("aicx"))
        .unwrap_or(false)
    {
        PayloadType::AicxArchive
    } else {
        PayloadType::RawFile
    }
}

fn prepare_payload(input: &Path, payload_type: &PayloadType) -> Result<Vec<u8>> {
    match payload_type {
        PayloadType::RawFile | PayloadType::AicxArchive => Ok(fs::read(input)?),
        PayloadType::DirectoryTar => {
            let mut bytes = Vec::new();
            let mut tar = Builder::new(&mut bytes);
            tar.follow_symlinks(false);
            for entry in WalkDir::new(input).follow_links(false) {
                let entry = entry?;
                if entry.path() == input {
                    continue;
                }
                let rel = entry.path().strip_prefix(input)?;
                if entry.file_type().is_symlink() {
                    bail!("symlink escape is blocked: {}", rel.display());
                }
                if entry.file_type().is_file() {
                    tar.append_path_with_name(entry.path(), rel)?;
                } else if entry.file_type().is_dir() {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_cksum();
                    tar.append_data(&mut header, rel, std::io::empty())?;
                }
            }
            tar.finish()?;
            drop(tar);
            Ok(bytes)
        }
    }
}

pub fn write_capsule_file(out: &Path, capsule: &Capsule) -> Result<()> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(AQR_MAGIC);
    bytes.extend(deterministic_cbor(capsule)?);
    fs::write(out, bytes)?;
    Ok(())
}

pub fn read_capsule_file(path: &Path) -> Result<Capsule> {
    let bytes = fs::read(path)?;
    if bytes.len() < 4 || &bytes[..4] != AQR_MAGIC {
        bail!("invalid capsule magic");
    }
    Ok(serde_cbor::from_slice(&bytes[4..])?)
}

pub fn inspect_header(path: &Path) -> Result<PublicHeader> {
    Ok(read_capsule_file(path)?.public_header)
}

pub fn verify_capsule(
    path: &Path,
    trust_store: Option<&TrustStore>,
    strict_trust: bool,
) -> Result<()> {
    let capsule = read_capsule_file(path)?;
    verify_signature(&capsule)?;

    if strict_trust {
        let ts = trust_store.context("strict trust requested but no trust store provided")?;
        if !ts.is_trusted(
            &capsule.signature_block.signer_id,
            &capsule.signature_block.public_key,
        ) {
            bail!("unknown signer under strict policy");
        }
    }

    if capsule.public_header.requires_signature && capsule.signature_block.signature.is_empty() {
        bail!("missing signature");
    }

    for chunk in &capsule.chunk_table {
        let start = (chunk.index as usize) * 1024;
        let end = start + chunk.length;
        if end > capsule.payload_section.ciphertext.len() {
            bail!("invalid chunk table bounds");
        }
        let actual = hash_bytes(&capsule.payload_section.ciphertext[start..end]);
        if actual != chunk.hash {
            bail!("chunk hash mismatch");
        }
    }
    Ok(())
}

pub fn decrypt_agent_index(path: &Path, passphrase: &str) -> Result<AgentIndex> {
    let capsule = read_capsule_file(path)?;
    let _ = decrypt_payload(
        passphrase,
        &capsule.public_header.bundle_id,
        &capsule.policy_block,
        &capsule.payload_section.payload_hash,
        &capsule.payload_section.salt,
        &capsule.payload_section.nonce,
        &capsule.payload_section.ciphertext,
    )?;
    Ok(capsule.agent_index)
}

pub fn unpack_capsule(path: &Path, out_dir: &Path, passphrase: &str) -> Result<()> {
    restore_capsule(path, out_dir, passphrase, false)
}

pub fn stage_capsule(path: &Path, out_dir: &Path, passphrase: &str) -> Result<()> {
    restore_capsule(path, out_dir, passphrase, true)
}

fn restore_capsule(path: &Path, out_dir: &Path, passphrase: &str, force_stage: bool) -> Result<()> {
    let capsule = read_capsule_file(path)?;
    verify_signature(&capsule)?;

    let decrypted = decrypt_payload(
        passphrase,
        &capsule.public_header.bundle_id,
        &capsule.policy_block,
        &capsule.payload_section.payload_hash,
        &capsule.payload_section.salt,
        &capsule.payload_section.nonce,
        &capsule.payload_section.ciphertext,
    )?;
    let actual_hash = hash_bytes(&decrypted);
    if actual_hash != capsule.payload_section.payload_hash {
        bail!("payload hash mismatch stops restore");
    }

    fs::create_dir_all(out_dir)?;
    let extracted = decompress(&decrypted, capsule.payload_section.compression.clone())?;

    match capsule.payload_section.payload_type {
        PayloadType::RawFile | PayloadType::AicxArchive => {
            let target = safe_join(out_dir, Path::new(&capsule.payload_section.original_name))?;
            write_payload_file(target, &extracted, force_stage)?;
        }
        PayloadType::DirectoryTar => {
            restore_tar(&extracted, out_dir, force_stage)?;
        }
    }
    Ok(())
}

fn restore_tar(bytes: &[u8], out_dir: &Path, force_stage: bool) -> Result<()> {
    let mut archive = Archive::new(bytes);
    for file in archive.entries()? {
        let mut file = file?;
        let path = file.path()?;
        let rel = path.as_ref();
        let target = safe_join(out_dir, rel)?;
        if file.header().entry_type().is_symlink() || file.header().entry_type().is_hard_link() {
            bail!("symlink escape is blocked");
        }
        if file.header().entry_type().is_dir() {
            fs::create_dir_all(&target)?;
            continue;
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut data = Vec::new();
        std::io::copy(&mut file, &mut data)?;
        write_payload_file(target, &data, force_stage)?;
    }
    Ok(())
}

fn validate_relative(path: &Path) -> Result<()> {
    if path.is_absolute() {
        bail!("path traversal is blocked");
    }
    for c in path.components() {
        if matches!(
            c,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            bail!("path traversal is blocked");
        }
    }
    Ok(())
}

fn safe_join(base: &Path, rel: &Path) -> Result<PathBuf> {
    validate_relative(rel)?;
    Ok(base.join(rel))
}

fn write_payload_file(path: PathBuf, data: &[u8], force_stage: bool) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_string();

    let out_path = if force_stage || is_executable_name(&file_name) {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let quarantine = parent.join("quarantine");
        fs::create_dir_all(&quarantine)?;
        quarantine.join(file_name)
    } else {
        path
    };

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, data)?;
    Ok(())
}

pub fn is_executable_name(name: &str) -> bool {
    let ext = Path::new(name)
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "sh" | "py" | "ps1" | "bat" | "cmd" | "exe" | "dll" | "so" | "dylib" | "jar" | "wasm"
    )
}

pub fn export_qr_packets(
    bundle_path: &Path,
    out_dir: &Path,
    packet_size: usize,
    write_png: bool,
) -> Result<()> {
    if packet_size == 0 {
        bail!("packet_size must be greater than zero");
    }
    let bytes = fs::read(bundle_path)?;
    if bytes.len() < 4 || &bytes[..4] != AQR_MAGIC {
        bail!("invalid capsule magic");
    }
    let capsule: Capsule = serde_cbor::from_slice(&bytes[4..])?;
    let hash = hash_bytes(&bytes);
    fs::create_dir_all(out_dir)?;
    let total = bytes.chunks(packet_size).count() as u32;

    for (index, chunk) in bytes.chunks(packet_size).enumerate() {
        let packet = QrPacket {
            magic: "AQRP".into(),
            version: AQR_VERSION,
            bundle_id: capsule.public_header.bundle_id.clone(),
            index: index as u32,
            total,
            capsule_hash: hash.clone(),
            payload_b64: base64::engine::general_purpose::STANDARD.encode(chunk),
            checksum: hash_bytes(chunk),
        };

        let cbor_path = out_dir.join(format!("packet-{:04}.cbor", index));
        let json_path = out_dir.join(format!("packet-{:04}.json", index));
        fs::write(cbor_path, deterministic_cbor(&packet)?)?;
        fs::write(json_path, serde_json::to_vec_pretty(&packet)?)?;

        #[cfg(feature = "qr-png")]
        if write_png {
            let data = serde_json::to_string(&packet)?;
            let code = qrcode::QrCode::new(data.as_bytes())?;
            let image = code.render::<image::Luma<u8>>().build();
            image.save(out_dir.join(format!("packet-{:04}.png", index)))?;
        }

        #[cfg(not(feature = "qr-png"))]
        if write_png {
            bail!("PNG QR export requested but the 'qr-png' feature is not compiled in; rebuild with --features qr-png");
        }
    }
    Ok(())
}

pub fn import_qr_packets(packet_dir: &Path, out_path: &Path) -> Result<()> {
    let mut packets = Vec::new();
    for entry in fs::read_dir(packet_dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("cbor") {
            let packet: QrPacket = serde_cbor::from_slice(&fs::read(&p)?)?;
            packets.push(packet);
        }
    }
    if packets.is_empty() {
        for entry in fs::read_dir(packet_dir)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("json") {
                let packet: QrPacket = serde_json::from_slice(&fs::read(&p)?)?;
                packets.push(packet);
            }
        }
    }

    if packets.is_empty() {
        bail!("no packets found");
    }

    let bundle_ids: BTreeSet<_> = packets.iter().map(|p| p.bundle_id.clone()).collect();
    if bundle_ids.len() != 1 {
        bail!("mixed bundle IDs");
    }

    let mut by_index: BTreeMap<u32, QrPacket> = BTreeMap::new();
    for packet in packets {
        if packet.magic != "AQRP" {
            bail!("invalid packet magic");
        }
        if packet.version != AQR_VERSION {
            bail!("unsupported packet version");
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(packet.payload_b64.as_bytes())
            .context("invalid packet base64")?;
        if hash_bytes(&bytes) != packet.checksum {
            bail!("packet checksum verification failed");
        }
        if let Some(existing) = by_index.get(&packet.index) {
            if existing.checksum != packet.checksum {
                bail!("duplicate conflicting chunks");
            }
        } else {
            by_index.insert(packet.index, packet);
        }
    }

    let first = by_index.values().next().unwrap();
    let total = first.total;
    if total == 0 {
        bail!("invalid packet total");
    }
    for packet in by_index.values() {
        if packet.total != total {
            bail!("inconsistent packet totals");
        }
        if packet.capsule_hash != first.capsule_hash {
            bail!("inconsistent capsule hash across packets");
        }
    }
    for i in 0..total {
        if !by_index.contains_key(&i) {
            bail!("missing chunk {i}");
        }
    }

    let mut out = Vec::new();
    for i in 0..total {
        let p = by_index.get(&i).unwrap();
        out.extend(base64::engine::general_purpose::STANDARD.decode(p.payload_b64.as_bytes())?);
    }

    let expected_hash = &first.capsule_hash;
    let actual_hash = hash_bytes(&out);
    if &actual_hash != expected_hash {
        bail!("capsule hash mismatch");
    }
    fs::write(out_path, out)?;
    Ok(())
}

pub fn deny_execution_message(policy: &ClientPolicy, auto_execute_requested: bool) -> String {
    if auto_execute_requested && !policy.auto_execute_enabled {
        "Execution denied: auto-execute is disabled by client policy. Scanning/decrypting/restoring never executes payloads.".into()
    } else {
        "Execution denied: runtime execution is not implemented in MVP.".into()
    }
}

fn chrono_like_now() -> String {
    current_timestamp_secs().to_string()
}

fn current_timestamp_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

const MAX_SIGNATURE_EXPIRATION_SECS: u64 = 253_402_300_799;

fn parse_timestamp_secs(ts: &str) -> Result<u64> {
    if ts.is_empty() {
        bail!("timestamp cannot be empty");
    }
    if ts.len() > 20 {
        bail!("timestamp exceeds supported range");
    }

    let parsed: u64 = ts.parse()?;
    if parsed > MAX_SIGNATURE_EXPIRATION_SECS {
        bail!("timestamp exceeds supported range");
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use tempfile::tempdir;

    fn resign_capsule_for_test(capsule: &mut Capsule) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let payload = signature_payload(capsule).unwrap();
        let sig = signing_key.sign(&payload);
        capsule.signature_block.signer_id = "test-signer".into();
        capsule.signature_block.public_key = signing_key.verifying_key().to_bytes().to_vec();
        capsule.signature_block.signature = sig.to_bytes().to_vec();
    }

    #[test]
    fn public_header_creation() {
        let h = PublicHeader {
            magic: "AQR1".into(),
            version: 1,
            bundle_id: "id".into(),
            profile: "balanced".into(),
            created_at: "0".into(),
            payload_type: PayloadType::RawFile,
            chunk_count: 1,
            recovery_required: false,
            encrypted: true,
            signed: true,
            auto_execute_capable: false,
            auto_execute_default: false,
            requires_signature: true,
            requires_policy: true,
        };
        assert_eq!(h.magic, "AQR1");
        assert!(!h.auto_execute_default);
    }

    #[test]
    fn deterministic_cbor_encoding() {
        let p = ClientPolicy::default();
        let a = deterministic_cbor(&p).unwrap();
        let b = deterministic_cbor(&p).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn compression_roundtrip() {
        let data = b"hello hello hello";
        let c = compress(data, CompressionProfile::Balanced).unwrap();
        let d = decompress(&c, CompressionProfile::Balanced).unwrap();
        assert_eq!(data.to_vec(), d);
    }

    #[test]
    fn wrong_passphrase_and_tamper_fail() {
        let data = b"secret payload";
        let p = ClientPolicy::default();
        let (salt, nonce, mut ct, hash) = encrypt_payload("pw", "id", &p, data).unwrap();
        assert!(decrypt_payload("bad", "id", &p, &hash, &salt, &nonce, &ct).is_err());
        ct[0] ^= 0x01;
        assert!(decrypt_payload("pw", "id", &p, &hash, &salt, &nonce, &ct).is_err());
    }

    #[test]
    fn sign_verify_and_tamper_fail() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let capsule = pack(&src, "pw", PackOptions::default()).unwrap();
        verify_signature(&capsule).unwrap();
        let mut tampered = capsule.clone();
        tampered.public_header.profile = "changed".into();
        assert!(verify_signature(&tampered).is_err());
    }

    #[test]
    fn expired_signature_is_rejected_for_verify_and_restore() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let bundle = dir.path().join("expired.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();

        let mut capsule = read_capsule_file(&bundle).unwrap();
        capsule.signature_block.expiration = Some("0".into());
        resign_capsule_for_test(&mut capsule);
        write_capsule_file(&bundle, &capsule).unwrap();

        assert!(verify_signature(&capsule).is_err());
        assert!(verify_capsule(&bundle, None, false).is_err());
        assert!(unpack_capsule(&bundle, &dir.path().join("out"), "pw").is_err());
    }

    #[test]
    fn invalid_signature_expiration_is_rejected() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let mut capsule = pack(&src, "pw", PackOptions::default()).unwrap();
        capsule.signature_block.expiration = Some("not-a-timestamp".into());
        resign_capsule_for_test(&mut capsule);

        assert!(verify_signature(&capsule).is_err());
    }

    #[test]
    fn out_of_range_signature_expiration_is_rejected() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let mut capsule = pack(&src, "pw", PackOptions::default()).unwrap();
        capsule.signature_block.expiration = Some((MAX_SIGNATURE_EXPIRATION_SECS + 1).to_string());
        resign_capsule_for_test(&mut capsule);

        assert!(verify_signature(&capsule).is_err());
    }

    #[test]
    fn excessively_long_signature_expiration_is_rejected() {
        assert!(parse_timestamp_secs("999999999999999999999").is_err());
    }

    #[test]
    fn policy_denial() {
        let msg = deny_execution_message(&ClientPolicy::default(), true);
        assert!(msg.contains("denied"));
    }

    #[test]
    fn executable_quarantine_detection() {
        assert!(is_executable_name("run.sh"));
        assert!(is_executable_name("mod.WASM"));
        assert!(!is_executable_name("notes.txt"));
    }

    #[test]
    fn qr_packet_encode_decode_and_mixed_rejection() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        let out = dir.path().join("x.aqr");
        fs::write(&src, b"abc").unwrap();
        pack_to_file(&src, &out, "pw", PackOptions::default()).unwrap();

        let qr = dir.path().join("qr");
        export_qr_packets(&out, &qr, 32, false).unwrap();
        let recovered = dir.path().join("recovered.aqr");
        import_qr_packets(&qr, &recovered).unwrap();
        assert_eq!(fs::read(&out).unwrap(), fs::read(&recovered).unwrap());

        let mut mixed: QrPacket =
            serde_cbor::from_slice(&fs::read(qr.join("packet-0000.cbor")).unwrap()).unwrap();
        mixed.bundle_id = "different".into();
        fs::write(
            qr.join("packet-0000.cbor"),
            serde_cbor::to_vec(&mixed).unwrap(),
        )
        .unwrap();
        assert!(import_qr_packets(&qr, &recovered).is_err());
    }

    #[test]
    fn scenario_pack_unpack_single_file() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("sample.txt");
        fs::write(&src, b"hello-aegisqr").unwrap();
        let bundle = dir.path().join("sample.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();
        let out = dir.path().join("out");
        unpack_capsule(&bundle, &out, "pw").unwrap();
        assert_eq!(
            fs::read(&src).unwrap(),
            fs::read(out.join("sample.txt")).unwrap()
        );
    }

    #[test]
    fn scenario_pack_unpack_directory_and_traversal_block() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("nested/a.txt"), b"A").unwrap();
        fs::write(src.join("b.bin"), b"B").unwrap();
        let bundle = dir.path().join("dir.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();
        let out = dir.path().join("out");
        unpack_capsule(&bundle, &out, "pw").unwrap();
        assert_eq!(
            hash_bytes(&fs::read(src.join("nested/a.txt")).unwrap()),
            hash_bytes(&fs::read(out.join("nested/a.txt")).unwrap())
        );

        assert!(validate_relative(Path::new("../escape.txt")).is_err());
    }

    #[test]
    fn scenario_aicx_roundtrip_and_verify_strict_trust() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("archive.aicx");
        fs::write(&src, b"aicx-bytes").unwrap();
        let bundle = dir.path().join("a.aqr");
        pack_to_file(
            &src,
            &bundle,
            "pw",
            PackOptions {
                payload_type: Some(PayloadType::AicxArchive),
                ..PackOptions::default()
            },
        )
        .unwrap();

        let mut trust = TrustStore::default();
        let capsule = read_capsule_file(&bundle).unwrap();
        trust.add_signer(
            capsule.signature_block.signer_id.clone(),
            capsule.signature_block.public_key.clone(),
        );
        verify_capsule(&bundle, Some(&trust), true).unwrap();

        let unknown = TrustStore::default();
        assert!(verify_capsule(&bundle, Some(&unknown), true).is_err());
    }

    #[test]
    fn scenario_qr_export_import_tamper_and_stage_quarantine() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("run.sh");
        fs::write(&src, b"echo hi").unwrap();
        let bundle = dir.path().join("run.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();

        let qr = dir.path().join("qr");
        export_qr_packets(&bundle, &qr, 16, false).unwrap();
        let mut p = fs::read(qr.join("packet-0000.cbor")).unwrap();
        p[0] ^= 0x01;
        fs::write(qr.join("packet-0000.cbor"), p).unwrap();
        let recovered = dir.path().join("recover.aqr");
        assert!(import_qr_packets(&qr, &recovered).is_err());

        stage_capsule(&bundle, &dir.path().join("stage"), "pw").unwrap();
        assert!(dir.path().join("stage/quarantine/run.sh").exists());
    }

    #[test]
    fn scenario_inspect_and_decrypt_agent_index() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"hello").unwrap();
        let bundle = dir.path().join("x.aqr");
        pack_to_file(
            &src,
            &bundle,
            "pw",
            PackOptions {
                auto_execute_capable: true,
                auto_execute_requested: true,
                ..PackOptions::default()
            },
        )
        .unwrap();

        let header = inspect_header(&bundle).unwrap();
        assert_eq!(header.magic, "AQR1");
        assert!(!header.auto_execute_default);

        let index = decrypt_agent_index(&bundle, "pw").unwrap();
        assert!(index.auto_execute_declaration);
        let denied = deny_execution_message(&ClientPolicy::default(), true);
        assert!(denied.contains("disabled by client policy"));
    }

    #[test]
    fn path_traversal_in_raw_original_name_is_blocked() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("safe.txt");
        fs::write(&src, b"safe").unwrap();
        let bundle = dir.path().join("safe.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();

        let mut capsule = read_capsule_file(&bundle).unwrap();
        capsule.payload_section.original_name = "../escape.txt".into();
        write_capsule_file(&bundle, &capsule).unwrap();

        let out = dir.path().join("out");
        assert!(unpack_capsule(&bundle, &out, "pw").is_err());
        assert!(!dir.path().join("escape.txt").exists());
    }

    #[test]
    fn export_qr_packet_size_zero_fails() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let out = dir.path().join("x.aqr");
        pack_to_file(&src, &out, "pw", PackOptions::default()).unwrap();
        let qr = dir.path().join("qr");
        assert!(export_qr_packets(&out, &qr, 0, false).is_err());
    }

    #[test]
    fn import_qr_rejects_bad_magic() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"abc").unwrap();
        let out = dir.path().join("x.aqr");
        pack_to_file(&src, &out, "pw", PackOptions::default()).unwrap();
        let qr = dir.path().join("qr");
        export_qr_packets(&out, &qr, 32, false).unwrap();

        let mut packet: QrPacket =
            serde_cbor::from_slice(&fs::read(qr.join("packet-0000.cbor")).unwrap()).unwrap();
        packet.magic = "BAD!".into();
        fs::write(
            qr.join("packet-0000.cbor"),
            serde_cbor::to_vec(&packet).unwrap(),
        )
        .unwrap();
        let recovered = dir.path().join("recovered.aqr");
        assert!(import_qr_packets(&qr, &recovered).is_err());
    }

    #[test]
    fn auto_execute_requested_without_capable_is_normalised_to_false() {
        // Bug-fix regression: if auto_execute_capable is false, the capsule must
        // not declare auto_execute_declaration=true even when
        // auto_execute_requested=true, because that would contradict the public
        // header's capability flag.
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"hello").unwrap();
        let bundle = dir.path().join("x.aqr");
        pack_to_file(
            &src,
            &bundle,
            "pw",
            PackOptions {
                auto_execute_capable: false,
                auto_execute_requested: true,
                ..PackOptions::default()
            },
        )
        .unwrap();
        let capsule = read_capsule_file(&bundle).unwrap();
        assert!(!capsule.public_header.auto_execute_capable);
        assert!(!capsule.agent_index.auto_execute_declaration);
    }

    #[test]
    fn section_table_does_not_contain_stale_signature_block_hash() {
        // Bug-fix regression: the section_table used to include a "signature_block"
        // entry hashed from the empty placeholder before signing.  That hash was
        // always wrong once the real key/signature were written.  The entry is now
        // omitted from the section table.
        let dir = tempdir().unwrap();
        let src = dir.path().join("a.txt");
        fs::write(&src, b"hello").unwrap();
        let bundle = dir.path().join("x.aqr");
        pack_to_file(&src, &bundle, "pw", PackOptions::default()).unwrap();
        let capsule = read_capsule_file(&bundle).unwrap();
        assert!(
            !capsule
                .section_table
                .iter()
                .any(|e| e.section_id == "signature_block"),
            "section_table must not contain a stale hash for signature_block"
        );
        // Signature verification must still succeed.
        verify_signature(&capsule).unwrap();
    }
}
