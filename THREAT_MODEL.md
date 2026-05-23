# Threat Model

Threats considered:
- malicious QR bundles
- tampered chunks
- unknown signers
- stolen printed QR sheets
- replayed old capsules
- malicious executable payloads
- compromised low-privilege agents
- insider signer abuse
- path traversal and symlink escape

Mitigations in MVP:
- integrity hashes and signature verification
- strict packet hash and checksum validation
- path traversal and symlink extraction blocking
- executable/script quarantine on restore/stage
- explicit safe denial for execution
- no persistence/privilege escalation/startup hooks
