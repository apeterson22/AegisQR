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
- packet index / duplicate / reconstructed-capsule validation during QR import
- public-header, section-table, and chunk-table consistency validation before verify / restore
- path traversal and symlink extraction blocking
- executable/script quarantine on restore/stage
- checksum-enforced remote installer downloads unless the caller explicitly opts out
- explicit safe denial for execution
- no persistence/privilege escalation/startup hooks
