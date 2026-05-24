# AegisQR Documentation Guidelines

## Scope
This file applies to everything under `AegisQR/`. The directory is currently planning and design documentation rather than executable code.

## Project Structure
- `PLAN.md` is the primary source of truth for the proposed format and implementation direction.
- `plan-enterprise.md` is the enterprise integration brief for AICX, Artifactory, and Nexus workflows.
- `.github/workflows/` carries CI, portable release, and CodeQL automation; `.github/dependabot.yml` keeps Cargo and Actions dependencies under review.
- Future spec, security, and threat-model documents should stay under this tree unless the structure is explicitly revised.
- Keep examples, tables, and fenced code blocks aligned with the planned architecture described in the plan.

## Commands
- Use `rg -n "<term>" AegisQR/` to cross-check terminology and repeated references.
- Use `sed -n '1,120p' AegisQR/PLAN.md` or similar ranges when reviewing a specific section.
- Use `sed -n '1,120p' AegisQR/plan-enterprise.md` when checking enterprise guidance against transport or approval-flow updates.
- If a Markdown linter is available locally, run it on changed files before finishing a large doc edit.
- There is no build or runtime target in this directory yet, so do not invent package commands here.

## Style
- Keep the prose internally consistent and aligned with the security-first architecture in `PLAN.md`.
- Prefer short headings, direct language, and explicit security boundaries.
- Keep code fences valid and use stable terminology for formats, sections, and workflows.

## Testing
- Verify that headings, lists, and fenced blocks still render cleanly after edits.
- Check that links, file names, and section references remain consistent within the plan.
- If you add more docs, confirm they do not contradict the existing trust, execution, or recovery model.

## Security
- Preserve the rule that scanning, decrypting, staging, and restoring do not imply execution.
- Keep auto-execute explicitly policy-gated and disabled by default in the documentation.
- Keep QR transport guidance aligned with the stricter import rules: validate magic/version/index/total/hash/checksum consistency, reject conflicting duplicates, and require reconstructed capsules to still be `AQR1`.
- Preserve enterprise compatibility wording for serialized fields such as `aicx_sidecar`, `toon_export`, `enterprise_policy`, and `approval_tokens`; do not document them as removed just because Rust field names changed.
- Keep remote archive install guidance aligned with the hardened installers: HTTPS only, checksum-required for direct remote archives unless the caller explicitly opts out.
- Avoid wording that weakens trust boundaries, policy requirements, or section isolation.

## Agent Workflow
- Keep changes minimal and targeted to the requested documentation area.
- Do not move content out of `AegisQR/` unless the repository structure is intentionally changing.
- When implementation work begins later, add a directory-specific guide in the new code subtree.
- When updating release automation, QR transport, or trust verification docs, keep `PLAN.md`, `plan-enterprise.md`, `SPEC.md`, `THREAT_MODEL.md`, and `.github/copilot-instructions.md` synchronized.
- Do not overwrite another agent’s documentation edits.
