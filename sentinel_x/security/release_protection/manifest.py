"""
Signed Release Manifest & Integrity Verification for Sentinel-X Anti-REA (Sections 5.1, 5.2, 5.3, 5.4).
Uses OpenSSL 3.0 Ed25519 asymmetric digital signatures to authenticate the publisher
and SHA-256 file inventory hashes to detect unauthorized file modifications (Tamper Detection).

Never embeds private signing keys in code and never claims 100% reverse-engineering prevention.
"""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel_x.core.exceptions import (
    ReleaseProtectionError,
    SignatureVerificationError,
)
from sentinel_x.security.release_protection.inventory import (
    FileInventoryEntry,
    build_file_inventory,
)

ANTI_REA_SCOPE_STATEMENT = (
    "Sentinel-X Release Protection (Anti-REA) provides Tamper Detection, Release Integrity "
    "Verification, Signed Release Manifest authentication, Build Hardening checks, and Sensitive "
    "Artifact Exposure Reduction. No software can guarantee 100% prevention against reverse engineering."
)


def generate_ed25519_keypair(private_key_path: Path, public_key_path: Path) -> None:
    """
    Generate an external Ed25519 keypair using OpenSSL 3.0 (shell=False).
    Intended for storing keys in an external key directory outside the repository.
    """
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "Ed25519",
                "-out",
                str(private_key_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
        )
        private_key_path.chmod(0o600)

        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(private_key_path),
                "-pubout",
                "-out",
                str(public_key_path),
            ],
            check=True,
            capture_output=True,
            text=True,
            shell=False,
        )
    except subprocess.CalledProcessError as exc:
        raise ReleaseProtectionError(
            f"OpenSSL Ed25519 key generation failed: {exc.stderr.strip()}"
        ) from exc


def sign_payload_ed25519(payload_bytes: bytes, private_key_path: Path) -> str:
    """Sign raw bytes using an external Ed25519 private key and return Base64 signature."""
    if not private_key_path or not private_key_path.is_file():
        raise ReleaseProtectionError(
            f"External Ed25519 private key file not found: {private_key_path}"
        )

    with tempfile.TemporaryDirectory() as tmpdir:
        msg_file = Path(tmpdir) / "payload.bin"
        sig_file = Path(tmpdir) / "sig.bin"
        msg_file.write_bytes(payload_bytes)
        try:
            subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(private_key_path),
                    "-rawin",
                    "-in",
                    str(msg_file),
                    "-out",
                    str(sig_file),
                ],
                check=True,
                capture_output=True,
                text=True,
                shell=False,
            )
        except subprocess.CalledProcessError as exc:
            raise ReleaseProtectionError(
                f"Ed25519 digital signature generation failed: {exc.stderr.strip()}"
            ) from exc

        return base64.b64encode(sig_file.read_bytes()).decode("ascii")


def verify_payload_ed25519(
    payload_bytes: bytes, signature_b64: str, public_key_path: Path
) -> bool:
    """Verify Base64 Ed25519 signature against payload_bytes using an external public key."""
    if not public_key_path or not public_key_path.is_file():
        raise SignatureVerificationError(
            f"External Ed25519 public key file not found: {public_key_path}"
        )
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise SignatureVerificationError(f"Malformed Base64 signature: {exc}") from exc

    with tempfile.TemporaryDirectory() as tmpdir:
        msg_file = Path(tmpdir) / "payload.bin"
        sig_file = Path(tmpdir) / "sig.bin"
        msg_file.write_bytes(payload_bytes)
        sig_file.write_bytes(sig_bytes)

        proc = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(public_key_path),
                "-rawin",
                "-in",
                str(msg_file),
                "-sigfile",
                str(sig_file),
            ],
            check=False,
            capture_output=True,
            text=True,
            shell=False,
        )
        return proc.returncode == 0


def canonicalize_manifest_body(manifest_body: Dict[str, Any]) -> bytes:
    """Produce deterministic canonical JSON bytes for signing and verification."""
    return json.dumps(manifest_body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


@dataclass
class VerificationResult:
    """Detailed outcome of Release Manifest & File Integrity Verification."""

    verified: bool
    signature_verified: bool
    integrity_verified: bool
    signature_algorithm: str
    total_manifest_files: int
    modified_files: List[str] = field(default_factory=list)
    missing_files: List[str] = field(default_factory=list)
    unexpected_files: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verified": self.verified,
            "signature_verified": self.signature_verified,
            "integrity_verified": self.integrity_verified,
            "signature_algorithm": self.signature_algorithm,
            "total_manifest_files": self.total_manifest_files,
            "modified_files": self.modified_files,
            "missing_files": self.missing_files,
            "unexpected_files": self.unexpected_files,
            "summary": self.summary,
            "security_scope": ANTI_REA_SCOPE_STATEMENT,
        }


def create_release_manifest(
    root_dir: Path | str,
    version: str = "0.1.0",
    publisher: str = "Sentinel-X Release Engineering",
    private_key_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Build a Release Manifest containing a SHA-256 file inventory and optional
    Ed25519 cryptographic digital signature.
    """
    entries: List[FileInventoryEntry] = build_file_inventory(root_dir)
    files_list = [e.to_dict() for e in entries]

    manifest_body: Dict[str, Any] = {
        "schema": "sentinel_x.release_manifest.v1",
        "version": version,
        "publisher": publisher,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "security_scope": ANTI_REA_SCOPE_STATEMENT,
        "file_count": len(files_list),
        "files": files_list,
    }
    canonical_bytes = canonicalize_manifest_body(manifest_body)
    inventory_sha256 = hashlib.sha256(canonical_bytes).hexdigest()

    signature_block: Dict[str, Any] = {
        "algorithm": "Ed25519" if private_key_path else "UNSIGNED",
        "inventory_sha256": inventory_sha256,
        "signature": "",
        "publisher_authenticated": False,
    }

    if private_key_path is not None:
        sig_b64 = sign_payload_ed25519(canonical_bytes, private_key_path)
        signature_block["signature"] = sig_b64
        signature_block["publisher_authenticated"] = True

    full_manifest = {
        "manifest": manifest_body,
        "signature_info": signature_block,
    }
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(full_manifest, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    return full_manifest


def verify_release_manifest(
    root_dir: Path | str,
    manifest_data_or_path: Dict[str, Any] | Path | str,
    public_key_path: Optional[Path] = None,
    require_signature: bool = True,
) -> VerificationResult:
    """
    Verify both the publisher's Ed25519 digital signature and the SHA-256 integrity
    of all files in root_dir against the manifest.
    Never accepts hash-only verification as publisher authentication when require_signature=True.
    """
    if isinstance(manifest_data_or_path, (Path, str)):
        mpath = Path(manifest_data_or_path)
        if not mpath.is_file():
            raise ReleaseProtectionError(f"Manifest file not found: {mpath}")
        try:
            full_manifest = json.loads(mpath.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReleaseProtectionError(f"Malformed manifest JSON: {exc}") from exc
    else:
        full_manifest = manifest_data_or_path

    manifest_body = full_manifest.get("manifest")
    sig_info = full_manifest.get("signature_info")
    if not isinstance(manifest_body, dict) or not isinstance(sig_info, dict):
        raise ReleaseProtectionError("Invalid manifest structure: missing 'manifest' or 'signature_info'.")

    canonical_bytes = canonicalize_manifest_body(manifest_body)
    computed_body_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
    recorded_body_sha256 = sig_info.get("inventory_sha256", "")

    alg = str(sig_info.get("algorithm", "UNSIGNED"))
    sig_b64 = str(sig_info.get("signature", ""))

    # 1. Digital Signature verification
    signature_verified = False
    if computed_body_sha256 != recorded_body_sha256:
        signature_verified = False
    elif require_signature:
        if alg != "Ed25519" or not sig_b64 or public_key_path is None:
            signature_verified = False
        else:
            signature_verified = verify_payload_ed25519(
                canonical_bytes, sig_b64, public_key_path
            )
    else:
        if alg == "Ed25519" and sig_b64 and public_key_path is not None:
            signature_verified = verify_payload_ed25519(
                canonical_bytes, sig_b64, public_key_path
            )
        else:
            signature_verified = False

    # 2. File Integrity / Tamper Detection
    expected_files: Dict[str, str] = {
        item["relative_path"]: item["sha256"]
        for item in manifest_body.get("files", [])
    }
    current_entries = build_file_inventory(root_dir)
    current_files: Dict[str, str] = {
        e.relative_path: e.sha256 for e in current_entries
    }

    modified_files: List[str] = []
    missing_files: List[str] = []
    unexpected_files: List[str] = []

    for rel_path, expected_hash in sorted(expected_files.items()):
        if rel_path not in current_files:
            missing_files.append(rel_path)
        elif current_files[rel_path] != expected_hash:
            modified_files.append(rel_path)

    for rel_path in sorted(current_files.keys()):
        if rel_path not in expected_files:
            unexpected_files.append(rel_path)

    integrity_verified = (
        computed_body_sha256 == recorded_body_sha256
        and not modified_files
        and not missing_files
        and not unexpected_files
    )

    overall_verified = (
        (signature_verified and integrity_verified)
        if require_signature
        else integrity_verified
    )

    reasons: List[str] = []
    if require_signature and not signature_verified:
        reasons.append("Digital signature verification FAILED (missing, invalid, or untrusted key)")
    elif signature_verified:
        reasons.append("Ed25519 digital signature VALID")
    else:
        reasons.append("Unsigned manifest (hash-only check; publisher identity NOT authenticated)")

    if integrity_verified:
        reasons.append(f"All {len(expected_files)} file hashes match")
    else:
        reasons.append(
            f"Tampering/drift detected: {len(modified_files)} modified, "
            f"{len(missing_files)} missing, {len(unexpected_files)} unexpected"
        )

    return VerificationResult(
        verified=overall_verified,
        signature_verified=signature_verified,
        integrity_verified=integrity_verified,
        signature_algorithm=alg,
        total_manifest_files=len(expected_files),
        modified_files=modified_files,
        missing_files=missing_files,
        unexpected_files=unexpected_files,
        summary="; ".join(reasons),
    )
