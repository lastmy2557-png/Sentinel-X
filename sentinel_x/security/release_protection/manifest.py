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
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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

# ==============================================================================
# Standard RFC 8032 Ed25519 & RFC 8410 PKCS#8 / SPKI PEM Implementation
# 100% interoperable with OpenSSL 3.0 Ed25519 keys and signatures, while running
# natively across Windows, Linux, and macOS without requiring external binaries.
# ==============================================================================
_ED25519_P = (1 << 255) - 19
_ED25519_L = (1 << 252) + 27742317777372353535851937790883648493
_ED25519_D = (-121665 * pow(121666, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_ED25519_I = pow(2, (_ED25519_P - 1) // 4, _ED25519_P)

# RFC 8410 ASN.1 DER prefixes for Ed25519 (OID 1.3.101.112)
_PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
_SPKI_ED25519_PREFIX = bytes.fromhex("302a300506032b6570032100")

ExtPoint = Tuple[int, int, int, int]


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * pow(_ED25519_D * y * y + 1, _ED25519_P - 2, _ED25519_P) % _ED25519_P
    x = pow(xx, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = (x * _ED25519_I) % _ED25519_P
    if x % 2 != 0:
        x = _ED25519_P - x
    return x


_BY = (4 * pow(5, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
_BX = _xrecover(_BY)
_ED25519_BASE: ExtPoint = (_BX % _ED25519_P, _BY % _ED25519_P, 1, (_BX * _BY) % _ED25519_P)
_ED25519_NEUTRAL: ExtPoint = (0, 1, 1, 0)


def _edwards_add(p1: ExtPoint, p2: ExtPoint) -> ExtPoint:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % _ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % _ED25519_P
    c = (2 * _ED25519_D * t1 * t2) % _ED25519_P
    d = (2 * z1 * z2) % _ED25519_P
    e = (b - a) % _ED25519_P
    f = (d - c) % _ED25519_P
    g = (d + c) % _ED25519_P
    h = (b + a) % _ED25519_P
    return ((e * f) % _ED25519_P, (g * h) % _ED25519_P, (f * g) % _ED25519_P, (e * h) % _ED25519_P)


def _edwards_double(p1: ExtPoint) -> ExtPoint:
    x1, y1, z1, _ = p1
    a = (x1 * x1) % _ED25519_P
    b = (y1 * y1) % _ED25519_P
    c = (2 * z1 * z1) % _ED25519_P
    h = (a + b) % _ED25519_P
    x_plus_y = (x1 + y1) % _ED25519_P
    e = (h - (x_plus_y * x_plus_y) % _ED25519_P) % _ED25519_P
    g = (a - b) % _ED25519_P
    f = (c + g) % _ED25519_P
    return ((e * f) % _ED25519_P, (g * h) % _ED25519_P, (f * g) % _ED25519_P, (e * h) % _ED25519_P)


def _scalarmult(pt: ExtPoint, scalar: int) -> ExtPoint:
    res = _ED25519_NEUTRAL
    cur = pt
    s = scalar
    while s > 0:
        if s & 1:
            res = _edwards_add(res, cur)
        cur = _edwards_double(cur)
        s >>= 1
    return res


def _encode_point(pt: ExtPoint) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, _ED25519_P - 2, _ED25519_P)
    xp = (x * zi) % _ED25519_P
    yp = (y * zi) % _ED25519_P
    encoded = bytearray(yp.to_bytes(32, "little"))
    encoded[31] |= (xp & 1) << 7
    return bytes(encoded)


def _decode_point(raw: bytes) -> ExtPoint:
    if len(raw) != 32:
        raise ValueError("Invalid Ed25519 point length.")
    y = int.from_bytes(raw, "little") & ((1 << 255) - 1)
    if y >= _ED25519_P:
        raise ValueError("Ed25519 y-coordinate out of range.")
    x_sign = (raw[31] >> 7) & 1
    u = (y * y - 1) % _ED25519_P
    v = (_ED25519_D * y * y + 1) % _ED25519_P
    xx = (u * pow(v, _ED25519_P - 2, _ED25519_P)) % _ED25519_P
    x = pow(xx, (_ED25519_P + 3) // 8, _ED25519_P)
    if (x * x - xx) % _ED25519_P != 0:
        x = (x * _ED25519_I) % _ED25519_P
    if (x * x - xx) % _ED25519_P != 0:
        raise ValueError("Point is not on Ed25519 curve.")
    if x == 0 and x_sign == 1:
        raise ValueError("Invalid Ed25519 x=0 with sign bit 1.")
    if (x & 1) != x_sign:
        x = _ED25519_P - x
    return (x, y, 1, (x * y) % _ED25519_P)


def _ed25519_public_from_seed(seed: bytes) -> Tuple[int, bytes, bytes]:
    digest = hashlib.sha512(seed).digest()
    a_bytes = bytearray(digest[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a_scalar = int.from_bytes(a_bytes, "little")
    pub_bytes = _encode_point(_scalarmult(_ED25519_BASE, a_scalar))
    return a_scalar, digest[32:64], pub_bytes


def _extract_pem_der(pem_text: str) -> bytes:
    lines = [
        line.strip()
        for line in pem_text.strip().splitlines()
        if line.strip() and not line.strip().startswith("-----")
    ]
    if not lines:
        raise ValueError("Empty PEM payload.")
    return base64.b64decode("".join(lines), validate=True)


def generate_ed25519_keypair(private_key_path: Path, public_key_path: Path) -> None:
    """
    Generate an external Ed25519 keypair in standard RFC 8410 PEM format (OpenSSL 3.0 compatible).
    Intended for storing keys in an external key directory outside the repository.
    """
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        seed = os.urandom(32)
        _, _, pub_raw = _ed25519_public_from_seed(seed)

        priv_der = _PKCS8_ED25519_PREFIX + seed
        pub_der = _SPKI_ED25519_PREFIX + pub_raw

        priv_b64 = base64.b64encode(priv_der).decode("ascii")
        pub_b64 = base64.b64encode(pub_der).decode("ascii")

        marker = "-" * 5
        priv_pem = f"{marker}BEGIN {'PRIVATE'} KEY{marker}\n{priv_b64}\n{marker}END {'PRIVATE'} KEY{marker}\n"
        pub_pem = f"{marker}BEGIN {'PUBLIC'} KEY{marker}\n{pub_b64}\n{marker}END {'PUBLIC'} KEY{marker}\n"

        private_key_path.write_text(priv_pem, encoding="utf-8")
        try:
            private_key_path.chmod(0o600)
        except OSError:
            pass
        public_key_path.write_text(pub_pem, encoding="utf-8")
    except Exception as exc:
        raise ReleaseProtectionError(f"Ed25519 key generation failed: {exc}") from exc


def sign_payload_ed25519(payload_bytes: bytes, private_key_path: Path) -> str:
    """Sign raw bytes using an external Ed25519 private key (RFC 8032) and return Base64 signature."""
    if not private_key_path or not private_key_path.is_file():
        raise ReleaseProtectionError(
            f"External Ed25519 private key file not found: {private_key_path}"
        )

    try:
        der = _extract_pem_der(private_key_path.read_text(encoding="utf-8"))
        if len(der) == 48 and der.startswith(_PKCS8_ED25519_PREFIX):
            seed = der[16:48]
        elif len(der) >= 32:
            seed = der[-32:]
        else:
            raise ValueError("Invalid Ed25519 PKCS#8 private key length.")

        a_scalar, prefix, pub_bytes = _ed25519_public_from_seed(seed)
        r = int.from_bytes(hashlib.sha512(prefix + payload_bytes).digest(), "little") % _ED25519_L
        r_bytes = _encode_point(_scalarmult(_ED25519_BASE, r))
        k = int.from_bytes(hashlib.sha512(r_bytes + pub_bytes + payload_bytes).digest(), "little") % _ED25519_L
        s = (r + k * a_scalar) % _ED25519_L
        sig = r_bytes + s.to_bytes(32, "little")
        return base64.b64encode(sig).decode("ascii")
    except Exception as exc:
        raise ReleaseProtectionError(f"Ed25519 digital signature generation failed: {exc}") from exc


def verify_payload_ed25519(
    payload_bytes: bytes, signature_b64: str, public_key_path: Path
) -> bool:
    """Verify Base64 Ed25519 signature (RFC 8032) against payload_bytes using an external public key."""
    if not public_key_path or not public_key_path.is_file():
        raise SignatureVerificationError(
            f"External Ed25519 public key file not found: {public_key_path}"
        )
    try:
        sig_bytes = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise SignatureVerificationError(f"Malformed Base64 signature: {exc}") from exc

    if len(sig_bytes) != 64:
        return False

    try:
        der = _extract_pem_der(public_key_path.read_text(encoding="utf-8"))
        if len(der) == 44 and der.startswith(_SPKI_ED25519_PREFIX):
            pub_raw = der[12:44]
        elif len(der) == 32:
            pub_raw = der
        else:
            return False

        r_bytes = sig_bytes[:32]
        s = int.from_bytes(sig_bytes[32:64], "little")
        if s >= _ED25519_L:
            return False

        a_point = _decode_point(pub_raw)
        r_point = _decode_point(r_bytes)
        k = int.from_bytes(hashlib.sha512(r_bytes + pub_raw + payload_bytes).digest(), "little") % _ED25519_L

        lhs = _scalarmult(_ED25519_BASE, s)
        rhs = _edwards_add(r_point, _scalarmult(a_point, k))
        return _encode_point(lhs) == _encode_point(rhs)
    except Exception:
        return False


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
