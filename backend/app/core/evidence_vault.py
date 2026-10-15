import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union


class EvidenceVault:
    """
    Forensic Evidence Integrity Engine.
    Provides SHA-256 cryptographic hashing, chain-of-custody logging,
    and mathematical tamper verification for cyberstalking electronic evidence.
    """

    @staticmethod
    def calculate_sha256(data: Union[str, bytes, Dict[str, Any], List[Any]]) -> str:
        """
        Compute an RFC 6234 compliant SHA-256 cryptographic digest.
        Ensures canonical JSON serialization for dictionaries and lists.
        """
        if isinstance(data, bytes):
            payload = data
        elif isinstance(data, (dict, list)):
            canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            payload = canonical_str.encode("utf-8")
        else:
            payload = str(data).encode("utf-8")

        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def generate_custody_record(
        item_id: str,
        item_type: str,
        content: Union[str, bytes, Dict[str, Any]],
        source_identifier: str,
        recorded_by: str = "AegisTrace-Forensic-Daemon",
        notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Creates a legally admissible chain-of-custody evidence receipt.
        """
        sha256_hash = EvidenceVault.calculate_sha256(content)
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Safe preview length for audit trails
        if isinstance(content, (dict, list)):
            preview = json.dumps(content)[:120] + ("..." if len(json.dumps(content)) > 120 else "")
        elif isinstance(content, bytes):
            preview = f"[Binary data: {len(content)} bytes]"
        else:
            preview = str(content)[:120] + ("..." if len(str(content)) > 120 else "")

        return {
            "evidence_id": item_id,
            "item_type": item_type,
            "source": source_identifier,
            "sha256_hash": sha256_hash,
            "acquired_at_utc": timestamp,
            "custodian": recorded_by,
            "preview": preview,
            "verified": True,
            "notes": notes or "Item sealed in digital evidence repository upon ingestion."
        }

    @staticmethod
    def verify_tamper_integrity(original_hash: str, current_content: Union[str, bytes, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validates content integrity against a previously recorded SHA-256 hash.
        """
        recalculated_hash = EvidenceVault.calculate_sha256(current_content)
        is_intact = (original_hash.lower() == recalculated_hash.lower())
        
        return {
            "status": "VERIFIED_INTACT" if is_intact else "TAMPER_DETECTED",
            "is_valid": is_intact,
            "recorded_hash": original_hash,
            "recalculated_hash": recalculated_hash,
            "verified_at_utc": datetime.now(timezone.utc).isoformat()
        }
