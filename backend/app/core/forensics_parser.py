import email
import ipaddress
import re
from datetime import datetime
from email import policy
from email.parser import HeaderParser
from typing import Any, Dict, List, Optional, Tuple


class ForensicHeaderParser:
    """
    Forensic RFC 822 / RFC 5322 Email Header Analysis Engine.
    Traces server relay hops, filters out bogon/private RFC 1918 addresses,
    pinpoints true originating public IPs, and extracts client fingerprints & authentication headers.
    """

    IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    IPV6_REGEX = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

    # Precise RFC 1918, Loopback, Link-Local, and Non-routable Private ranges
    INTERNAL_NETWORKS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("0.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fc00::/7"),
        ipaddress.ip_network("fe80::/10"),
    ]

    @classmethod
    def is_public_ip(cls, ip_str: str) -> bool:
        """
        Validates if an IP string is a public WAN address
        (specifically excluding RFC 1918 private subnets, loopbacks, link-local, and multicasts).
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local:
                return False
            for net in cls.INTERNAL_NETWORKS:
                if ip in net:
                    return False
            return True
        except ValueError:
            return False

    @classmethod
    def classify_ip(cls, ip_str: str) -> Dict[str, Any]:
        """
        Classifies an IP string into category (Public Internet, Private RFC 1918, Loopback, or Invalid).
        """
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            is_pub = cls.is_public_ip(ip_str)

            if ip.is_loopback:
                category = "Loopback"
            elif any(ip in net for net in cls.INTERNAL_NETWORKS[:3]):  # 10, 172.16, 192.168
                category = "Private (RFC 1918)"
            elif ip.is_link_local:
                category = "Link-Local"
            elif is_pub:
                category = "Public Internet"
            else:
                category = "Internal / Reserved"
            
            return {
                "ip": ip_str,
                "valid": True,
                "is_public": is_pub,
                "category": category,
                "version": ip.version
            }
        except ValueError:
            return {
                "ip": ip_str,
                "valid": False,
                "is_public": False,
                "category": "Invalid IP",
                "version": None
            }

    @classmethod
    def extract_ips_from_text(cls, text: str) -> List[str]:
        """
        Finds all IPv4 and IPv6 strings inside a raw text snippet.
        """
        v4s = cls.IPV4_REGEX.findall(text)
        v6s = cls.IPV6_REGEX.findall(text)
        return list(dict.fromkeys(v4s + v6s))  # preserve order, unique

    @classmethod
    def parse_single_received_hop(cls, hop_index: int, raw_hop_text: str) -> Dict[str, Any]:
        """
        Parses a single 'Received:' header block into sender, receiver, protocol, IP, and timestamp.
        """
        cleaned = " ".join(raw_hop_text.split())

        from_match = re.search(r"\bfrom\s+([^\s;()]+(?:\s*\([^)]*\))?)", cleaned, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s;()]+)", cleaned, re.IGNORECASE)
        with_match = re.search(r"\bwith\s+([^\s;()]+)", cleaned, re.IGNORECASE)
        date_match = re.search(r";\s*([^;]+)$", cleaned)

        from_token = from_match.group(1).strip() if from_match else "Unknown"
        by_token = by_match.group(1).strip() if by_match else "Unknown"
        protocol = with_match.group(1).strip() if with_match else "SMTP"
        timestamp_str = date_match.group(1).strip() if date_match else "Unknown"

        # Extract IPs from this specific hop
        all_ips = cls.extract_ips_from_text(cleaned)
        classified_ips = [cls.classify_ip(ip) for ip in all_ips if cls.classify_ip(ip)["valid"]]

        # Find first public IP in this hop, if any
        public_ip = next((c["ip"] for c in classified_ips if c["is_public"]), None)

        return {
            "hop_index": hop_index,
            "raw": cleaned,
            "from_host": from_token,
            "by_host": by_token,
            "protocol": protocol,
            "timestamp_str": timestamp_str,
            "ips_found": [c["ip"] for c in classified_ips],
            "ip_classifications": classified_ips,
            "identified_ip": public_ip or (classified_ips[0]["ip"] if classified_ips else "N/A"),
            "is_public_hop": bool(public_ip)
        }

    @classmethod
    def parse_headers(cls, raw_headers: str) -> Dict[str, Any]:
        """
        Performs full forensic inspection of RFC 822 email headers.
        Extracts hops, originating IP, user agents, and authentication headers.
        """
        if not raw_headers or not raw_headers.strip():
            return {
                "success": False,
                "error": "Empty or blank header text provided.",
                "hops": [],
                "originating_ip": None,
                "user_agent": "N/A",
                "authentication": {},
                "summary": "No headers analyzed."
            }

        # Normalize line breaks
        normalized = raw_headers.replace("\r\n", "\n").replace("\r", "\n")
        msg = HeaderParser(policy=policy.default).parsestr(normalized)

        # Basic metadata
        subject = msg.get("Subject", "N/A")
        date_header = msg.get("Date", "N/A")
        from_header = msg.get("From", "N/A")
        to_header = msg.get("To", "N/A")
        message_id = msg.get("Message-ID", "N/A")
        return_path = msg.get("Return-Path", "N/A")
        user_agent = (
            msg.get("User-Agent")
            or msg.get("X-Mailer")
            or msg.get("X-Client-Agent")
            or "Unknown / Stripped"
        )

        # Explicit originating IP header overrides if present
        explicit_originating_ip = (
            msg.get("X-Originating-IP")
            or msg.get("X-Sender-IP")
            or msg.get("X-Source-IP")
        )
        if explicit_originating_ip:
            clean_match = re.search(r"[0-9a-fA-F.:]+", explicit_originating_ip)
            if clean_match:
                explicit_originating_ip = clean_match.group(0)

        # Authentication headers
        received_spf = msg.get("Received-SPF", "N/A")
        auth_results = msg.get("Authentication-Results", "N/A")
        dkim_signature = msg.get("DKIM-Signature", "None")

        spf_status = "Unknown"
        combined_spf = f"{received_spf} {auth_results}".lower()
        if "pass" in combined_spf and "spf=pass" in combined_spf:
            spf_status = "PASS"
        elif "softfail" in combined_spf:
            spf_status = "SOFTFAIL"
        elif "fail" in combined_spf:
            spf_status = "FAIL"
        elif "neutral" in combined_spf:
            spf_status = "NEUTRAL"

        dkim_status = "None"
        combined_dkim = f"{dkim_signature} {auth_results}".lower()
        if dkim_signature != "None":
            if "dkim=pass" in combined_dkim:
                dkim_status = "PASS"
            elif "dkim=fail" in combined_dkim:
                dkim_status = "FAIL"
            else:
                dkim_status = "PRESENT (Unverified)"

        # Parse 'Received:' headers in chronological sequence (bottom to top)
        raw_received_list = msg.get_all("Received", [])
        chronological_hops = list(reversed(raw_received_list))
        parsed_hops: List[Dict[str, Any]] = []

        for idx, hop_str in enumerate(chronological_hops, start=1):
            hop_data = cls.parse_single_received_hop(idx, hop_str)
            parsed_hops.append(hop_data)

        # Determine true originating public IP:
        # 1. Prefer verified public explicit originating IP if valid
        originating_public_ip = None
        if explicit_originating_ip and cls.is_public_ip(explicit_originating_ip):
            originating_public_ip = explicit_originating_ip
        else:
            # 2. Iterate chronological hops from origin (Hop 1 upwards) and find first public IP
            for hop in parsed_hops:
                for ip_item in hop["ip_classifications"]:
                    if ip_item["is_public"]:
                        originating_public_ip = ip_item["ip"]
                        break
                if originating_public_ip:
                    break

        # If still none, check fallback regex over entire header block for any public IP
        if not originating_public_ip:
            all_found_ips = cls.extract_ips_from_text(normalized)
            for ip in all_found_ips:
                if cls.is_public_ip(ip):
                    originating_public_ip = ip
                    break

        # Forensic findings & anomaly flags
        anomalies = []
        if spf_status in ["FAIL", "SOFTFAIL"]:
            anomalies.append("SPF Validation Issue: Sender IP is not authorized by domain's SPF record.")
        if dkim_status == "FAIL":
            anomalies.append("DKIM Signature Invalid: Cryptographic signature mismatch detected.")
        if not parsed_hops:
            anomalies.append("No 'Received:' headers found in submitted text block.")
        if explicit_originating_ip and originating_public_ip and explicit_originating_ip != originating_public_ip:
            anomalies.append(f"Header discrepancy: X-Originating-IP ({explicit_originating_ip}) differs from relay hop IP ({originating_public_ip}).")

        return {
            "success": True,
            "subject": subject,
            "date": date_header,
            "from": from_header,
            "to": to_header,
            "message_id": message_id,
            "return_path": return_path,
            "user_agent": user_agent,
            "explicit_originating_ip": explicit_originating_ip,
            "originating_public_ip": originating_public_ip or "Not Found (Encrypted/Private Relay)",
            "authentication": {
                "spf_status": spf_status,
                "dkim_status": dkim_status,
                "received_spf": received_spf[:160],
                "auth_results": auth_results[:160]
            },
            "hop_count": len(parsed_hops),
            "hops": parsed_hops,
            "anomalies": anomalies,
            "summary": (
                f"Traced {len(parsed_hops)} routing hops. "
                f"Originating Public IP identified as: {originating_public_ip or 'Private/Hidden'}. "
                f"SPF Status: {spf_status}, DKIM: {dkim_status}."
            )
        }
