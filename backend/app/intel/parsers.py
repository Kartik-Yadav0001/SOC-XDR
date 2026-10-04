"""Threat Intelligence Parsers for STIX 2.1, MISP, and format auto-detection."""

import re
from typing import Dict, Any, List, Optional


IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
HASH_REGEX = re.compile(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")
URL_REGEX = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_indicator_type(value: str) -> str:
    """Auto-detect IoC indicator type from string value."""
    val = value.strip()
    if IP_REGEX.match(val):
        return "IP"
    if HASH_REGEX.match(val):
        return "HASH"
    if URL_REGEX.match(val):
        return "URL"
    if EMAIL_REGEX.match(val):
        return "EMAIL"
    if DOMAIN_REGEX.match(val):
        return "DOMAIN"
    return "UNKNOWN"


def parse_stix_bundle(stix_json: Dict[str, Any], default_source: str = "STIX 2.1 Feed") -> List[Dict[str, Any]]:
    """Parse STIX 2.1 JSON bundle object and extract standardized IoCs."""
    parsed_indicators = []
    objects = stix_json.get("objects", [])

    if isinstance(stix_json, list):
        objects = stix_json

    for obj in objects:
        if not isinstance(obj, dict):
            continue

        obj_type = obj.get("type")
        confidence = float(obj.get("confidence", 80.0))
        tags = obj.get("labels", []) or obj.get("object_marking_refs", [])

        if obj_type == "indicator":
            pattern = obj.get("pattern", "")
            # Extract values from STIX pattern like [ipv4-addr:value = '198.51.100.1']
            matches = re.findall(r"='([^']+)'", pattern)
            if not matches:
                matches = re.findall(r"= '([^']+)'", pattern)

            for val in matches:
                ioc_type = detect_indicator_type(val)
                if ioc_type != "UNKNOWN":
                    parsed_indicators.append({
                        "value": val.strip(),
                        "indicator_type": ioc_type,
                        "reputation": "malicious",
                        "confidence": confidence,
                        "source": default_source,
                        "tags": tags if isinstance(tags, list) else [str(tags)],
                    })
        elif obj_type in ["ipv4-addr", "domain-name", "url", "file"]:
            val = obj.get("value") or obj.get("name")
            if obj_type == "file":
                hashes = obj.get("hashes", {})
                val = hashes.get("SHA-256") or hashes.get("MD5") or val

            if val:
                ioc_type = detect_indicator_type(str(val))
                if ioc_type != "UNKNOWN":
                    parsed_indicators.append({
                        "value": str(val).strip(),
                        "indicator_type": ioc_type,
                        "reputation": "malicious",
                        "confidence": confidence,
                        "source": default_source,
                        "tags": tags if isinstance(tags, list) else [],
                    })

    return parsed_indicators


def parse_misp_event(misp_json: Dict[str, Any], default_source: str = "MISP Threat Sharing") -> List[Dict[str, Any]]:
    """Parse MISP Event JSON object and extract standardized IoCs."""
    parsed_indicators = []
    
    event = misp_json.get("Event") or misp_json
    attributes = event.get("Attribute", []) or event.get("attributes", [])

    for attr in attributes:
        if not isinstance(attr, dict):
            continue

        category = attr.get("category", "")
        attr_type = attr.get("type", "")
        value = attr.get("value", "")

        if not value:
            continue

        # Handle composite MISP values like ip|port
        if "|" in str(value):
            value = str(value).split("|")[0]

        ioc_type = detect_indicator_type(str(value))
        if ioc_type != "UNKNOWN":
            tags = []
            if "Tag" in attr and isinstance(attr["Tag"], list):
                tags = [t.get("name") for t in attr["Tag"] if isinstance(t, dict) and t.get("name")]

            parsed_indicators.append({
                "value": str(value).strip(),
                "indicator_type": ioc_type,
                "reputation": "malicious" if attr.get("to_ids", True) else "suspicious",
                "confidence": 85.0 if attr.get("to_ids") else 60.0,
                "source": default_source,
                "tags": tags,
            })

    return parsed_indicators
