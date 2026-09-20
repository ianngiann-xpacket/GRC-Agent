"""Step 33-D: GCP Identity Normalizer (Sections 5 & 6).

Parses diverse GCP resource locators into a canonical GCPResourceIdentity model.
Supports:
- Full resource names (//service.googleapis.com/projects/...)
- Self-link URLs (https://www.googleapis.com/...)
- GCS URIs (gs://bucket-name)
- Relative resource names (projects/proj/zones/zone/instances/name)
- Simple resource names with context (project, service, resource_type)

Enforces strict input sanitation against injection strings, path traversals, and null bytes.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from secgrc.connectors.resolution.models import (
    GCPResourceIdentity,
    compute_canonical_resource_key,
)


DANGEROUS_PATTERNS = [
    re.compile(r"[\x00\r\n]"),
    re.compile(r"[;`$|><&]"),
    re.compile(r"\.\./|\.\.\\"),  # Path traversal
]


def sanitize_input(value: Optional[str]) -> str:
    """Validates that an identifier does not contain malicious characters."""
    if not value:
        return ""
    v = value.strip()
    for pat in DANGEROUS_PATTERNS:
        if pat.search(v):
            raise ValueError(f"Malicious or invalid characters detected in resource locator: '{v}'")
    return v


class GCPIdentityNormalizer:
    """Deterministic parser and normalizer for GCP resource identities."""

    @classmethod
    def normalize(
        cls,
        raw_locator: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> GCPResourceIdentity:
        """Parses and normalizes a raw GCP resource locator into GCPResourceIdentity.

        Args:
            raw_locator: The raw identifier (URI, URL, gs://, relative path, or short ID).
            context: Optional contextual attributes from raw observation (project_id, service, etc.).
        """
        ctx = context or {}
        raw = sanitize_input(raw_locator)
        if not raw:
            raise ValueError("Raw resource locator cannot be empty")

        ctx_proj = sanitize_input(ctx.get("project_id") or ctx.get("project") or "")
        ctx_service = sanitize_input(ctx.get("service") or "")
        ctx_rtype = sanitize_input(ctx.get("resource_type") or ctx.get("type") or "")
        ctx_region = sanitize_input(ctx.get("region") or "")
        ctx_zone = sanitize_input(ctx.get("zone") or "")

        # 1. GCS gs://bucket-name[/object]
        if raw.startswith("gs://"):
            bucket_path = raw[5:].strip("/")
            parts = bucket_path.split("/", 1)
            bucket_name = parts[0]
            proj = ctx_proj or "unknown-project"
            full_name = f"//storage.googleapis.com/projects/{proj}/buckets/{bucket_name}"
            self_link = f"https://storage.googleapis.com/storage/v1/b/{bucket_name}"
            canon_key = compute_canonical_resource_key(proj, "storage_bucket", bucket_name)
            return GCPResourceIdentity(
                cloud_provider="GCP",
                project_id=proj if proj != "unknown-project" else None,
                service="storage",
                resource_type="storage_bucket",
                resource_id=bucket_name,
                resource_name=bucket_name,
                full_resource_name=full_name,
                self_link=self_link,
                canonical_resource_key=canon_key,
                location=ctx_region or "global",
            )

        # 2. Full resource name: //compute.googleapis.com/projects/...
        if raw.startswith("//"):
            clean = raw[2:]
            slash_idx = clean.find("/")
            if slash_idx != -1:
                service_domain = clean[:slash_idx].lower()
                path = clean[slash_idx + 1:]
                service = service_domain.replace(".googleapis.com", "")
                return cls._parse_relative_path(path, service, raw, ctx)

        # 3. HTTP / HTTPS Self-link URL
        if raw.startswith("http://") or raw.startswith("https://"):
            parsed = urlparse(raw)
            domain = (parsed.netloc or "").lower()
            path = parsed.path.strip("/")
            service = "compute"
            if "storage.googleapis.com" in domain or path.startswith("storage/"):
                service = "storage"
            elif "iam.googleapis.com" in domain or path.startswith("iam/"):
                service = "iam"
            elif "cloudkms.googleapis.com" in domain or path.startswith("cloudkms/"):
                service = "cloudkms"
            elif "compute.googleapis.com" in domain or path.startswith("compute/"):
                service = "compute"
            return cls._parse_relative_path(path, service, raw, ctx)

        # 4. Relative resource name: projects/<proj>/...
        if raw.startswith("projects/"):
            return cls._parse_relative_path(raw, ctx_service or "compute", None, ctx)

        # 5. CryptoKeys / KeyRings relative format: locations/...
        if raw.startswith("locations/"):
            proj = ctx_proj or "unknown-project"
            rel_path = f"projects/{proj}/{raw}"
            return cls._parse_relative_path(rel_path, "cloudkms", None, ctx)

        # 6. Service account email: sa@project.iam.gserviceaccount.com
        if "@" in raw and raw.endswith(".gserviceaccount.com"):
            sa_email = raw.lower()
            sa_proj = sa_email.split("@")[1].split(".")[0]
            proj = ctx_proj or sa_proj
            full_name = f"//iam.googleapis.com/projects/{proj}/serviceAccounts/{sa_email}"
            canon_key = compute_canonical_resource_key(proj, "iam_service_account", sa_email)
            return GCPResourceIdentity(
                cloud_provider="GCP",
                project_id=proj,
                service="iam",
                resource_type="iam_service_account",
                resource_id=sa_email,
                resource_name=sa_email.split("@")[0],
                full_resource_name=full_name,
                canonical_resource_key=canon_key,
                location="global",
            )

        # 7. Fallback: Short resource name or ID with context
        proj = ctx_proj or "unknown-project"
        service = ctx_service or "compute"
        rtype = ctx_rtype or "resource"
        canon_key = compute_canonical_resource_key(proj, rtype, raw)
        return GCPResourceIdentity(
            cloud_provider="GCP",
            project_id=proj if proj != "unknown-project" else None,
            service=service,
            resource_type=rtype,
            resource_id=raw,
            resource_name=raw,
            full_resource_name=f"//{service}.googleapis.com/projects/{proj}/{rtype}s/{raw}",
            canonical_resource_key=canon_key,
            region=ctx_region or None,
            zone=ctx_zone or None,
            location=ctx_zone or ctx_region or "global",
        )

    @classmethod
    def _parse_relative_path(
        cls,
        path: str,
        service: str,
        original_uri: Optional[str],
        ctx: Dict[str, Any],
    ) -> GCPResourceIdentity:
        """Parses a relative path like projects/proj/zones/zone/instances/name."""
        # Strip API version prefixes if present (e.g. compute/v1/, storage/v1/)
        clean_path = re.sub(r"^(?:compute|storage|iam|cloudkms|sqladmin)/v\d+/", "", path)
        parts = [p for p in clean_path.split("/") if p]

        proj: Optional[str] = None
        zone: Optional[str] = None
        region: Optional[str] = None
        resource_type: str = "resource"
        resource_name: str = parts[-1] if parts else "unknown"
        resource_id: str = resource_name

        # Parse key-value pairs in path: projects/<p>/zones/<z>/instances/<i>
        i = 0
        while i < len(parts) - 1:
            seg = parts[i].lower()
            val = parts[i + 1]
            if seg == "projects":
                proj = val
                i += 2
            elif seg == "zones":
                zone = val
                region = "-".join(zone.split("-")[:2]) if "-" in zone else zone
                i += 2
            elif seg == "regions" or seg == "locations":
                region = val
                i += 2
            elif seg in ("instances", "disks", "firewalls", "networks", "subnetworks", "buckets", "serviceaccounts", "cryptokeys", "keyrings"):
                resource_type = cls._standardize_resource_type(seg)
                resource_name = val
                resource_id = val
                i += 2
            else:
                i += 1

        final_proj = proj or ctx.get("project_id") or ctx.get("project") or "unknown-project"
        final_service = service.lower()
        if not resource_type or resource_type == "resource":
            resource_type = cls._infer_type_from_service_or_context(final_service, ctx)

        full_name = original_uri if original_uri and original_uri.startswith("//") else f"//{final_service}.googleapis.com/{clean_path}"
        self_link = original_uri if original_uri and original_uri.startswith("http") else None

        canon_key = compute_canonical_resource_key(final_proj, resource_type, resource_id)

        return GCPResourceIdentity(
            cloud_provider="GCP",
            project_id=final_proj if final_proj != "unknown-project" else None,
            service=final_service,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            full_resource_name=full_name,
            self_link=self_link,
            canonical_resource_key=canon_key,
            region=region or ctx.get("region"),
            zone=zone or ctx.get("zone"),
            location=zone or region or ctx.get("zone") or ctx.get("region") or "global",
        )

    @classmethod
    def _standardize_resource_type(cls, segment: str) -> str:
        s = segment.lower()
        mapping = {
            "instances": "compute_instance",
            "disks": "compute_disk",
            "firewalls": "compute_firewall",
            "networks": "compute_network",
            "subnetworks": "compute_subnetwork",
            "buckets": "storage_bucket",
            "serviceaccounts": "iam_service_account",
            "cryptokeys": "kms_crypto_key",
            "keyrings": "kms_key_ring",
        }
        return mapping.get(s, s.rstrip("s"))

    @classmethod
    def _infer_type_from_service_or_context(cls, service: str, ctx: Dict[str, Any]) -> str:
        if ctx.get("resource_type"):
            return str(ctx["resource_type"])
        if service == "storage":
            return "storage_bucket"
        if service == "iam":
            return "iam_service_account"
        if service == "cloudkms":
            return "kms_crypto_key"
        if service == "compute":
            return "compute_instance"
        return "cloud_resource"
