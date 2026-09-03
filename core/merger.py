"""Merges and deduplicates analysis results from multiple sources."""

import urllib.parse

from utils.logger import logger

_CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "none": 0}

_EMPTY_RESULT = {
    "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
    "endpoints": [],
    "secrets": [],
    "auth_logic": [],
    "suspicious_logic": [],
}


class ResultMerger:

    def __init__(self):
        pass

    def merge(self, chunk_results: list[dict]) -> dict:
        """Merge a list of per-chunk analysis dicts into a single deduplicated result.

        Never loses a unique finding. Duplicates are dropped based on
        category-specific keys; no findings are silently combined into one.
        """
        if not chunk_results:
            return dict(_EMPTY_RESULT)

        # Flatten each category across all chunks before deduplication.
        raw_endpoints = [e for r in chunk_results for e in r.get("endpoints", [])]
        raw_secrets = [s for r in chunk_results for s in r.get("secrets", [])]
        raw_auth = [a for r in chunk_results for a in r.get("auth_logic", [])]
        raw_suspicious = [s for r in chunk_results for s in r.get("suspicious_logic", [])]

        logger.debug(
            f"Pre-dedup counts — endpoints: {len(raw_endpoints)}, "
            f"secrets: {len(raw_secrets)}, auth_logic: {len(raw_auth)}, "
            f"suspicious_logic: {len(raw_suspicious)}"
        )

        merged = {
            "analysis_summary": {"total_findings": 0, "highest_severity": "none"},
            "endpoints": self._dedupe_endpoints(raw_endpoints),
            "secrets": self._dedupe_secrets(raw_secrets),
            "auth_logic": self._dedupe_auth_logic(raw_auth),
            "suspicious_logic": self._dedupe_suspicious(raw_suspicious),
        }

        logger.debug(
            f"Post-dedup counts — endpoints: {len(merged['endpoints'])}, "
            f"secrets: {len(merged['secrets'])}, auth_logic: {len(merged['auth_logic'])}, "
            f"suspicious_logic: {len(merged['suspicious_logic'])}"
        )

        return self._recalculate_summary(merged)

    def _dedupe_endpoints(self, items: list[dict]) -> list[dict]:
        """Deduplicate endpoints by (path, method), merging metadata on collision.

        UNKNOWN acts as a wildcard method: a ``(path, UNKNOWN)`` finding and a
        concrete ``(path, POST)`` finding describe the same endpoint and are
        collapsed into the concrete one, regardless of the order they arrive in.
        Distinct concrete methods for the same path (GET vs POST) stay separate.
        """
        seen: dict[tuple, dict] = {}

        def _merge_into(existing: dict, item: dict) -> None:
            # Union parameters, preserving insertion order.
            current_params = existing["parameters"]
            for p in item.get("parameters") or []:
                if p not in current_params:
                    current_params.append(p)
            # Keep higher confidence.
            if _CONFIDENCE_RANK.get(item.get("confidence", "low"), 0) > \
               _CONFIDENCE_RANK.get(existing.get("confidence", "low"), 0):
                existing["confidence"] = item.get("confidence", existing.get("confidence"))
            # Keep longer evidence string (more context is better).
            if len(item.get("evidence", "")) > len(existing.get("evidence", "")):
                existing["evidence"] = item["evidence"]
            # Keep first non-null body_structure.
            if existing.get("body_structure") is None and item.get("body_structure") is not None:
                existing["body_structure"] = item["body_structure"]

        def _fresh(item: dict) -> dict:
            copy_ = dict(item)
            copy_["parameters"] = list(item.get("parameters") or [])
            return copy_

        for item in items:
            path = item.get("path", "")
            method = item.get("method", "UNKNOWN")
            key = (path, method)

            if key in seen:
                _merge_into(seen[key], item)
                continue

            if method != "UNKNOWN":
                # Upgrade a pending UNKNOWN entry for this path to the concrete method.
                unknown_key = (path, "UNKNOWN")
                if unknown_key in seen:
                    existing = seen.pop(unknown_key)
                    existing["method"] = method
                    _merge_into(existing, item)
                    seen[key] = existing
                else:
                    seen[key] = _fresh(item)
                continue

            # method == UNKNOWN: fold into an existing concrete entry for this path.
            concrete = next((k for k in seen if k[0] == path and k[1] != "UNKNOWN"), None)
            if concrete is not None:
                _merge_into(seen[concrete], item)
            else:
                seen[key] = _fresh(item)

        return list(seen.values())

    def _dedupe_secrets(self, items: list[dict]) -> list[dict]:
        """Deduplicate secrets by (type, value_preview). Keep longer evidence on collision."""
        seen: dict[tuple, dict] = {}

        for item in items:
            key = (item.get("type", ""), item.get("value_preview", ""))

            if key not in seen:
                seen[key] = dict(item)
            elif len(item.get("evidence", "")) > len(seen[key].get("evidence", "")):
                seen[key] = dict(item)

        return list(seen.values())

    def _dedupe_auth_logic(self, items: list[dict]) -> list[dict]:
        """Deduplicate auth_logic by (mechanism, storage_location), case-insensitive on mechanism."""
        seen: dict[tuple, dict] = {}

        for item in items:
            key = (
                item.get("mechanism", "").lower(),
                item.get("storage_location", ""),
            )

            if key not in seen:
                seen[key] = dict(item)
            elif len(item.get("evidence", "")) > len(seen[key].get("evidence", "")):
                seen[key] = dict(item)

        return list(seen.values())

    def _dedupe_suspicious(self, items: list[dict]) -> list[dict]:
        """Deduplicate suspicious_logic by evidence snippet. Keep higher severity on collision."""
        seen: dict[str, dict] = {}

        for item in items:
            key = item.get("evidence", "")

            if key not in seen:
                seen[key] = dict(item)
            elif _SEVERITY_RANK.get(item.get("severity", "info"), 0) > \
                 _SEVERITY_RANK.get(seen[key].get("severity", "info"), 0):
                seen[key] = dict(item)

        return list(seen.values())

    def _recalculate_summary(self, merged: dict) -> dict:
        """Rebuild analysis_summary from the merged data and return the updated dict."""
        total = (
            len(merged["endpoints"])
            + len(merged["secrets"])
            + len(merged["auth_logic"])
            + len(merged["suspicious_logic"])
        )

        highest = "none"
        for finding in merged["suspicious_logic"]:
            sev = finding.get("severity", "none")
            if _SEVERITY_RANK.get(sev, 0) > _SEVERITY_RANK.get(highest, 0):
                highest = sev

        # secrets/endpoints carry no per-item severity in the schema — floor the
        # summary so a real finding never rounds down to "none".
        if merged["secrets"] and _SEVERITY_RANK.get(highest, 0) < _SEVERITY_RANK["high"]:
            highest = "high"
        if merged["endpoints"] and _SEVERITY_RANK.get(highest, 0) < _SEVERITY_RANK["low"]:
            highest = "low"

        merged["analysis_summary"] = {
            "total_findings": total,
            "highest_severity": highest,
        }

        logger.info(f"Merge complete — {total} total finding(s), highest severity: {highest}")
        return merged

    def filter_third_party(self, results: dict, target_domain: str) -> dict:
        """Remove endpoints that are absolute URLs pointing to a different domain.

        Relative paths (starting with /) are always kept. An absolute URL is
        kept only when its hostname is the target domain or a subdomain of it —
        matched case-insensitively on a label boundary, so ``example.com`` keeps
        ``api.example.com`` but drops ``evil-example.com`` and ``example.com.evil.net``.
        """
        raw = (target_domain or "").strip().lower()
        if not raw:
            # No target specified — nothing to filter against.
            return self._recalculate_summary({**results})
        # Be forgiving if a full URL (or host:port) is passed instead of a bare
        # host: reduce "https://eservices.example.sa/x" -> "eservices.example.sa".
        parsed = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
        target = (parsed.hostname or raw).rstrip(".")

        before = len(results.get("endpoints", []))

        def keep(ep: dict) -> bool:
            path = ep.get("path", "")
            if not path.startswith(("http://", "https://")):
                return True  # Relative path — always keep.
            hostname = (urllib.parse.urlparse(path).hostname or "").lower()
            return hostname == target or hostname.endswith("." + target)

        filtered_endpoints = [ep for ep in results.get("endpoints", []) if keep(ep)]
        removed = before - len(filtered_endpoints)

        if removed:
            logger.info(f"Filtered {removed} third-party endpoint(s) (domain: {target_domain}).")

        updated = {**results, "endpoints": filtered_endpoints}
        return self._recalculate_summary(updated)


result_merger = ResultMerger()
