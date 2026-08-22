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
        """Deduplicate endpoints by (path, method), merging metadata on collision."""
        seen: dict[tuple, dict] = {}

        for item in items:
            key = (item.get("path", ""), item.get("method", "UNKNOWN"))

            if key not in seen:
                # Store a shallow copy so we never mutate the original.
                seen[key] = dict(item)
                seen[key]["parameters"] = list(item.get("parameters") or [])
                continue

            existing = seen[key]

            # Prefer a known HTTP method over UNKNOWN.
            if existing.get("method") == "UNKNOWN" and item.get("method") != "UNKNOWN":
                existing["method"] = item["method"]
                # Update key to the more specific method.
                del seen[key]
                new_key = (existing["path"], existing["method"])
                seen[new_key] = existing
                key = new_key

            # Union parameters, preserving insertion order.
            current_params = existing["parameters"]
            for p in item.get("parameters") or []:
                if p not in current_params:
                    current_params.append(p)

            # Keep higher confidence.
            if _CONFIDENCE_RANK.get(item.get("confidence", "low"), 0) > \
               _CONFIDENCE_RANK.get(existing.get("confidence", "low"), 0):
                existing["confidence"] = item["confidence"]

            # Keep longer evidence string (more context is better).
            if len(item.get("evidence", "")) > len(existing.get("evidence", "")):
                existing["evidence"] = item["evidence"]

            # Keep first non-null body_structure.
            if existing.get("body_structure") is None and item.get("body_structure") is not None:
                existing["body_structure"] = item["body_structure"]

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

        Relative paths (starting with /) are always kept. Only absolute URLs
        whose hostname does not contain target_domain are filtered out.
        """
        before = len(results.get("endpoints", []))

        def keep(ep: dict) -> bool:
            path = ep.get("path", "")
            if not path.startswith(("http://", "https://")):
                return True  # Relative path — always keep.
            hostname = urllib.parse.urlparse(path).hostname or ""
            return target_domain in hostname

        filtered_endpoints = [ep for ep in results.get("endpoints", []) if keep(ep)]
        removed = before - len(filtered_endpoints)

        if removed:
            logger.info(f"Filtered {removed} third-party endpoint(s) (domain: {target_domain}).")

        updated = {**results, "endpoints": filtered_endpoints}
        return self._recalculate_summary(updated)


result_merger = ResultMerger()
