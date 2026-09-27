#!/usr/bin/env python3
"""One-off import of archived ransomware victim post titles."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path

from json_io import read_json, utc_now, write_json_atomic
from scrape_victims import clean_text, normalize_listing_record, normalize_name


ROOT = Path(__file__).resolve().parents[1]
GROUPS_PATH = ROOT / "site" / "data" / "groups.json"
VICTIMS_PATH = ROOT / "site" / "data" / "victims.json"

# Explicitly approved source-label aliases. Targets are current catalog IDs;
# no other fuzzy group matching is attempted.
APPROVED_GROUP_ALIASES = {
    "lockbit3_fs": "lockbit-30",
    "lockbit3_cronos": "lockbit-30",
    "hunters": "hunters-international",
    "medusa": "medusa-blog",
    "quantum": "quantum-locker",
    "payloadbin": "payload",
    "trinity": "trinitylock",
    "cheers": "cheerscrypt",
    "unsafeleak": "unsafe",
    "dataleak": "dataleakes",
    "blacktor": "blckt0r",
    "malas": "malaslocker",
    "vendetta": "v-vendetta",
    "robinhood": "robbinhood",
    "lockbit3": "lockbit-30",
    "clop": "cl0p",
}

_WRAPPER_PATTERNS = (
    re.compile(r"^leaks?\s+company\s+(.+?)\s*$", re.I),
    re.compile(r"^leakage\s+from\s+company\s+(.+?)\s*$", re.I),
    re.compile(r"^security\s+breach\s+of\s+(.+?)\s+network\s*[.!]*$", re.I),
    re.compile(r"^official\s+appeal\s+to\s+(.+?)\s*[.!]*$", re.I),
    re.compile(r"^leak\s+post\s+(.+?)\s*[.!]*$", re.I),
    re.compile(r"^new\s+files\s+for\s+leak\s+(.+?)\s+post\s*[.!]*$", re.I),
    re.compile(r"^full\s+data\s+leak\s+of\s+(.+?)\s*/+\s*$", re.I),
    re.compile(r"^full\s+data\s+leak\s+of\s+(.+?)\s*[.!]*$", re.I),
    re.compile(r"^leak\s+announcement\s*[-:–—]\s*(?:it\s+company\s+)?(.+?)\s*[.!]*$", re.I),
    re.compile(r"^(.+?)\s+[-–—]\s+announcement(?:\s+before\s+publishing\s+data)?\s*[.!]*$", re.I),
    re.compile(
        r"^announcement\s*:\s*(.+?)\s+(?:will\s+be\s+leaked|going\s+to\s+be\s+leaked|"
        r"will\s+be\s+published|going\s+to\s+be\s+published|will\s+be\s+leaked\s+soon|"
        r"will\s+be\s+leaked\s+in\s+\d+\s+days).*$",
        re.I,
    ),
    re.compile(r"^(.+?)\s*(?:\|\s*|[-–—:]\s*)data\s+security\s+breach\s*[.!]*$", re.I),
    re.compile(r"^(.+?)\s+(?:big\s+|full\s+|confidential\s+)?data\s+leak\s*[.!]*$", re.I),
    re.compile(r"^(.+?)\s+data\s+breach\s*[.!]*$", re.I),
    re.compile(r"^(.+?)\s+security\s+breach\s*[.!]*$", re.I),
    re.compile(r"^(.+?)\s+breach\s*[.!]*$", re.I),
)

_HEADLINE_OR_AMBIGUOUS = re.compile(
    r"\b(?:announce(?:s|d|ment)?|summary|evidence\s*&\s*debunking|"
    r"debunking|reported\s+to\s+the\s+sec|following\s+a\s+breach)\b",
    re.I,
)
_UNSUPPORTED_NEW_DATA_LEAK = re.compile(r"^new\s+data\s+leak\s+post\s+from\s+chemical\s+company\b", re.I)
_LEGAL_ENTITY_MARKER = re.compile(
    r"\b(?:incorporated|inc|llc|ltd|limited|corp|corporation|plc|gmbh|s\.?a\.?|s\.?r\.?l\.?|llp|pty)\b",
    re.I,
)


def compact_group_name(value: object) -> str:
    """Normalize punctuation and spacing for exact catalog-name comparisons."""
    decomposed = unicodedata.normalize("NFKD", str(value or "")).casefold()
    return "".join(character for character in decomposed if character.isalnum())


def build_group_matcher(groups: list[dict]) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return unambiguous exact-name and approved-alias mappings."""
    current_by_id: dict[str, dict] = {}
    candidates: dict[str, dict[str, dict]] = defaultdict(dict)
    for group in groups:
        if not isinstance(group, dict) or not group.get("group_id"):
            continue
        group_id = str(group["group_id"])
        current_by_id[group_id] = group
        for value in (group.get("group_id"), group.get("name")):
            key = compact_group_name(value)
            if key:
                candidates[key][group_id] = group

    exact = {
        key: next(iter(group_candidates.values()))
        for key, group_candidates in candidates.items()
        if len(group_candidates) == 1
    }
    aliases: dict[str, dict] = {}
    for alias, group_id in APPROVED_GROUP_ALIASES.items():
        target = current_by_id.get(group_id)
        if target is None:
            raise ValueError(f"Approved alias target is missing from the current catalog: {group_id}")
        aliases[compact_group_name(alias)] = target
    return exact, aliases


def match_group(label: object, exact: dict[str, dict], aliases: dict[str, dict]) -> dict | None:
    key = compact_group_name(label)
    return aliases.get(key) or exact.get(key)


def _strip_title_decoration(value: str) -> str:
    title = clean_text(value)
    title = re.sub(r"^[\s*_`~]+|[\s*_`~]+$", "", title)
    return clean_text(title)


def _looks_like_organization(value: str) -> bool:
    """Reject obvious prose/placeholders while retaining short real names."""
    candidate = clean_text(value).strip(" \t\r\n|!?:;,-")
    normalized = normalize_name(candidate)
    if not normalized or len(normalized.replace(" ", "")) < 2:
        return False
    if not re.search(r"[\w\u3400-\u9fff]", candidate, re.UNICODE):
        return False
    if _LEGAL_ENTITY_MARKER.search(candidate) or re.search(r"\b[\w-]+\.[A-Za-z]{2,}\b", candidate):
        return True
    if any(ord(character) > 127 and character.isalpha() for character in candidate):
        return True
    words = re.findall(r"[A-Za-z0-9]+(?:['’&.-][A-Za-z0-9]+)*", candidate)
    if not words:
        return False
    if len(words) == 1:
        return words[0].isupper() or (words[0][:1].isupper() and len(words[0]) >= 3)
    if any(word.isupper() and len(word) >= 2 for word in words):
        return True
    proper_words = sum(word[:1].isupper() for word in words)
    return proper_words >= 2


def _wrapper_organization(title: str) -> str | None:
    for pattern in _WRAPPER_PATTERNS:
        match = pattern.match(title)
        if match:
            candidate = clean_text(match.group(1)).strip(" \t\r\n|!?:;,-")
            if _looks_like_organization(candidate):
                return candidate
    return None


def classify_historical_title(value: object) -> dict | None:
    """Return a normalized victim record or None for a headline/ambiguous title."""
    original = clean_text(str(value or ""))[:500]
    title = _strip_title_decoration(original)
    if not title or _UNSUPPORTED_NEW_DATA_LEAK.match(title):
        return None

    wrapped_organization = _wrapper_organization(title)
    if wrapped_organization:
        normalized = normalize_listing_record({"post_title": title, "organization": wrapped_organization})
        if not normalized.get("country"):
            normalized.pop("country_basis", None)
        normalized["organization"] = wrapped_organization
        normalized["post_type"] = "victim"
    else:
        if _HEADLINE_OR_AMBIGUOUS.search(title):
            return None
        normalized = normalize_listing_record({"post_title": title, "organization": title})
        if normalized.get("post_type") != "victim":
            return None
        if not normalized.get("organization") or not _looks_like_organization(normalized["organization"]):
            return None

    # Keep the source title intact (apart from whitespace normalization and
    # the existing 500-character schema bound) for the dashboard disclosure.
    normalized["post_title"] = original
    normalized["record_id"] = None
    normalized.pop("claim_details", None)
    return normalized


def parse_discovered(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("Archive row is missing its discovered timestamp")
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        discovered = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"Invalid discovered timestamp: {text}") from exc
    if discovered.tzinfo is None:
        discovered = discovered.replace(tzinfo=timezone.utc)
    discovered = discovered.astimezone(timezone.utc)
    return discovered.isoformat().replace("+00:00", "Z")


def _stable_historical_id(group_id: str, organization: str) -> str:
    material = f"historical-posts\0{group_id}\0{normalize_name(organization)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _import_metadata(candidate: dict, imported_at: str) -> dict:
    previous = candidate.get("historical_import")
    metadata = dict(previous) if isinstance(previous, dict) else {}
    metadata.update({
        "source": "posts.txt",
        "earliest_discovered": candidate["first_seen_at"],
        "latest_discovered": candidate["archive_last_seen_at"],
        "archive_observations": candidate["archive_observations"],
        "archive_post_title": candidate["post_title"],
        "imported_at": metadata.get("imported_at") or imported_at,
    })
    return metadata


def build_import(
    posts: list[dict],
    catalog: dict,
    existing_data: dict,
    *,
    imported_at: str | None = None,
) -> tuple[dict, dict]:
    groups = catalog.get("groups")
    if not isinstance(groups, list):
        raise ValueError("Current group catalog has no groups list")
    exact, aliases = build_group_matcher(groups)
    now = imported_at or utc_now()
    candidates: dict[tuple[str, str], dict] = {}
    counts: Counter[str] = Counter()

    for row in posts:
        if not isinstance(row, dict):
            counts["invalid_row"] += 1
            continue
        group = match_group(row.get("group_name"), exact, aliases)
        if group is None:
            counts["unmatched_group"] += 1
            continue
        normalized = classify_historical_title(row.get("post_title"))
        if normalized is None:
            counts["excluded_headline_or_ambiguous"] += 1
            continue
        try:
            discovered = parse_discovered(row.get("discovered"))
        except ValueError:
            counts["invalid_timestamp"] += 1
            continue
        group_id = str(group["group_id"])
        organization = str(normalized["organization"])
        key = (group_id, normalize_name(organization))
        candidate = candidates.get(key)
        if candidate is None:
            candidate = {
                "id": _stable_historical_id(group_id, organization),
                "group_id": group_id,
                "group_name": str(group.get("name") or group_id),
                "organization": organization,
                "reported_date": None,
                "country": normalized.get("country"),
                "sector": None,
                "first_seen_at": discovered,
                "last_seen_at": discovered,
                "archive_last_seen_at": discovered,
                "listing_state": "unknown",
                "source_id": None,
                "source_ids": [],
                "source_host": None,
                "post_title": normalized.get("post_title"),
                "post_type": "victim",
                "record_id": None,
                "archive_observations": 1,
            }
            if normalized.get("country_basis"):
                candidate["country_basis"] = normalized["country_basis"]
            candidates[key] = candidate
        else:
            candidate["archive_observations"] += 1
            candidate["first_seen_at"] = min(candidate["first_seen_at"], discovered)
            if discovered > candidate["archive_last_seen_at"]:
                candidate["archive_last_seen_at"] = discovered
                candidate["last_seen_at"] = discovered
                candidate["post_title"] = normalized.get("post_title")
            if not candidate.get("country") and normalized.get("country"):
                candidate["country"] = normalized["country"]
                candidate["country_basis"] = normalized.get("country_basis")
        counts["matched_archive_rows"] += 1

    sightings = [dict(item) for item in existing_data.get("sightings", []) if isinstance(item, dict)]
    existing_index: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for sighting in sightings:
        group_id = str(sighting.get("group_id") or "")
        organization = normalize_name(str(sighting.get("organization") or ""))
        if group_id and organization:
            existing_index[(group_id, organization)].append(sighting)

    new_sightings = 0
    merged_sightings = 0
    for key, candidate in candidates.items():
        matches = existing_index.get(key, [])
        metadata = _import_metadata(candidate, now)
        if matches:
            for sighting in matches:
                sighting["first_seen_at"] = min(
                    str(sighting.get("first_seen_at") or candidate["first_seen_at"]),
                    candidate["first_seen_at"],
                )
                if not sighting.get("country") and candidate.get("country"):
                    sighting["country"] = candidate["country"]
                    sighting["country_basis"] = candidate.get("country_basis")
                if not sighting.get("organization"):
                    sighting["organization"] = candidate["organization"]
                if sighting.get("post_type") != "victim":
                    sighting["post_type"] = "victim"
                previous_metadata = sighting.get("historical_import")
                merged_metadata = dict(previous_metadata) if isinstance(previous_metadata, dict) else {}
                merged_metadata.update(metadata)
                raw_source_ids = sighting.get("source_ids", [])
                if isinstance(raw_source_ids, str):
                    source_ids = {raw_source_ids} if raw_source_ids else set()
                else:
                    source_ids = set(str(value) for value in raw_source_ids if value)
                if sighting.get("source_id"):
                    source_ids.add(str(sighting["source_id"]))
                source_ids.update(
                    str(value) for value in merged_metadata.get("matched_source_ids", []) if value
                )
                sighting["source_ids"] = sorted(source_ids)
                if not sighting.get("source_id"):
                    sighting["last_seen_at"] = max(
                        str(sighting.get("last_seen_at") or candidate["last_seen_at"]),
                        candidate["last_seen_at"],
                    )
                sighting["historical_import"] = merged_metadata
                merged_sightings += 1
            counts["merged_group_organization"] += 1
            continue

        candidate["historical_import"] = metadata
        candidate.pop("archive_last_seen_at", None)
        candidate.pop("archive_observations", None)
        sightings.append(candidate)
        new_sightings += 1
        counts["new_group_organization"] += 1

    result = dict(existing_data)
    result["updated_at"] = now
    result["sightings"] = sorted(
        sightings,
        key=lambda item: (
            str(item.get("last_seen_at") or ""),
            str(item.get("group_name") or "").casefold(),
            str(item.get("organization") or "").casefold(),
        ),
        reverse=True,
    )
    summary = {
        "archive_rows": len(posts),
        "matched_archive_rows": counts["matched_archive_rows"],
        "unique_group_organizations": len(candidates),
        "new_sightings": new_sightings,
        "existing_sightings_updated": merged_sightings,
        "excluded_headline_or_ambiguous": counts["excluded_headline_or_ambiguous"],
        "unmatched_group_rows": counts["unmatched_group"],
        "invalid_rows": counts["invalid_row"],
        "invalid_timestamps": counts["invalid_timestamp"],
        "matched_groups": len({candidate["group_id"] for candidate in candidates.values()}),
        "sighting_total": len(sightings),
    }
    return result, summary


def _read_posts(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, list):
        raise ValueError(f"Expected a JSON array in {path}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="JSON archive file, for example posts.txt")
    parser.add_argument("--groups", type=Path, default=GROUPS_PATH)
    parser.add_argument("--output", type=Path, default=VICTIMS_PATH)
    parser.add_argument("--apply", action="store_true", help="write the import; without this flag only preview it")
    args = parser.parse_args(argv)

    try:
        posts = _read_posts(args.input)
        catalog = read_json(args.groups, {})
        existing = read_json(args.output, {"sightings": [], "sources": []})
        result, summary = build_import(posts, catalog, existing)
        if args.apply:
            write_json_atomic(args.output, result)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Historical import failed: {exc}", file=sys.stderr)
        return 1

    mode = "applied" if args.apply else "dry-run; no files changed"
    print("Historical import " + mode)
    for key, value in summary.items():
        print(f"{key}={value}")
    if args.apply:
        print(f"Wrote {args.output}")
    else:
        print("Use --apply to write the reviewed result.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
