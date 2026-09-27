#!/usr/bin/env python3
"""Collect metadata-only victim listings from WatchGuard-listed leak sites."""

from __future__ import annotations

import argparse
from collections import defaultdict
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import datetime
import hashlib
import json
import re
import sys
import time
import unicodedata
from threading import Lock
from pathlib import Path
from typing import Callable
from urllib.parse import parse_qs, unquote, urljoin, urlparse, urlunsplit

from html_dom import Element, parse_html
from http_client import FetchError, fetch_html, normalize_url
from json_io import read_json, utc_now, write_json_atomic


ROOT = Path(__file__).resolve().parents[1]
GROUPS_PATH = ROOT / "site" / "data" / "groups.json"
OUTPUT_PATH = ROOT / "site" / "data" / "victims.json"
MAX_CONCURRENCY = 3
FETCH_DEADLINE_SECONDS = 25.0
CRAWL_BUDGET_SECONDS = 90 * 60
MAX_PAGES_PER_SOURCE = 25
REQUEST_DELAY_SECONDS = 0.8
VICTIM_HEADERS = ("victim", "company", "organization", "organisation", "target", "entity")
NAME_HEADERS = {"name", "company name", "victim name", "organization name", "organisation name"}
DATE_HEADERS = ("date", "posted", "published", "added", "reported", "listed", "exposure")
COUNTRY_HEADERS = ("country", "location", "region")
SECTOR_HEADERS = ("sector", "industry", "business")
CARD_CLASS_MARKERS = {"victim", "victim-card", "victim-item", "post", "post-card", "entry", "attack", "listing", "card"}
GENERIC_TITLES = {
    "home", "about", "contact", "news", "blog", "victims", "victim list",
    "recent victims", "all victims", "load more", "read more", "welcome",
    "important announcement", "why it matters", "what is stored", "warning",
    "press", "notice", "jurisdiction", "cooperation reached",
}
STATUS_TAGS = {
    "announcement", "all data published", "all stolen data", "data leak", "data leaked",
    "leaked", "new", "published", "publication", "released", "sale", "sold", "victim",
}
TITLE_PREFIXES = ("leak:", "victim:", "new victim:", "company:", "organization:")
HEADLINE_PREFIXES = (
    "view all", "load more", "read more", "what time does", "what time is",
    "response to ", "publication hold", "press release", "statement:", "article:",
    "why it matters", "what is stored", "warning:", "notice:", "jurisdiction:",
    "cooperation reached",
)
DETAIL_LABELS = {
    "description": {"description", "summary", "excerpt", "post description"},
    "claimed_data_size": {"data size", "claimed data size", "size of data", "data volume"},
    "file_count": {"file count", "number of files", "files", "documents", "record count"},
    "deadline": {"deadline", "publication deadline", "due date", "countdown"},
    "organization_website": {"website", "company website", "organization website", "domain"},
}
DETAIL_CLASS_LABELS = {
    "description": {"description", "summary", "excerpt", "post-description", "post-summary"},
    "claimed_data_size": {"data-size", "claimed-data-size", "data-volume"},
    "file_count": {"file-count", "files-count", "document-count", "record-count"},
    "deadline": {"deadline", "publication-deadline", "due-date", "countdown"},
    "organization_website": {"website", "company-website", "organization-website", "domain"},
}
FLAG_COUNTRIES = {
    "AE": "United Arab Emirates", "AR": "Argentina", "AT": "Austria", "AU": "Australia",
    "BE": "Belgium", "BR": "Brazil", "CA": "Canada", "CH": "Switzerland", "CL": "Chile",
    "CN": "China", "CO": "Colombia", "CR": "Costa Rica", "CZ": "Czechia", "DE": "Germany",
    "DK": "Denmark", "ES": "Spain", "FI": "Finland", "FR": "France", "GB": "United Kingdom",
    "GR": "Greece", "HK": "Hong Kong", "HU": "Hungary", "ID": "Indonesia", "IE": "Ireland",
    "IL": "Israel", "IN": "India", "IT": "Italy", "JP": "Japan", "KR": "South Korea",
    "LU": "Luxembourg", "MX": "Mexico", "MY": "Malaysia", "NL": "Netherlands", "NO": "Norway",
    "NZ": "New Zealand", "PH": "Philippines", "PL": "Poland", "PT": "Portugal", "RO": "Romania",
    "RU": "Russia", "SA": "Saudi Arabia", "SE": "Sweden", "SG": "Singapore", "TH": "Thailand",
    "TR": "Turkey", "TW": "Taiwan", "UA": "Ukraine", "US": "United States", "VN": "Vietnam",
    "ZA": "South Africa",
}
ListingParser = Callable[[str, str], dict]
PARSER_REGISTRY: dict[str, ListingParser] = {}


def register_parser(host_suffix: str, parser: ListingParser) -> None:
    """Register an explicit parser for a leak-site host suffix."""
    suffix = host_suffix.casefold().lstrip(".")
    if not suffix or "/" in suffix:
        raise ValueError("Parser host suffix must be a hostname")
    PARSER_REGISTRY[suffix] = parser


def clean_text(value: str) -> str:
    text = value or ""
    for corrupted, repaired in {
        "â\x86\x92": "→", "â†’": "→", "â\x86\x90": "←",
        "â€™": "’", "â€œ": "“", "â€\x9d": "”", "â€“": "–", "â€”": "—", "Â ": " ",
    }.items():
        text = text.replace(corrupted, repaired)
    return re.sub(r"\s+", " ", text).strip()


def normalize_name(value: str) -> str:
    # Preserve non-Latin organization names (for example Chinese, Japanese,
    # and Arabic text) so classification, deduplication, and history matching
    # do not collapse distinct companies to an empty string.
    normalized = unicodedata.normalize("NFKD", value).casefold()
    normalized = "".join(character for character in normalized if not unicodedata.combining(character))
    return re.sub(r"[\W_]+", " ", normalized, flags=re.UNICODE).strip()


def country_from_flag(value: str) -> tuple[str | None, str]:
    """Remove a leading regional-indicator flag and return its country name."""
    text = clean_text(value)
    if len(text) < 2 or not (0x1F1E6 <= ord(text[0]) <= 0x1F1FF and 0x1F1E6 <= ord(text[1]) <= 0x1F1FF):
        return None, text
    code = "".join(chr(ord(character) - 0x1F1E6 + ord("A")) for character in text[:2])
    # The compact fallback preserves a valid two-letter flag code even for a
    # country not in the display-name table, rather than dropping the signal.
    country = FLAG_COUNTRIES.get(code, code)
    return country, clean_text(text[2:])


def _clean_listing_title(value: str) -> tuple[str, str | None]:
    title = clean_text(value)
    inferred_country, title = country_from_flag(title)
    previous = None
    while previous != title:
        previous = title
        title = re.sub(r"\s*\[(?P<tag>[^\]]{1,80})\]\s*$", lambda match: "" if normalize_name(match.group("tag")) in STATUS_TAGS else match.group(0), title)
        title = clean_text(title)
    lowered = title.casefold()
    for prefix in TITLE_PREFIXES:
        if lowered.startswith(prefix):
            title = clean_text(title[len(prefix):])
            break
    return title[:240], inferred_country


def _classify_listing_title(title: str, organization: str | None = None) -> tuple[str, str | None]:
    """Conservatively separate clear organization names from post headlines."""
    raw = clean_text(title)
    cleaned, _country = _clean_listing_title(raw)
    candidate = clean_text(organization or cleaned) or None
    normalized = normalize_name(cleaned)
    lowered = cleaned.casefold()
    if not cleaned or not normalized:
        return "review", None
    if normalized in GENERIC_TITLES or any(lowered.startswith(prefix) for prefix in HEADLINE_PREFIXES):
        return "headline", None
    if re.match(r"^(?:important\s+)?announcement\b", lowered):
        match = re.match(r"^announcement\s+(?:for|about)\s+(?:the\s+)?(.+?)(?:\s+and\s+its\s+clients)?$", cleaned, re.I)
        return ("review", clean_text(match.group(1)) if match else None)
    if re.search(r"\b(?:article|interview|press release|announcement)\b", lowered):
        return "headline", None
    if re.match(r"^(?:welcome\s+to|welcome\s+back)\b", lowered):
        return "headline", None
    if re.match(r"^(?:response to|publication hold|press release|statement|article)\b", lowered):
        return "headline", None
    if "?" in cleaned or len(cleaned) > 120:
        return "review", candidate
    # Sentence-like claims are retained for inspection instead of being
    # counted as organizations; dotted legal suffixes without a predicate
    # (Inc., GmbH, S.r.l.) remain eligible victim names.
    sentence_cue = re.search(
        r"\b(?:has been|have been|was|were|will be|are being|we have|our company|announced that|reported that)\b",
        lowered,
    )
    if sentence_cue:
        return "review", candidate
    return "victim", candidate


def _bounded_text(value: object, limit: int = 500) -> str | None:
    text = clean_text(str(value or ""))
    if not text:
        return None
    return text[:limit]


def normalize_listing_record(record: dict) -> dict:
    """Normalize a parsed card/table row into the additive public schema."""
    result = dict(record)
    post_title = _bounded_text(result.get("post_title") or result.get("organization") or result.get("name"), 500)
    raw_organization = _bounded_text(result.get("organization") or result.get("name"), 240)
    cleaned_organization, flag_country = _clean_listing_title(raw_organization or post_title or "")
    post_type, candidate = _classify_listing_title(post_title or cleaned_organization, cleaned_organization or None)
    # A source may explicitly supply a normalized organization alongside a
    # longer post title; retain that candidate unless the title is clearly a
    # non-victim control/headline.
    if post_type == "victim" and raw_organization:
        candidate = cleaned_organization or raw_organization
    if post_type == "headline":
        candidate = None
    explicit_country = _bounded_text(result.get("country"), 120)
    country_flag, explicit_country_text = country_from_flag(explicit_country or "")
    country = explicit_country_text or country_flag or flag_country
    country_basis = result.get("country_basis")
    if country:
        if country_basis not in {"explicit", "flag_inferred"}:
            country_basis = "explicit" if explicit_country_text else "flag_inferred"
    else:
        country_basis = None

    details = dict(result.get("claim_details") or {})
    for key in DETAIL_LABELS:
        value = _bounded_text(details.get(key), 500 if key == "description" else 240)
        if value:
            details[key] = value
        else:
            details.pop(key, None)

    result.update({
        "post_title": post_title,
        "post_type": post_type,
        "organization": candidate,
        "reported_date": _bounded_text(result.get("reported_date"), 120),
        "country": country,
        "sector": _bounded_text(result.get("sector"), 160),
    })
    if country:
        result["country_basis"] = country_basis
    else:
        result.pop("country_basis", None)
    if details:
        result["claim_details"] = details
    else:
        result.pop("claim_details", None)
    return result


def _slug_from_url(value: str) -> str | None:
    parsed = urlparse(value)
    path = unquote(parsed.path).rstrip("/")
    if not path:
        return None
    slug = path.rsplit("/", 1)[-1]
    return slug if slug and slug not in {"index", "home"} else None


def _table_cells(row: Element) -> list[Element]:
    direct = [child for child in row.children if isinstance(child, Element) and child.tag in {"td", "th"}]
    if direct:
        return direct
    return [item for item in row.iter() if item.tag in {"td", "th"}]


def _headers_for_table(table: Element) -> list[str]:
    for row in table.iter("tr"):
        cells = _table_cells(row)
        if cells and any(cell.tag == "th" for cell in cells):
            return [clean_text(cell.text()).casefold() for cell in cells]
    first_row = next(iter(table.iter("tr")), None)
    if first_row:
        cells = _table_cells(first_row)
        values = [clean_text(cell.text()).casefold() for cell in cells]
        if any(value in NAME_HEADERS for value in values):
            return values
    return []


def _header_index(headers: list[str], exact: set[str] | tuple[str, ...], *, allow_name: bool = False) -> int | None:
    for index, value in enumerate(headers):
        if any(term in value for term in exact):
            return index
    if allow_name:
        for index, value in enumerate(headers):
            if value in NAME_HEADERS:
                return index
    return None


def _detail_indexes(headers: list[str]) -> dict[str, int | None]:
    aliases = {
        "description": ("description", "summary", "excerpt"),
        "claimed_data_size": ("claimed data size", "data size", "size of data", "data volume"),
        "file_count": ("file count", "number of files", "files", "documents", "record count"),
        "deadline": ("deadline", "publication deadline", "due date", "countdown"),
        "organization_website": ("organization website", "company website", "website", "domain"),
    }
    return {key: _header_index(headers, terms) for key, terms in aliases.items()}


def _text_after_label(value: str, labels: set[str]) -> str | None:
    for label in sorted(labels, key=len, reverse=True):
        match = re.match(r"^\s*" + re.escape(label) + r"\s*[:\-–—]\s*(.+?)\s*$", value, re.I)
        if match:
            return clean_text(match.group(1)) or None
    return None


def _card_claim_details(item: Element) -> dict[str, str]:
    details: dict[str, str] = {}
    normalized_labels = {
        key: {normalize_name(label).replace(" ", "-") for label in labels} | labels
        for key, labels in DETAIL_CLASS_LABELS.items()
    }
    labels_for_text = DETAIL_LABELS
    for child in item.iter():
        classes = _class_tokens(child)
        if child is item:
            continue
        for field, aliases in normalized_labels.items():
            if field in details or not classes.intersection(aliases):
                continue
            value = clean_text(child.text())
            labeled = _text_after_label(value, labels_for_text[field])
            details[field] = labeled or value

    for child in item.iter():
        if child.tag not in {"p", "li", "div", "span", "dd"}:
            continue
        value = clean_text(child.text())
        for field, labels in labels_for_text.items():
            if field not in details:
                extracted = _text_after_label(value, labels)
                if extracted:
                    details[field] = extracted
        data_label = normalize_name(str(child.attrs.get("data-label") or "")).replace(" ", "-")
        for field, aliases in normalized_labels.items():
            if field not in details and data_label in aliases:
                details[field] = _text_after_label(value, labels_for_text[field]) or value

    # Common definition-list layout: <dt>Label</dt><dd>Value</dd>.
    for label_node in item.iter("dt"):
        parent = label_node.parent
        if not parent:
            continue
        try:
            index = parent.children.index(label_node)
        except ValueError:
            continue
        next_node = next(
            (node for node in parent.children[index + 1:] if isinstance(node, Element) and node.tag == "dd"),
            None,
        )
        if not next_node:
            continue
        label = normalize_name(label_node.text())
        for field, labels in labels_for_text.items():
            normalized_labels = {normalize_name(value) for value in labels}
            if field not in details and label in normalized_labels:
                details[field] = clean_text(next_node.text())

    return {
        field: _bounded_text(value, 500 if field == "description" else 240)
        for field, value in details.items()
        if _bounded_text(value, 500 if field == "description" else 240)
    }


def _record_id(row: Element, victim_cell: Element) -> str | None:
    for key in ("data-id", "data-victim-id", "id"):
        value = clean_text(str(row.attrs.get(key) or ""))
        if value and value not in {"", "row"}:
            return value[:160]
    for anchor in victim_cell.iter("a"):
        href = anchor.attrs.get("href")
        if href:
            slug = _slug_from_url(str(href))
            if slug:
                return slug[:160]
    return None


def _records_from_tables(root: Element) -> tuple[bool, list[dict], str | None]:
    for table in root.iter("table"):
        headers = _headers_for_table(table)
        if not headers:
            continue
        victim_index = _header_index(headers, VICTIM_HEADERS, allow_name=True)
        if victim_index is None:
            continue
        has_context = (
            any(any(term in header for term in DATE_HEADERS) for header in headers)
            or any(any(term in header for term in COUNTRY_HEADERS) for header in headers)
            or any(any(term in header for term in SECTOR_HEADERS) for header in headers)
            or any(term in header for header in headers for term in VICTIM_HEADERS)
        )
        if not has_context:
            continue

        date_index = _header_index(headers, DATE_HEADERS)
        country_index = _header_index(headers, COUNTRY_HEADERS)
        sector_index = _header_index(headers, SECTOR_HEADERS)
        detail_indexes = _detail_indexes(headers)
        records: list[dict] = []
        for row in table.iter("tr"):
            if any(cell.tag == "th" for cell in _table_cells(row)):
                continue
            cells = _table_cells(row)
            if victim_index >= len(cells):
                continue
            organization = clean_text(cells[victim_index].text())
            if not organization or len(organization) > 500:
                continue
            claim_details = {
                field: clean_text(cells[index].text())
                for field, index in detail_indexes.items()
                if index is not None and index < len(cells) and clean_text(cells[index].text())
            }
            record = {
                "organization": organization,
                "post_title": organization,
                "record_id": _record_id(row, cells[victim_index]),
                "reported_date": clean_text(cells[date_index].text()) if date_index is not None and date_index < len(cells) else None,
                "country": clean_text(cells[country_index].text()) if country_index is not None and country_index < len(cells) else None,
                "sector": clean_text(cells[sector_index].text()) if sector_index is not None and sector_index < len(cells) else None,
            }
            if claim_details:
                record["claim_details"] = claim_details
            records.append(normalize_listing_record(record))
        return True, records, "html-table"
    return False, [], None


def _class_tokens(element: Element) -> set[str]:
    return set(str(element.attrs.get("class") or "").casefold().split())


def _card_title(element: Element) -> Element | None:
    for tag in ("h1", "h2", "h3", "h4"):
        heading = next(element.iter(tag), None)
        if heading:
            return heading
    for item in element.iter():
        classes = _class_tokens(item)
        if classes.intersection({"title", "victim-name", "company-name", "organization-name"}):
            return item
    return None


def _records_from_cards(root: Element) -> tuple[bool, list[dict], str | None]:
    records: list[dict] = []
    recognized_empty = False
    seen_names: set[str] = set()
    for item in root.iter():
        classes = _class_tokens(item)
        marked = bool(classes.intersection(CARD_CLASS_MARKERS))
        if not marked:
            continue
        heading_count = sum(1 for tag in ("h1", "h2", "h3", "h4") for _ in item.iter(tag))
        if heading_count > 1:
            continue
        title = _card_title(item)
        if title is None:
            if classes.intersection({"victim", "victim-card", "victim-item"}):
                recognized_empty = True
            continue
        post_title = clean_text(title.text())
        normalized = normalize_name(post_title)
        if not post_title or len(post_title) > 500:
            continue
        if normalized in seen_names:
            continue
        seen_names.add(normalized)
        time_node = next(item.iter("time"), None)
        date_value = None
        if time_node:
            date_value = clean_text(str(time_node.attrs.get("datetime") or time_node.text())) or None
        if date_value is None:
            for child in item.iter():
                classes = _class_tokens(child)
                if classes.intersection({"date", "published", "posted", "timestamp"}):
                    date_value = clean_text(child.text()) or None
                    break
        country = None
        sector = None
        for child in item.iter():
            classes = _class_tokens(child)
            if country is None and classes.intersection({"country", "location", "region"}):
                country = clean_text(child.text()) or None
            if sector is None and classes.intersection({"sector", "industry"}):
                sector = clean_text(child.text()) or None
        identity = clean_text(str(item.attrs.get("data-id") or item.attrs.get("id") or "")) or None
        if identity is None:
            for anchor in title.iter("a"):
                href = anchor.attrs.get("href")
                if href:
                    identity = _slug_from_url(str(href))
                    if identity:
                        break
        record = {
            "organization": post_title,
            "post_title": post_title,
            "record_id": identity,
            "reported_date": date_value,
            "country": country,
            "sector": sector,
        }
        claim_details = _card_claim_details(item)
        if claim_details:
            record["claim_details"] = claim_details
        records.append(normalize_listing_record(record))
    return bool(records) or recognized_empty, records, "html-cards" if records or recognized_empty else None


def _same_source_host(candidate: str, base_url: str) -> bool:
    try:
        return (urlparse(candidate).hostname or "").casefold() == (urlparse(base_url).hostname or "").casefold()
    except ValueError:
        return False


def extract_pagination_urls(root: Element, page_url: str) -> list[str]:
    candidates: dict[str, str] = {}
    parsed_base = urlparse(page_url)
    base_path = parsed_base.path.rstrip("/")
    for anchor in root.iter("a"):
        href = anchor.attrs.get("href")
        if not href:
            continue
        absolute = urljoin(page_url, str(href))
        parsed = urlparse(absolute)
        if not _same_source_host(absolute, page_url):
            continue
        if parsed.scheme not in {"http", "https"}:
            continue
        if base_path and parsed.path.rstrip("/") != base_path and not parsed.path.startswith(base_path + "/"):
            continue

        rel = str(anchor.attrs.get("rel") or "").casefold().split()
        pagination_context = any(
            parent.has_class("pagination") or parent.has_class("pager")
            for parent in anchor.ancestors()
        )
        query = parse_qs(parsed.query)
        page_query = any(key.casefold() in {"page", "p", "offset"} for key in query)
        label = clean_text(anchor.text()).casefold()
        is_next = "next" in rel or label in {"next", "›", "»", "→", "older"}
        if not (is_next or pagination_context or page_query):
            continue
        key = urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", parsed.query, ""))
        if key.rstrip("/") != page_url.rstrip("/"):
            candidates[key] = absolute
    return list(candidates.values())


def parse_listing(markup: str, page_url: str) -> dict:
    root = parse_html(markup)
    hostname = (urlparse(page_url).hostname or "").casefold()
    for suffix, parser in sorted(PARSER_REGISTRY.items(), key=lambda item: len(item[0]), reverse=True):
        if hostname == suffix or hostname.endswith("." + suffix):
            adapted = parser(markup, page_url)
            if adapted.get("recognized"):
                pagination = list(adapted.get("pagination_urls") or [])
                pagination.extend(extract_pagination_urls(root, page_url))
                return {
                    **adapted,
                    "records": [normalize_listing_record(item) for item in adapted.get("records", [])],
                    "pagination_urls": list(dict.fromkeys(pagination)),
                }
    recognized, records, parser_name = _records_from_tables(root)
    if not recognized:
        recognized, records, parser_name = _records_from_cards(root)
    return {
        "recognized": recognized,
        "records": [normalize_listing_record(item) for item in records],
        "parser": parser_name,
        "pagination_urls": extract_pagination_urls(root, page_url),
    }


def _canonical_source_url(url: str) -> str:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/") or "/", query, ""))


def source_id_for(url: str, group_id: str = "") -> str:
    identity = str(group_id).casefold() + "\0" + _canonical_source_url(url)
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def sighting_id_for(group_id: str, source_id: str, record: dict) -> str:
    record = normalize_listing_record(record)
    record_id = clean_text(str(record.get("record_id") or ""))
    organization = normalize_name(str(record.get("organization") or ""))
    if record.get("post_type") == "victim" and organization:
        # Mirror URLs for one group often publish the same victim listing.
        # Their URL-specific source IDs belong on the record as provenance,
        # but must not create a second victim identity.
        stable_identity = "victim:" + organization
        material = f"{group_id.casefold()}\0{stable_identity}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]

    fallback = record.get("organization") or record.get("post_title") or ""
    stable_identity = "record:" + record_id.casefold() if record_id else (
        record["post_type"] + ":" + normalize_name(str(fallback))
    )
    material = f"{group_id.casefold()}\0{source_id}\0{stable_identity}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _sighting_source_ids(sighting: dict) -> list[str]:
    """Return all known source IDs, including legacy and import provenance."""
    source_ids: set[str] = set()
    raw_source_ids = sighting.get("source_ids")
    if isinstance(raw_source_ids, (list, tuple, set)):
        source_ids.update(str(value) for value in raw_source_ids if value)
    elif isinstance(raw_source_ids, str) and raw_source_ids:
        source_ids.add(raw_source_ids)
    if sighting.get("source_id"):
        source_ids.add(str(sighting["source_id"]))
    historical_import = sighting.get("historical_import")
    if isinstance(historical_import, dict):
        matched_source_ids = historical_import.get("matched_source_ids") or []
        if isinstance(matched_source_ids, (list, tuple, set)):
            source_ids.update(str(value) for value in matched_source_ids if value)
        elif isinstance(matched_source_ids, str):
            source_ids.add(matched_source_ids)
    return sorted(source_ids)


def _sighting_has_source_id(sighting: dict, source_id: str) -> bool:
    return source_id in _sighting_source_ids(sighting)


def _victim_identity(sighting: dict) -> tuple[str, str] | None:
    if sighting.get("post_type") != "victim":
        return None
    group_id = str(sighting.get("group_id") or "").casefold()
    organization = normalize_name(str(sighting.get("organization") or ""))
    if not group_id or not organization:
        return None
    return group_id, organization


def _merge_victim_sightings(sightings: list[dict]) -> dict:
    """Combine same-group victim copies while preserving metadata and history."""
    ordered = sorted(sightings, key=lambda item: str(item.get("id") or ""))
    merged = dict(ordered[0])
    for item in ordered[1:]:
        for field in (
            "organization", "post_title", "record_id", "reported_date", "country",
            "country_basis", "sector", "source_host", "watchguard_profile_url",
        ):
            if not merged.get(field) and item.get(field):
                merged[field] = item[field]

    first_seen_values = [str(item["first_seen_at"]) for item in ordered if item.get("first_seen_at")]
    last_seen_values = [str(item["last_seen_at"]) for item in ordered if item.get("last_seen_at")]
    if first_seen_values:
        merged["first_seen_at"] = min(first_seen_values, key=_timestamp_sort_key)
    if last_seen_values:
        merged["last_seen_at"] = max(last_seen_values, key=_timestamp_sort_key)

    all_source_ids = sorted({source_id for item in ordered for source_id in _sighting_source_ids(item)})
    merged["source_ids"] = all_source_ids
    if not merged.get("source_id") and all_source_ids:
        merged["source_id"] = all_source_ids[0]
    primary_source_id = merged.get("source_id")
    if not merged.get("source_host") and primary_source_id:
        primary = next(
            (item for item in ordered if item.get("source_id") == primary_source_id and item.get("source_host")),
            None,
        )
        if primary:
            merged["source_host"] = primary["source_host"]

    details: dict = {}
    for item in ordered:
        for field, value in (item.get("claim_details") or {}).items():
            if value and not details.get(field):
                details[field] = value
    if details:
        merged["claim_details"] = details
    else:
        merged.pop("claim_details", None)

    imports = [item.get("historical_import") for item in ordered if isinstance(item.get("historical_import"), dict)]
    if imports:
        provenance: dict = {}
        matched_source_ids: set[str] = set()
        for item in imports:
            for field, value in item.items():
                if field == "matched_source_ids":
                    values = value if isinstance(value, (list, tuple, set)) else [value]
                    matched_source_ids.update(str(source_id) for source_id in values if source_id)
                elif value and not provenance.get(field):
                    provenance[field] = value
        if matched_source_ids:
            provenance["matched_source_ids"] = sorted(matched_source_ids)
        merged["historical_import"] = provenance

    merged["listing_state"] = (
        "listed" if any(item.get("listing_state") == "listed" for item in ordered) else "unknown"
    )
    return merged


def _timestamp_sort_key(value: str) -> tuple[int, object]:
    """Sort ISO timestamps chronologically, falling back to their text value."""
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return 1, parsed.timestamp()
    except (ValueError, OverflowError):
        return 0, value


def migrate_sightings(sightings: list[dict]) -> list[dict]:
    """Add normalized fields and a multivalued source attribution compatibly."""
    migrated: list[dict] = []
    for item in sightings:
        if not isinstance(item, dict):
            continue
        normalized = normalize_listing_record(item)
        migrated_item = {**item, **normalized}
        if migrated_item.get("post_type") == "victim":
            migrated_item["source_ids"] = _sighting_source_ids(migrated_item)
        migrated.append(migrated_item)
    return migrated


def canonicalize_sightings(sightings: list[dict]) -> list[dict]:
    """Keep one victim row per group/organization and preserve other records."""
    victim_groups: dict[tuple[str, str], list[tuple[int, dict]]] = defaultdict(list)
    ordered_sightings: list[tuple[int, dict]] = []
    for index, original in enumerate(sightings):
        if not isinstance(original, dict):
            continue
        # This migration changes victim identity only. Previously classified
        # review and headline rows must keep their current fields and IDs.
        if original.get("post_type") in {"headline", "review"}:
            ordered_sightings.append((index, dict(original)))
            continue
        item = migrate_sightings([original])[0]
        if original.get("post_type") == "victim":
            item["post_type"] = "victim"
            item["source_ids"] = _sighting_source_ids(item)
        identity = _victim_identity(item)
        if identity:
            victim_groups[identity].append((index, item))
        else:
            ordered_sightings.append((index, item))

    for _identity, indexed_items in sorted(victim_groups.items()):
        merged = _merge_victim_sightings([item for _index, item in indexed_items])
        ordered_sightings.append((min(index for index, _item in indexed_items), merged))

    return [
        item
        for _index, item in sorted(
            ordered_sightings,
            key=lambda indexed: (
                str(indexed[1].get("last_seen_at") or ""),
                str(indexed[1].get("group_name") or "").casefold(),
                str(indexed[1].get("organization") or "").casefold(),
                -indexed[0],
            ),
            reverse=True,
        )
    ]


def _matching_history(
    existing_by_id: dict[str, dict], group_id: str, source_id: str, record: dict
) -> dict | None:
    record_id = clean_text(str(record.get("record_id") or ""))
    normalized_org = normalize_name(str(record.get("organization") or ""))
    normalized_title = normalize_name(str(record.get("post_title") or ""))
    if record.get("post_type") == "victim" and normalized_org:
        identity = (group_id.casefold(), normalized_org)
        matches = [
            old for old in existing_by_id.values()
            if _victim_identity(old) == identity
        ]
        return sorted(matches, key=lambda item: str(item.get("id") or ""))[0] if matches else None

    matches: list[dict] = []
    historical_matches: list[dict] = []
    for old in existing_by_id.values():
        if str(old.get("group_id") or "").casefold() != group_id.casefold():
            continue
        old_record_id = clean_text(str(old.get("record_id") or ""))
        same_source = _sighting_has_source_id(old, source_id)
        old_org = normalize_name(str(old.get("organization") or ""))
        if same_source and record_id and old_record_id and record_id.casefold() == old_record_id.casefold():
            return old
        if same_source:
            if record_id and old_record_id:
                continue
            old_title = normalize_name(str(old.get("post_title") or ""))
            if normalized_org and old_org == normalized_org:
                matches.append(old)
            elif not normalized_org and normalized_title and old_title == normalized_title:
                matches.append(old)
        elif isinstance(old.get("historical_import"), dict) and normalized_org and old_org == normalized_org:
            # The one-off archive has no leak-site source ID. Once a later
            # crawl sees the same group/organization, keep extending that
            # stable historical record even if the live source URL differs.
            historical_matches.append(old)
    if matches:
        # Normally there is one row after canonicalization. If old data still
        # contains duplicates, select deterministically so a crawl never
        # creates yet another copy.
        return sorted(matches, key=lambda item: str(item.get("id") or ""))[0]
    if historical_matches:
        return sorted(
            historical_matches,
            key=lambda item: (str(item.get("last_seen_at") or ""), str(item.get("id") or "")),
            reverse=True,
        )[0]
    return None


def _dedupe_records(records: list[dict]) -> list[dict]:
    result: dict[str, dict] = {}
    for record in records:
        record = normalize_listing_record(record)
        name = normalize_name(str(record.get("organization") or ""))
        title = normalize_name(str(record.get("post_title") or ""))
        record_id = clean_text(str(record.get("record_id") or ""))
        if record["post_type"] == "victim" and name:
            key = "victim:" + name
        elif record_id:
            key = "record:" + record_id.casefold()
        else:
            key = f"{record['post_type']}:{name or title}"
        if not key:
            continue
        existing = result.get(key)
        if existing is None:
            result[key] = record
            continue
        for field in ("record_id", "reported_date", "country", "country_basis", "sector"):
            if not existing.get(field) and record.get(field):
                existing[field] = record[field]
        details = existing.setdefault("claim_details", {})
        for field, value in record.get("claim_details", {}).items():
            if not details.get(field) and value:
                details[field] = value
        if not details:
            existing.pop("claim_details", None)
    return list(result.values())


def crawl_site(
    source_url: str,
    *,
    group_id: str = "",
    group_ids: list[str] | None = None,
    source_ids: list[str] | None = None,
    fetcher=fetch_html,
    deadline_seconds: float = FETCH_DEADLINE_SECONDS,
    crawl_deadline: float | None = None,
    max_pages: int = MAX_PAGES_PER_SOURCE,
    request_pacer: Callable[[str], None] | None = None,
) -> dict:
    """Fetch and parse up to the first 25 listing pages for one source."""
    context = (
        f"group_ids={','.join(group_ids or ([group_id] if group_id else [])) or 'unknown'} "
        f"source_ids={','.join(source_ids or []) or 'unknown'}"
    )
    try:
        normalized_source = normalize_url(source_url)
        source_id = source_id_for(normalized_source, group_id)
        source_host = (urlparse(normalized_source).hostname or "").casefold()
    except FetchError as exc:
        return {
            "source_id": hashlib.sha256(
                (str(group_id).casefold() + "\0" + str(source_url)).encode("utf-8")
            ).hexdigest()[:20],
            "source_host": "",
            "status": "unsupported",
            "error": exc.code,
            "error_type": getattr(exc, "cause_type", None),
            "pages_scanned": 0,
            "records": [],
            "parser": None,
            "http_status": getattr(exc, "http_status", None),
            "page_errors": [],
            "page_limit_reached": False,
        }

    page_limit = max(1, int(max_pages))
    pending_pages = [normalized_source]
    queued_keys = {_canonical_source_url(normalized_source)}
    scanned_pages = 0
    page_errors: list[dict] = []
    records: list[dict] = []
    parsers: list[str] = []
    last_http_status: int | None = None
    budget_hit = False

    pages_attempted = 0
    while pending_pages and pages_attempted < page_limit:
        page_number = pages_attempted + 1
        page_url = pending_pages.pop(0)
        if request_pacer:
            request_pacer(source_host)

        remaining = deadline_seconds
        if crawl_deadline is not None:
            remaining = min(remaining, crawl_deadline - time.monotonic())
            if remaining <= 0:
                budget_hit = True
                _emit(
                    f"page_skipped {context} host={source_host or 'unknown'} "
                    f"page={page_number}/{page_limit} status=skipped_budget error=crawl_budget_reached"
                )
                break

        page_started = time.monotonic()
        pages_attempted += 1
        _emit(
            f"page_start {context} host={source_host or 'unknown'} "
            f"page={page_number}/{page_limit}"
        )
        try:
            response = fetcher(page_url, total_timeout=remaining)
        except FetchError as exc:
            is_budget_timeout = (
                crawl_deadline is not None
                and time.monotonic() >= crawl_deadline
                and exc.code == "deadline_exceeded"
            )
            if is_budget_timeout:
                budget_hit = True
            failure = {
                "page": page_number,
                "error": "crawl_budget_reached" if is_budget_timeout else exc.code,
                "error_type": getattr(exc, "cause_type", None),
                "http_status": getattr(exc, "http_status", None),
            }
            page_errors.append(failure)
            _emit(
                f"page_error {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
                f"elapsed_seconds={time.monotonic() - page_started:.2f} "
                f"status={'skipped_budget' if is_budget_timeout else 'offline'} "
                f"http_status={failure['http_status']} error={failure['error']} "
                f"error_type={failure['error_type']}"
            )
            if is_budget_timeout:
                break
            continue
        except Exception as exc:
            failure = {
                "page": page_number,
                "error": "fetch_error",
                "error_type": type(exc).__name__,
                "http_status": None,
            }
            page_errors.append(failure)
            _emit(
                f"page_error {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
                f"elapsed_seconds={time.monotonic() - page_started:.2f} status=offline "
                "http_status=None error=fetch_error "
                f"error_type={type(exc).__name__}"
            )
            continue

        response_host = (urlparse(response.url).hostname or "").casefold()
        last_http_status = getattr(response, "status_code", None)
        scanned_pages += 1
        if not response_host or response_host != source_host:
            failure = {
                "page": page_number,
                "error": "redirect_host_changed" if response_host else "invalid_response_url",
                "error_type": None,
                "http_status": last_http_status,
            }
            page_errors.append(failure)
            _emit(
                f"page_error {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
                f"elapsed_seconds={time.monotonic() - page_started:.2f} status=unsupported "
                f"http_status={last_http_status} error={failure['error']} error_type=None"
            )
            continue

        try:
            parsed = parse_listing(response.body, response.url)
            if not parsed.get("recognized"):
                failure = {
                    "page": page_number,
                    "error": "unsupported_layout",
                    "error_type": None,
                    "http_status": last_http_status,
                }
                page_errors.append(failure)
                _emit(
                    f"page_error {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
                    f"elapsed_seconds={time.monotonic() - page_started:.2f} status=unsupported "
                    f"http_status={last_http_status} error=unsupported_layout error_type=None"
                )
                continue
        except Exception as exc:
            failure = {
                "page": page_number,
                "error": "parser_error",
                "error_type": type(exc).__name__,
                "http_status": last_http_status,
            }
            page_errors.append(failure)
            _emit(
                f"page_error {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
                f"elapsed_seconds={time.monotonic() - page_started:.2f} status=offline "
                f"http_status={last_http_status} error=parser_error error_type={type(exc).__name__}"
            )
            continue

        records.extend(parsed.get("records", []))
        parser_name = parsed.get("parser")
        if parser_name and parser_name not in parsers:
            parsers.append(parser_name)
        for next_url in parsed.get("pagination_urls", []):
            try:
                canonical = _canonical_source_url(str(next_url))
            except FetchError:
                continue
            if _same_source_host(canonical, normalized_source) and canonical not in queued_keys:
                queued_keys.add(canonical)
                pending_pages.append(canonical)
        _emit(
            f"page_complete {context} host={source_host or 'unknown'} page={page_number}/{page_limit} "
            f"elapsed_seconds={time.monotonic() - page_started:.2f} status=ok "
            f"http_status={last_http_status} records={len(parsed.get('records', []))}"
        )

    budget_hit = budget_hit or (
        crawl_deadline is not None and time.monotonic() >= crawl_deadline and bool(pending_pages)
    )
    page_limit_reached = bool(pending_pages) and not budget_hit and pages_attempted >= page_limit
    successful_pages = scanned_pages - sum(
        1 for error in page_errors if error.get("error") in {"unsupported_layout", "parser_error", "redirect_host_changed", "invalid_response_url"}
    )
    unsupported_only = bool(page_errors) and all(
        error.get("error") in {"unsupported_layout", "invalid_response_url", "redirect_host_changed"}
        for error in page_errors
    )

    if budget_hit:
        status = "partial" if successful_pages else "skipped_budget"
        error = "crawl_budget_reached"
    elif page_errors and successful_pages:
        status = "partial"
        error = "page_errors"
    elif page_errors:
        status = "unsupported" if unsupported_only else "offline"
        error = str(page_errors[0].get("error") or "page_error")
    else:
        status = "ok"
        error = None

    error_types = sorted({str(item["error_type"]) for item in page_errors if item.get("error_type")})
    return {
        "source_id": source_id,
        "source_host": source_host,
        "status": status,
        "error": error,
        "error_type": ",".join(error_types) or None,
        "pages_scanned": scanned_pages,
        "records": _dedupe_records(records),
        "parser": ",".join(parsers) or None,
        "http_status": last_http_status,
        "page_errors": page_errors,
        "page_limit_reached": page_limit_reached,
    }

def merge_source_result(
    existing_sightings: list[dict],
    group: dict,
    source: dict,
    result: dict,
    observed_at: str,
) -> list[dict]:
    """Merge a source crawl into append-only history and update listing state."""
    group_id = str(group.get("group_id") or "unknown")
    source_id = str(result["source_id"])
    existing_by_id: dict[str, dict] = {}
    existing_victim_ids_by_identity: dict[tuple[str, str], str] = {}
    for item in existing_sightings:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        if item.get("post_type") in {"headline", "review"}:
            migrated = dict(item)
        else:
            migrated = {**item, **normalize_listing_record(item)}
            if item.get("post_type") == "victim":
                migrated["post_type"] = "victim"
        if migrated.get("post_type") == "victim":
            migrated["source_ids"] = _sighting_source_ids(migrated)
        migrated_id = str(migrated["id"])
        existing_by_id[migrated_id] = migrated
        identity = _victim_identity(migrated)
        if identity:
            existing_victim_ids_by_identity.setdefault(identity, migrated_id)
    current_ids: set[str] = set()
    profile_url = str(group.get("profile_url") or "")

    for record in result.get("records", []):
        record = normalize_listing_record(record)
        if not record.get("post_title"):
            continue
        record_identity = _victim_identity({**record, "group_id": group_id})
        old = existing_by_id.get(sighting_id_for(group_id, source_id, record))
        if old is None and record_identity:
            old_id = existing_victim_ids_by_identity.get(record_identity)
            old = existing_by_id.get(old_id) if old_id else None
        if old is None:
            old = _matching_history(existing_by_id, group_id, source_id, record)
        sighting_id = str(old.get("id")) if old else sighting_id_for(group_id, source_id, record)
        current_ids.add(sighting_id)
        old = old or existing_by_id.get(sighting_id, {})
        details = dict(old.get("claim_details") or {})
        for field, value in record.get("claim_details", {}).items():
            if value:
                details[field] = value
        is_victim = record.get("post_type") == "victim"
        primary_source_id = str(old.get("source_id") or source_id)
        all_source_ids = sorted(set(_sighting_source_ids(old) + [source_id])) if is_victim else []
        first_seen_at = old.get("first_seen_at") or observed_at
        if old.get("first_seen_at") and _timestamp_sort_key(str(old["first_seen_at"])) > _timestamp_sort_key(observed_at):
            first_seen_at = observed_at
        last_seen_at = observed_at
        if old.get("last_seen_at") and _timestamp_sort_key(str(old["last_seen_at"])) > _timestamp_sort_key(observed_at):
            last_seen_at = old["last_seen_at"]
        source_host = old.get("source_host")
        if not source_host and primary_source_id == source_id:
            source_host = result.get("source_host") or ""
        sighting = {
            **old,
            "id": sighting_id,
            "group_id": group_id,
            "group_name": str(group.get("name") or group_id),
            "organization": old.get("organization") or record.get("organization"),
            "post_title": old.get("post_title") or record.get("post_title"),
            "post_type": record.get("post_type", "review"),
            "record_id": old.get("record_id") or record.get("record_id"),
            "reported_date": record.get("reported_date") or old.get("reported_date"),
            "country": record.get("country") or old.get("country"),
            "country_basis": record.get("country_basis") or old.get("country_basis"),
            "sector": record.get("sector") or old.get("sector"),
            "first_seen_at": first_seen_at,
            "last_seen_at": last_seen_at,
            "listing_state": "listed",
            "source_id": primary_source_id if is_victim else source_id,
            "source_host": source_host,
            "watchguard_profile_url": profile_url,
        }
        if is_victim:
            sighting["source_ids"] = all_source_ids
        else:
            sighting.pop("source_ids", None)
        historical_import = old.get("historical_import")
        if isinstance(historical_import, dict):
            raw_matched_ids = historical_import.get("matched_source_ids") or []
            matched_source_ids = list(raw_matched_ids) if isinstance(raw_matched_ids, (list, tuple, set)) else []
            if source_id not in matched_source_ids:
                matched_source_ids.append(source_id)
            sighting["historical_import"] = {
                **historical_import,
                "matched_source_ids": sorted(set(str(item) for item in matched_source_ids)),
            }
        if details:
            sighting["claim_details"] = details
        existing_by_id[sighting_id] = sighting
        if is_victim and record_identity:
            existing_victim_ids_by_identity[record_identity] = sighting_id

    for sighting_id, sighting in existing_by_id.items():
        if str(sighting.get("group_id") or "").casefold() != group_id.casefold() or not _sighting_has_source_id(sighting, source_id):
            continue
        if sighting_id in current_ids:
            continue
        # The first 25 pages cannot establish that a historical listing was
        # removed, so sightings missing from the checked pages remain unknown.
        sighting["listing_state"] = "unknown"

    return sorted(
        existing_by_id.values(),
        key=lambda item: (
            str(item.get("last_seen_at") or ""),
            str(item.get("group_name") or "").casefold(),
            str(item.get("organization") or "").casefold(),
        ),
        reverse=True,
    )


def aggregate_listing_states(
    sightings: list[dict], active_group_ids: set[str], listed_victims: set[tuple[str, str]]
) -> list[dict]:
    """Set merged victim state from all source results in this crawl."""
    aggregated: list[dict] = []
    active_ids = {group_id.casefold() for group_id in active_group_ids}
    for sighting in sightings:
        identity = _victim_identity(sighting)
        if identity is None:
            aggregated.append(sighting)
            continue
        updated = dict(sighting)
        updated["listing_state"] = (
            "listed" if identity[0] in active_ids and identity in listed_victims else "unknown"
        )
        aggregated.append(updated)
    return aggregated


def _group_status(source_results: list[dict], group_status: str = "active") -> str:
    if group_status.casefold() != "active":
        return "skipped_inactive"
    if not source_results:
        return "no_source"
    statuses = {item["status"] for item in source_results}
    if statuses == {"ok"}:
        return "ok"
    if statuses == {"skipped_budget"}:
        return "skipped_budget"
    if statuses == {"skipped_unscoped_catalog"}:
        return "skipped_unscoped_catalog"
    if statuses == {"offline"}:
        return "offline"
    if statuses == {"unsupported"}:
        return "unsupported"
    if statuses == {"skipped_inactive"}:
        return "skipped_inactive"
    return "partial"


def _safe_source_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").casefold()
    except ValueError:
        return ""


def _emit(message: str) -> None:
    print(message, flush=True)


def crawl_catalog(
    catalog: dict,
    previous: dict | None = None,
    *,
    fetcher=fetch_html,
    budget_seconds: float = CRAWL_BUDGET_SECONDS,
    fetch_deadline_seconds: float = FETCH_DEADLINE_SECONDS,
    request_delay_seconds: float = REQUEST_DELAY_SECONDS,
    max_concurrency: int = MAX_CONCURRENCY,
    sleep=time.sleep,
) -> dict:
    """Crawl active sources through at most their first 25 pages, retaining history."""
    groups = catalog.get("groups")
    if not isinstance(groups, list):
        raise ValueError("Group catalog has no groups list")
    if not groups:
        raise ValueError("Group catalog is empty; refresh it before crawling victims")

    previous = previous or {}
    run_at = utc_now()
    crawl_started = time.monotonic()
    deadline = crawl_started + max(0.0, float(budget_seconds))
    sightings = canonicalize_sightings(previous.get("sightings", []))
    source_records: dict[str, dict] = {
        str(item["source_id"]): dict(item)
        for item in previous.get("sources", [])
        if isinstance(item, dict) and item.get("source_id")
    }
    current_source_ids: set[str] = set()
    active_urls: dict[str, dict] = {}
    group_by_id: dict[str, dict] = {}
    group_source_ids: dict[str, list[str]] = {}
    active_group_ids: set[str] = set()
    inactive_group_ids: set[str] = set()
    listed_victims: set[tuple[str, str]] = set()
    active_assignment_count = 0

    for group in groups:
        if not isinstance(group, dict) or not group.get("group_id"):
            continue
        group_id = str(group["group_id"])
        group_by_id[group_id] = group
        group_source_ids[group_id] = []
        if str(group.get("status") or "unknown").casefold() == "active":
            active_group_ids.add(group_id)
        else:
            inactive_group_ids.add(group_id)

        sources = group.get("leak_sites") or []
        for source in sources:
            if not isinstance(source, dict) or not source.get("url"):
                continue
            raw_url = str(source["url"])
            try:
                canonical_url = _canonical_source_url(raw_url)
                source_id = source_id_for(canonical_url, group_id)
                host = _safe_source_host(canonical_url)
                url_error = None
            except FetchError as exc:
                canonical_url = ""
                source_id = hashlib.sha256((group_id.casefold() + "\0" + raw_url).encode("utf-8")).hexdigest()[:20]
                host = ""
                url_error = exc.code

            if source_id in group_source_ids[group_id]:
                continue
            current_source_ids.add(source_id)
            group_source_ids[group_id].append(source_id)
            if group_id not in active_group_ids:
                prior = source_records.get(source_id, {})
                record = {
                    **prior,
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": prior.get("source_host") or host,
                    "status": "skipped_inactive",
                    "status_updated_at": run_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "posts_review": 0,
                    "page_errors": [],
                    "page_limit_reached": False,
                    "error": None,
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                source_records[source_id] = record
                for sighting in sightings:
                    if _sighting_has_source_id(sighting, source_id):
                        sighting["listing_state"] = "unknown"
                continue

            if group.get("leak_sites_scope") != "extortion_links":
                prior = source_records.get(source_id, {})
                source_records[source_id] = {
                    **prior,
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": prior.get("source_host") or host,
                    "status": "skipped_unscoped_catalog",
                    "status_updated_at": run_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "posts_review": 0,
                    "page_errors": [],
                    "page_limit_reached": False,
                    "error": "missing_extortion_scope",
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                for sighting in sightings:
                    if _sighting_has_source_id(sighting, source_id):
                        sighting["listing_state"] = "unknown"
                _emit(
                    f"source_skipped group_id={group_id} source_id={source_id} host={host or 'unknown'} "
                    "elapsed_seconds=0.00 status=skipped_unscoped_catalog error=missing_extortion_scope"
                )
                continue

            active_assignment_count += 1
            if url_error:
                result = {
                    "source_id": source_id,
                    "source_host": host,
                    "status": "unsupported",
                    "error": url_error,
                    "error_type": None,
                    "http_status": None,
                    "pages_scanned": 0,
                    "records": [],
                    "parser": None,
                    "page_errors": [],
                    "page_limit_reached": False,
                }
                completed_at = utc_now()
                sightings = merge_source_result(sightings, group, source, result, completed_at)
                source_records[source_id] = {
                    "source_id": source_id,
                    "group_id": group_id,
                    "group_name": str(group.get("name") or group_id),
                    "source_host": host,
                    "status": result["status"],
                    "checked_at": completed_at,
                    "status_updated_at": completed_at,
                    "pages_scanned": 0,
                    "victims_found": 0,
                    "posts_review": 0,
                    "parser": None,
                    "error": url_error,
                    "error_type": None,
                    "http_status": None,
                    "page_errors": [],
                    "page_limit_reached": False,
                    "watchguard_profile_url": str(group.get("profile_url") or ""),
                }
                _emit(
                    f"source_error group_id={group_id} source_id={source_id} host=unknown "
                    f"elapsed_seconds=0.00 status=unsupported error={url_error} progress=local_validation"
                )
                continue

            entry = active_urls.setdefault(canonical_url, {
                "url": canonical_url,
                "host": host,
                "associations": [],
            })
            if not any(item["source_id"] == source_id for item in entry["associations"]):
                entry["associations"].append({"group": group, "source": source, "source_id": source_id})

    pending = [active_urls[key] for key in sorted(active_urls)]
    unique_url_count = len(pending)
    worker_count = max(1, min(3, int(max_concurrency)))
    _emit(
        "crawl_started "
        f"active_groups={len(active_group_ids)} non_active_groups={len(inactive_group_ids)} "
        f"eligible_group_sources={active_assignment_count} unique_urls={unique_url_count} "
        f"workers={worker_count} fetch_deadline_seconds={fetch_deadline_seconds:g} "
        f"pages_per_source={MAX_PAGES_PER_SOURCE} "
        f"crawl_budget_seconds={max(0.0, float(budget_seconds)):g}"
    )

    completed_unique = 0
    crawl_pages_scanned = 0
    last_host_start: dict[str, float] = {}
    next_host_request: dict[str, float] = {}
    pacing_lock = Lock()
    in_flight: dict[Future, tuple[dict, float]] = {}
    budget_skipped: list[dict] = []

    def pace_request(host: str) -> None:
        with pacing_lock:
            now = time.monotonic()
            start_at = max(now, next_host_request.get(host, now))
            next_host_request[host] = start_at + max(0.0, request_delay_seconds)
        delay = start_at - now
        if delay > 0:
            sleep(delay)

    def store_completed(entry: dict, result: dict, started_at: float) -> None:
        nonlocal sightings, completed_unique, crawl_pages_scanned
        completed_unique += 1
        crawl_pages_scanned += int(result.get("pages_scanned", 0) or 0)
        elapsed = time.monotonic() - started_at
        completed_at = utc_now()
        associations = entry["associations"]
        group_ids = ",".join(str(item["group"]["group_id"]) for item in associations)
        association_source_ids = ",".join(item["source_id"] for item in associations)
        for association in associations:
            group = association["group"]
            source = association["source"]
            source_id = association["source_id"]
            group_id = str(group["group_id"])
            for record in result.get("records", []):
                normalized = normalize_listing_record(record)
                if normalized.get("post_type") != "victim":
                    continue
                identity = _victim_identity({**normalized, "group_id": group_id})
                if identity:
                    listed_victims.add(identity)
            attributed_result = {**result, "source_id": source_id}
            sightings = merge_source_result(sightings, group, source, attributed_result, completed_at)
            source_records[source_id] = {
                "source_id": source_id,
                "group_id": str(group["group_id"]),
                "group_name": str(group.get("name") or group["group_id"]),
                "source_host": result.get("source_host") or entry["host"],
                "status": result["status"],
                "checked_at": completed_at,
                "status_updated_at": completed_at,
                "pages_scanned": result.get("pages_scanned", 0),
                "victims_found": sum(item.get("post_type") == "victim" for item in result.get("records", [])),
                "posts_review": sum(item.get("post_type") != "victim" for item in result.get("records", [])),
                "parser": result.get("parser"),
                "error": result.get("error"),
                "error_type": result.get("error_type"),
                "http_status": result.get("http_status"),
                "page_errors": result.get("page_errors", []),
                "page_limit_reached": result.get("page_limit_reached", False),
                "watchguard_profile_url": str(group.get("profile_url") or ""),
            }
        detail = (
            f"http_status={result.get('http_status')}"
            if result.get("http_status") is not None
            else f"error={result.get('error') or 'unknown'}"
        )
        if result.get("error_type"):
            detail += f" error_type={result['error_type']}"
        _emit(
            f"source_complete progress={completed_unique}/{unique_url_count} "
            f"group_ids={group_ids} source_ids={association_source_ids} host={entry['host'] or 'unknown'} "
            f"elapsed_seconds={elapsed:.2f} status={result['status']} {detail} "
            f"pages={result.get('pages_scanned', 0)} records={len(result.get('records', []))} "
            f"page_limit_reached={str(result.get('page_limit_reached', False)).lower()} "
            f"victims={sum(item.get('post_type') == 'victim' for item in result.get('records', []))} "
            f"review={sum(item.get('post_type') != 'victim' for item in result.get('records', []))}"
        )

    with ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="victim-crawl") as executor:
        while pending or in_flight:
            now = time.monotonic()
            budget_remaining = deadline - now
            if budget_remaining <= 0 and pending:
                budget_skipped.extend(pending)
                pending.clear()
            while pending and len(in_flight) < worker_count and budget_remaining > 0:
                if time.monotonic() >= deadline:
                    budget_remaining = 0
                    break
                ready_index = None
                wait_for_host = None
                for index, item in enumerate(pending):
                    available_at = last_host_start.get(item["host"], float("-inf")) + max(0.0, request_delay_seconds)
                    delay_left = available_at - now
                    if delay_left <= 0:
                        ready_index = index
                        break
                    wait_for_host = delay_left if wait_for_host is None else min(wait_for_host, delay_left)
                if ready_index is None:
                    break
                entry = pending.pop(ready_index)
                started_at = time.monotonic()
                last_host_start[entry["host"]] = started_at
                group_ids = ",".join(str(item["group"]["group_id"]) for item in entry["associations"])
                source_ids = ",".join(item["source_id"] for item in entry["associations"])
                _emit(
                    f"source_start progress={completed_unique + len(in_flight) + 1}/{unique_url_count} "
                    f"group_ids={group_ids} source_ids={source_ids} host={entry['host'] or 'unknown'}"
                )
                future = executor.submit(
                    crawl_site,
                    entry["url"],
                    group_ids=[str(item["group"]["group_id"]) for item in entry["associations"]],
                    source_ids=[str(item["source_id"]) for item in entry["associations"]],
                    fetcher=fetcher,
                    deadline_seconds=fetch_deadline_seconds,
                    crawl_deadline=deadline,
                    max_pages=MAX_PAGES_PER_SOURCE,
                    request_pacer=pace_request,
                )
                in_flight[future] = (entry, started_at)
                now = time.monotonic()
                budget_remaining = deadline - now

            if not pending and not in_flight:
                break

            timeout_candidates = []
            budget_remaining = deadline - time.monotonic()
            if pending and budget_remaining > 0:
                timeout_candidates.append(budget_remaining)
                for item in pending:
                    available_at = last_host_start.get(item["host"], float("-inf")) + max(0.0, request_delay_seconds)
                    if available_at > time.monotonic():
                        timeout_candidates.append(available_at - time.monotonic())
            wait_timeout = min(timeout_candidates) if timeout_candidates else None
            if in_flight:
                done, _not_done = wait(tuple(in_flight), timeout=wait_timeout, return_when=FIRST_COMPLETED)
                for future in done:
                    entry, started_at = in_flight.pop(future)
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {
                            "status": "offline", "error": "worker_error",
                            "error_type": type(exc).__name__, "http_status": None,
                            "pages_scanned": 0, "records": [], "parser": None,
                            "source_host": entry["host"],
                            "page_errors": [], "page_limit_reached": False,
                        }
                    store_completed(entry, result, started_at)
            elif pending:
                delay = wait_timeout if wait_timeout is not None else 0
                if delay > 0:
                    sleep(delay)

    budget_exhausted = bool(budget_skipped) or any(
        source_id in current_source_ids and item.get("error") == "crawl_budget_reached"
        for source_id, item in source_records.items()
    )
    for entry in budget_skipped:
        for association in entry["associations"]:
            group = association["group"]
            source = association["source"]
            source_id = association["source_id"]
            prior = source_records.get(source_id, {})
            source_records[source_id] = {
                **prior,
                "source_id": source_id,
                "group_id": str(group["group_id"]),
                "group_name": str(group.get("name") or group["group_id"]),
                "source_host": prior.get("source_host") or entry["host"],
                "status": "skipped_budget",
                "status_updated_at": utc_now(),
                "pages_scanned": 0,
                "victims_found": 0,
                "posts_review": 0,
                "error": None,
                "error_type": None,
                "http_status": None,
                "page_errors": [],
                "page_limit_reached": False,
                "watchguard_profile_url": str(group.get("profile_url") or ""),
            }
            for sighting in sightings:
                if _sighting_has_source_id(sighting, source_id):
                    sighting["listing_state"] = "unknown"
    if budget_exhausted:
        interrupted_sources = sum(
            source_id in current_source_ids and item.get("error") == "crawl_budget_reached"
            for source_id, item in source_records.items()
        )
        _emit(
            f"crawl_budget_exhausted completed_unique={completed_unique} "
            f"unique_urls={unique_url_count} skipped_unique={len(budget_skipped)} "
            f"interrupted_sources={interrupted_sources} unique_pages_scanned={crawl_pages_scanned} "
            f"budget_seconds={max(0.0, float(budget_seconds)):g}"
        )

    for source_id, source_record in list(source_records.items()):
        if source_id in current_source_ids:
            continue
        source_record["status"] = "not_in_catalog"
        source_record["status_updated_at"] = utc_now()
        source_record["pages_scanned"] = 0
        source_record["victims_found"] = 0
        source_record["posts_review"] = 0
        source_record["page_errors"] = []
        source_record["page_limit_reached"] = False
        source_records[source_id] = source_record
        for sighting in sightings:
            if _sighting_has_source_id(sighting, source_id):
                sighting["listing_state"] = "unknown"

    sightings = canonicalize_sightings(sightings)
    sightings = aggregate_listing_states(sightings, active_group_ids, listed_victims)

    group_summaries: list[dict] = []
    for group_id, group in group_by_id.items():
        result_records = [source_records[item] for item in group_source_ids[group_id] if item in source_records]
        eligibility = "active" if group_id in active_group_ids else "non_active"
        group_summaries.append({
            "group_id": group_id,
            "name": str(group.get("name") or group_id),
            "watchguard_profile_url": str(group.get("profile_url") or ""),
            "eligibility": eligibility,
            "status": _group_status(result_records, str(group.get("status") or "unknown")),
            "source_issue": group.get("leak_sites_status") or (
                "catalog_missing_extortion_scope"
                if group.get("leak_sites") and group.get("leak_sites_scope") != "extortion_links"
                else None
            ),
            "checked_at": run_at,
            "sources_total": len(result_records),
            "sources_ok": sum(item.get("status") == "ok" for item in result_records),
            "sources_skipped": sum(str(item.get("status", "")).startswith("skipped_") for item in result_records),
        })

    elapsed = time.monotonic() - crawl_started
    final_counts: dict[str, int] = {}
    for source_id in current_source_ids:
        status = source_records.get(source_id, {}).get("status", "unknown")
        final_counts[status] = final_counts.get(status, 0) + 1
    counts_text = ",".join(f"{key}={value}" for key, value in sorted(final_counts.items())) or "none"
    _emit(
        f"crawl_finished elapsed_seconds={elapsed:.2f} completed_unique={completed_unique}/{unique_url_count} "
        f"budget_exhausted={str(budget_exhausted).lower()} source_statuses={counts_text} "
        f"sightings={len(sightings)}"
    )

    return {
        "schema_version": 2,
        "updated_at": utc_now(),
        "crawl_started_at": run_at,
        "crawl_elapsed_seconds": round(elapsed, 2),
        "crawl_budget_seconds": max(0, int(budget_seconds)),
        "crawl_partial": budget_exhausted,
        "crawl_pages_scanned": crawl_pages_scanned,
        "source_catalog_updated_at": catalog.get("updated_at"),
        "groups": sorted(group_summaries, key=lambda item: item["name"].casefold()),
        "sources": sorted(source_records.values(), key=lambda item: (item["group_name"].casefold(), item["source_host"])),
        "sightings": sorted(
            sightings,
            key=lambda item: (
                str(item.get("last_seen_at") or ""),
                str(item.get("group_name") or "").casefold(),
                str(item.get("organization") or "").casefold(),
            ),
            reverse=True,
        ),
    }

def _catalog_needs_tor(catalog: dict) -> bool:
    for group in catalog.get("groups", []):
        if (
            not isinstance(group, dict)
            or str(group.get("status") or "unknown").casefold() != "active"
            or group.get("leak_sites_scope") != "extortion_links"
        ):
            continue
        for source in group.get("leak_sites", []) if isinstance(group, dict) else []:
            if isinstance(source, dict) and ".onion" in str(source.get("url") or "").casefold():
                return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--groups", type=Path, default=GROUPS_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument(
        "--needs-tor",
        action="store_true",
        help="exit 0 when the catalog contains onion sources, otherwise exit 1",
    )
    args = parser.parse_args()

    try:
        catalog = read_json(args.groups, {"groups": []})
        if args.needs_tor:
            return 0 if _catalog_needs_tor(catalog) else 1
        previous = read_json(args.output, {"sightings": [], "sources": []})
        result = crawl_catalog(catalog, previous)
        write_json_atomic(args.output, result)
    except (FetchError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"Victim scrape failed: {exc}", file=sys.stderr)
        return 1

    status_counts: dict[str, int] = {}
    for source in result["sources"]:
        status_counts[source["status"]] = status_counts.get(source["status"], 0) + 1
    summary = ", ".join(f"{key}={value}" for key, value in sorted(status_counts.items())) or "no sources"
    if result.get("crawl_partial"):
        print(
            "::warning::The 90-minute crawl budget was reached; completed sightings were saved "
            "and remaining sources were marked skipped_budget.",
            flush=True,
        )
    print(
        f"Saved {len(result['sightings'])} historical sightings from "
        f"{len(result['sources'])} sources ({summary}) to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
