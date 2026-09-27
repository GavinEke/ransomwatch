from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import scrape_victims
from http_client import FetchError


GROUP = {
    "group_id": "krybit",
    "name": "KryBit",
    "status": "active",
    "leak_sites_scope": "extortion_links",
    "profile_url": "https://profile.example.invalid/krybit",
}


def live_sighting(group_id: str, source_id: str, organization: str, *, listing_state="listed", **extra) -> dict:
    return {
        "id": f"{source_id}-{scrape_victims.normalize_name(organization)}",
        "group_id": group_id,
        "group_name": group_id.title(),
        "source_id": source_id,
        "source_host": f"{source_id}.example.invalid",
        "organization": organization,
        "post_title": organization,
        "post_type": "victim",
        "first_seen_at": "2026-09-01T00:00:00Z",
        "last_seen_at": "2026-09-02T00:00:00Z",
        "listing_state": listing_state,
        **extra,
    }


class VictimSourceMergeTests(unittest.TestCase):
    def test_migration_collapses_same_group_only_and_preserves_history(self) -> None:
        duplicate_a = live_sighting(
            "krybit", "source-a", "Acme, Inc.",
            first_seen_at="2026-09-01T00:00:00.100Z",
            last_seen_at="2026-09-02T00:00:00Z",
            claim_details={"description": "Claim detail"},
            historical_import={"source": "posts.txt", "matched_source_ids": ["source-c"]},
        )
        duplicate_a["id"] = "z-id"
        duplicate_b = live_sighting(
            "KRYBIT", "source-b", "Acme Inc.", listing_state="unknown",
            first_seen_at="2026-09-01T00:00:00Z",
            last_seen_at="2026-09-02T00:00:00.250Z",
            historical_import={"source": "archive", "archive_observations": 2},
        )
        duplicate_b["id"] = "a-id"
        other_group = live_sighting("other-group", "source-d", "Acme Inc.")
        headline = {
            "id": "headline-id", "group_id": "krybit", "source_id": "source-a",
            "post_title": "Important Announcement", "post_type": "headline",
            "organization": None, "listing_state": "unknown",
        }
        review = {
            "id": "review-id", "group_id": "krybit", "source_id": "source-a",
            "post_title": "Ambiguous post", "post_type": "review",
            "organization": "Ambiguous post", "listing_state": "unknown",
        }

        result = scrape_victims.canonicalize_sightings(
            [duplicate_a, duplicate_b, other_group, headline, review]
        )

        merged = [item for item in result if item.get("group_id", "").casefold() == "krybit" and item.get("post_type") == "victim"]
        self.assertEqual(len(merged), 1)
        victim = merged[0]
        self.assertEqual(victim["id"], "a-id")
        self.assertEqual(victim["source_id"], "source-b")
        self.assertEqual(victim["source_ids"], ["source-a", "source-b", "source-c"])
        self.assertEqual(victim["first_seen_at"], "2026-09-01T00:00:00Z")
        self.assertEqual(victim["last_seen_at"], "2026-09-02T00:00:00.250Z")
        self.assertEqual(victim["listing_state"], "listed")
        self.assertEqual(victim["claim_details"], {"description": "Claim detail"})
        self.assertEqual(victim["historical_import"]["source"], "archive")
        self.assertEqual(victim["historical_import"]["matched_source_ids"], ["source-c"])
        self.assertEqual(sum(item.get("post_type") == "victim" for item in result), 2)
        self.assertEqual({item["id"] for item in result if item.get("post_type") in {"headline", "review"}}, {"headline-id", "review-id"})

    def test_repeated_mirror_crawls_union_sources_and_keep_stable_identity(self) -> None:
        source_a = {"url": "https://one.example.invalid/"}
        source_b = {"url": "https://two.example.invalid/"}
        source_a_id = scrape_victims.source_id_for(source_a["url"], GROUP["group_id"])
        source_b_id = scrape_victims.source_id_for(source_b["url"], GROUP["group_id"])

        first = scrape_victims.merge_source_result(
            [], GROUP, source_a,
            {"source_id": source_a_id, "source_host": "one.example.invalid", "status": "ok", "records": [
                {"organization": "Acme Corp", "post_title": "Acme Corp", "claim_details": {"file_count": "40 files"}},
            ]},
            "2026-09-20T00:00:00Z",
        )
        initial_id = first[0]["id"]
        second = scrape_victims.merge_source_result(
            first, GROUP, source_b,
            {"source_id": source_b_id, "source_host": "two.example.invalid", "status": "ok", "records": [
                {"organization": "ACME CORP", "post_title": "Acme Corp [LEAKED]", "record_id": "mirror-record"},
            ]},
            "2026-09-21T00:00:00Z",
        )

        self.assertEqual(len(second), 1)
        victim = second[0]
        self.assertEqual(victim["id"], initial_id)
        self.assertEqual(victim["source_id"], source_a_id)
        self.assertEqual(victim["source_host"], "one.example.invalid")
        self.assertEqual(victim["source_ids"], sorted([source_a_id, source_b_id]))
        self.assertEqual(victim["claim_details"], {"file_count": "40 files"})
        self.assertEqual(victim["last_seen_at"], "2026-09-21T00:00:00Z")

        other_group = dict(GROUP, group_id="other-group", name="Other Group")
        third = scrape_victims.merge_source_result(
            second, other_group, source_a,
            {"source_id": scrape_victims.source_id_for(source_a["url"], "other-group"), "source_host": "one.example.invalid", "status": "ok", "records": [
                {"organization": "Acme Corp", "post_title": "Acme Corp"},
            ]},
            "2026-09-22T00:00:00Z",
        )
        self.assertEqual(sum(item.get("organization", "").casefold() == "acme corp" for item in third), 2)
        different_organization = scrape_victims.merge_source_result(
            third, GROUP, source_b,
            {"source_id": source_b_id, "source_host": "two.example.invalid", "status": "ok", "records": [
                {"organization": "Different Corp", "post_title": "Different Corp", "record_id": "mirror-record"},
            ]},
            "2026-09-23T00:00:00Z",
        )
        self.assertEqual(len(different_organization), 3)

        same_page_duplicates = scrape_victims._dedupe_records([
            {"organization": "Acme Corp", "record_id": "post-from-mirror-one"},
            {"organization": "ACME CORP", "record_id": "post-from-mirror-two", "claim_details": {"file_count": "40 files"}},
        ])
        self.assertEqual(len(same_page_duplicates), 1)
        self.assertEqual(same_page_duplicates[0]["claim_details"]["file_count"], "40 files")

    def test_catalog_aggregate_keeps_positive_sighting_when_another_source_is_offline(self) -> None:
        catalog = {"groups": [dict(GROUP, leak_sites=[
            {"url": "https://one.example.invalid/"},
            {"url": "https://two.example.invalid/"},
        ])]}
        markup = "<table><tr><th>Victim</th></tr><tr><td>Acme Corp</td></tr></table>"

        def fake_fetch(url: str, **_kwargs) -> SimpleNamespace:
            if "two.example.invalid" in url:
                raise FetchError("network_error", cause_type="ConnectionError")
            return SimpleNamespace(url=url, body=markup, status_code=200)

        result = scrape_victims.crawl_catalog(
            catalog,
            {"sightings": [], "sources": []},
            fetcher=fake_fetch,
            budget_seconds=5,
            request_delay_seconds=0,
            max_concurrency=2,
        )

        self.assertEqual(len(result["sightings"]), 1)
        self.assertEqual(result["sightings"][0]["listing_state"], "listed")
        self.assertEqual(len(result["sightings"][0]["source_ids"]), 1)
        statuses = {item["status"] for item in result["sources"]}
        self.assertEqual(statuses, {"ok", "offline"})

    def test_unavailable_sources_leave_unseen_history_unknown(self) -> None:
        first = live_sighting("krybit", "source-a", "Acme Corp")
        first["id"] = "stable-acme-id"
        first["source_ids"] = ["source-a", "source-b"]
        result = scrape_victims.aggregate_listing_states([first], {"krybit"}, set())
        self.assertEqual(result[0]["id"], "stable-acme-id")
        self.assertEqual(result[0]["listing_state"], "unknown")

    def test_malformed_victim_rows_still_get_an_empty_source_ids_array(self) -> None:
        result = scrape_victims.canonicalize_sightings([{
            "id": "legacy-placeholder",
            "group_id": "krybit",
            "source_id": None,
            "organization": None,
            "post_title": "**—",
            "post_type": "victim",
        }])
        self.assertEqual(result[0]["source_ids"], [])


if __name__ == "__main__":
    unittest.main()
