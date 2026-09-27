from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import import_historical_posts as historical
import scrape_victims


def load_catalog() -> dict:
    return json.loads((ROOT / "site" / "data" / "groups.json").read_text(encoding="utf-8"))


class HistoricalImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()
        cls.exact, cls.aliases = historical.build_group_matcher(cls.catalog["groups"])

    def test_approved_aliases_match_existing_groups_and_unknown_labels_do_not(self) -> None:
        for source_label, target_id in historical.APPROVED_GROUP_ALIASES.items():
            with self.subTest(source_label=source_label):
                self.assertEqual(
                    historical.match_group(source_label, self.exact, self.aliases)["group_id"],
                    target_id,
                )
        self.assertEqual(
            historical.match_group("hunters", self.exact, self.aliases)["name"],
            "Hunters International",
        )
        self.assertEqual(
            historical.match_group("lockbit3_cronos", self.exact, self.aliases)["name"],
            "LockBit 3.0",
        )
        self.assertIsNone(historical.match_group("lockbit2", self.exact, self.aliases))
        self.assertIsNone(historical.match_group("unapproved-near-match", self.exact, self.aliases))

    def test_titles_extract_clear_organizations_and_reject_headlines(self) -> None:
        self.assertEqual(
            historical.classify_historical_title("Leaks Company Birch Communications inc.")["organization"],
            "Birch Communications inc.",
        )
        self.assertEqual(
            historical.classify_historical_title("Security breach of CAPCOM network")["organization"],
            "CAPCOM",
        )
        self.assertEqual(
            historical.classify_historical_title("🇹🇼 台灣東洋國際儀表股份有限公司")["organization"],
            "台灣東洋國際儀表股份有限公司",
        )
        self.assertEqual(
            historical.classify_historical_title("🇹🇼 台灣東洋國際儀表股份有限公司")["country"],
            "Taiwan",
        )
        for title in ("Brunner Announce – Hello World !", "View All", "**—", "Important Announcement"):
            with self.subTest(title=title):
                self.assertIsNone(historical.classify_historical_title(title))

    def test_import_collapses_duplicates_with_stable_historical_dates_and_id(self) -> None:
        posts = [
            {"group_name": "hunters", "post_title": "Leaks Company Acme Holdings", "discovered": "2023-06-10T10:00:00Z"},
            {"group_name": "hunters", "post_title": "Acme Holdings Data Breach", "discovered": "2024-07-12T11:30:00Z"},
            {"group_name": "lockbit2", "post_title": "CAPCOM", "discovered": "2022-01-01T00:00:00Z"},
            {"group_name": "hunters", "post_title": "View All", "discovered": "2022-01-01T00:00:00Z"},
        ]
        existing = {"sources": [{"source_id": "untouched"}], "sightings": []}
        first, summary = historical.build_import(
            posts, self.catalog, existing, imported_at="2026-09-27T00:00:00Z"
        )
        second, _ = historical.build_import(
            posts, self.catalog, existing, imported_at="2026-09-28T00:00:00Z"
        )

        self.assertEqual(summary["archive_rows"], 4)
        self.assertEqual(summary["matched_archive_rows"], 2)
        self.assertEqual(summary["unmatched_group_rows"], 1)
        self.assertEqual(summary["excluded_headline_or_ambiguous"], 1)
        self.assertEqual(summary["new_sightings"], 1)
        self.assertEqual(first["sources"], existing["sources"])
        self.assertEqual(len(first["sightings"]), 1)
        sighting = first["sightings"][0]
        self.assertEqual(sighting["group_id"], "hunters-international")
        self.assertEqual(sighting["group_name"], "Hunters International")
        self.assertEqual(sighting["organization"], "Acme Holdings")
        self.assertEqual(sighting["first_seen_at"], "2023-06-10T10:00:00Z")
        self.assertEqual(sighting["last_seen_at"], "2024-07-12T11:30:00Z")
        self.assertEqual(sighting["listing_state"], "unknown")
        self.assertIsNone(sighting["source_id"])
        self.assertEqual(sighting["post_title"], "Acme Holdings Data Breach")
        self.assertEqual(sighting["historical_import"]["archive_post_title"], "Acme Holdings Data Breach")
        self.assertEqual(sighting["id"], second["sightings"][0]["id"])

    def test_overlap_preserves_live_id_attribution_state_and_details(self) -> None:
        posts = [{
            "group_name": "hunters",
            "post_title": "Leaks Company Acme Holdings",
            "discovered": "2022-04-03T00:00:00Z",
        }]
        live = {
            "id": "existing-live-id",
            "group_id": "hunters-international",
            "group_name": "Hunters International",
            "source_id": "live-source-id",
            "source_host": "live.example",
            "organization": "Acme Holdings",
            "post_title": "Acme Holdings",
            "post_type": "victim",
            "first_seen_at": "2023-01-01T00:00:00Z",
            "last_seen_at": "2026-09-25T00:00:00Z",
            "listing_state": "listed",
            "reported_date": "2026-09-20",
            "country": "Canada",
            "sector": "Manufacturing",
            "claim_details": {"file_count": "40 files"},
        }
        imported, summary = historical.build_import(
            posts,
            self.catalog,
            {"sources": [{"source_id": "live-source-id"}], "sightings": [live]},
            imported_at="2026-09-27T00:00:00Z",
        )

        self.assertEqual(summary["new_sightings"], 0)
        self.assertEqual(len(imported["sightings"]), 1)
        merged = imported["sightings"][0]
        self.assertEqual(merged["id"], "existing-live-id")
        self.assertEqual(merged["source_id"], "live-source-id")
        self.assertEqual(merged["source_ids"], ["live-source-id"])
        self.assertEqual(merged["source_host"], "live.example")
        self.assertEqual(merged["listing_state"], "listed")
        self.assertEqual(merged["first_seen_at"], "2022-04-03T00:00:00Z")
        self.assertEqual(merged["last_seen_at"], "2026-09-25T00:00:00Z")
        self.assertEqual(merged["reported_date"], "2026-09-20")
        self.assertEqual(merged["claim_details"], {"file_count": "40 files"})
        self.assertEqual(merged["historical_import"]["earliest_discovered"], "2022-04-03T00:00:00Z")

    def test_later_live_crawl_merges_into_historical_record_without_dropping_provenance(self) -> None:
        old = {
            "id": "archive-stable-id",
            "group_id": "hunters-international",
            "group_name": "Hunters International",
            "source_id": None,
            "source_host": None,
            "organization": "Acme Holdings",
            "post_title": "Leaks Company Acme Holdings",
            "post_type": "victim",
            "first_seen_at": "2023-06-10T10:00:00Z",
            "last_seen_at": "2024-07-12T11:30:00Z",
            "listing_state": "unknown",
            "historical_import": {
                "source": "posts.txt",
                "archive_post_title": "Acme Holdings Data Breach",
                "latest_discovered": "2024-07-12T11:30:00Z",
            },
        }
        source_url = "https://leak.example.invalid/"
        source_id = scrape_victims.source_id_for(source_url, "hunters-international")
        result = {
            "source_id": source_id,
            "source_host": "leak.example.invalid",
            "status": "ok",
            "records": [{"organization": "Acme Holdings", "post_title": "Acme Holdings"}],
        }
        merged = scrape_victims.merge_source_result(
            [old],
            {"group_id": "hunters-international", "name": "Hunters International", "profile_url": "https://profile.invalid/hunters"},
            {"url": source_url},
            result,
            "2026-09-27T00:00:00Z",
        )

        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["id"], "archive-stable-id")
        self.assertEqual(merged[0]["source_id"], source_id)
        self.assertEqual(merged[0]["listing_state"], "listed")
        self.assertEqual(merged[0]["first_seen_at"], "2023-06-10T10:00:00Z")
        self.assertEqual(merged[0]["last_seen_at"], "2026-09-27T00:00:00Z")
        self.assertEqual(merged[0]["historical_import"]["archive_post_title"], "Acme Holdings Data Breach")
        self.assertEqual(merged[0]["historical_import"]["matched_source_ids"], [source_id])

    def test_unmatched_history_is_not_added_or_modified_as_crawl_state(self) -> None:
        old = {
            "id": "unmatched-history",
            "group_id": "hunters-international",
            "source_id": None,
            "organization": "Old Corporation",
            "post_title": "Old Corporation",
            "post_type": "victim",
            "listing_state": "unknown",
            "historical_import": {"source": "posts.txt"},
        }
        source_url = "https://leak.example.invalid/"
        result = {
            "source_id": scrape_victims.source_id_for(source_url, "hunters-international"),
            "source_host": "leak.example.invalid",
            "status": "ok",
            "records": [{"organization": "Acme Holdings", "post_title": "Acme Holdings"}],
        }
        merged = scrape_victims.merge_source_result(
            [old],
            {"group_id": "hunters-international", "name": "Hunters International", "profile_url": ""},
            {"url": source_url},
            result,
            "2026-09-27T00:00:00Z",
        )
        history = next(item for item in merged if item["id"] == "unmatched-history")
        self.assertEqual(history["listing_state"], "unknown")


if __name__ == "__main__":
    unittest.main()
