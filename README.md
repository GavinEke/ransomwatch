# Ransomwatch

A small public threat-intelligence dashboard that records organization names listed on ransomware group leak sites. GitHub Actions refresh the group catalog and collect listing metadata; GitHub Pages serves the static dashboard.

Listings are claims published by threat actors. Seeing an organization here does not confirm that a data breach occurred or that data was stolen. This project stores names and limited text metadata only. It does not download, mirror, or link to leaked files, and it does not collect personal contact details.

## Data collected

- site/data/groups.json contains group names, status, upstream profile URLs, first/last-seen metadata, and direct website or Tor leak-site endpoints.
- site/data/victims.json contains one victim row per group and normalized organization, with the original post title, source-reported date/country/sector when available, optional short listing details, first/last observation timestamps, and listing state. Victim rows retain the legacy primary `source_id` plus a `source_ids` array for every leak-site URL that has reported the organization; per-URL crawl status remains in `sources[]`.
- Headlines and ambiguous posts remain in the data but are not displayed in the dashboard or included in victim totals. Country values inferred from a leading flag are labeled as inferred.
- Optional descriptions, claimed data size, file count, deadline, and organization website are collected only when explicitly shown on the listing. Those values are attributed to the threat actor and are not independently verified.

## One-time historical import

The historical importer accepts the archived `posts.json`-format file (the supplied copy may be named `posts.txt`). It previews the mapping by default; review that summary before applying it:

~~~sh
python scripts/import_historical_posts.py --input /path/to/posts.txt
python scripts/import_historical_posts.py --input /path/to/posts.txt --apply
~~~

The upstream archive records a post title, group name, and discovery time, but no post-level source ID. The importer therefore collapses duplicates by current group and normalized organization name and assigns a stable local ID. It uses exact group names plus only the explicitly approved aliases, leaves unmatched groups out, and does not add the archive file to this repository. Imported-only sightings remain `unknown` until a later live crawl sees them.

The victim crawler checks groups marked `active`, and up to the first 25 listing pages at each direct extortion endpoint. It requires the catalog's `leak_sites_scope` marker, so older catalogs are skipped until the group catalog refresh runs. A visible organization is marked `listed`; a historical organization not found in the first 25 pages remains `unknown`. Offline, unsupported, inactive, unscoped, removed, and time-budget-skipped sources also leave sightings `unknown`. Historical sightings are retained.

The collectors use conservative HTML table and victim-card parsing. A site's layout may not be recognized; those sources are marked unsupported. Add a parser in scripts/scrape_victims.py when a site needs a specific layout adapter. The crawler deduplicates shared URLs, scans up to 25 pagination pages per source, uses at most three concurrent requests with a 25-second per-page fetch deadline and 90-minute crawl budget, restricts requests to HTTP(S) public hosts or `.onion` hosts, validates redirect targets, and caps response size. Progress and per-page errors are flushed to the Actions log. If the time budget is reached, completed sightings are saved and remaining pages or sources are reported as partial or skipped by the budget. Classification migration retains existing sighting IDs and observation history.

## GitHub setup

1. Create a public GitHub repository and push this local main branch after GitHub CLI authentication is available.
2. In Settings → Pages, set Build and deployment → Source to GitHub Actions.
3. In Settings → Actions → General, allow the workflows to write repository contents. The workflows scope their token permissions to the data commit and Pages deployment jobs.
4. Run Refresh group catalog from the Actions tab. When it completes, the victim crawl and Pages deployment run automatically.

The group catalog also refreshes daily at 03:00 UTC. The second workflow can be dispatched manually to recrawl the current catalog. The Pages site URL appears in the deployment job summary.
Dashboard code and data changes pushed to `main` are published by a separate Pages-only workflow without starting a victim crawl.

## Local use

Requires Python 3.13 or newer and a public Tor SOCKS proxy at 127.0.0.1:9050 if the catalog contains onion sites.

~~~sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/refresh_groups.py
python scripts/scrape_victims.py
python -m http.server 8000 --directory site
~~~

Then open http://localhost:8000. Run the fixture checks with:

~~~sh
python -m unittest discover -s tests -v
~~~

## Project contents

- .github/workflows/refresh-groups.yml refreshes and commits the group catalog.
- .github/workflows/scrape-victims.yml crawls the catalog, commits sightings, and deploys GitHub Pages.
- .github/workflows/publish-pages.yml publishes dashboard changes without crawling leak sites.
- scripts/ contains the collectors, bounded network/HTML helpers, and a Pages artifact builder that omits upstream profile links.
- site/ contains the framework-free dashboard and generated JSON.
- tests/fixtures/ contains small HTML examples used by parser tests.
