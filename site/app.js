"use strict";

const DATA_URL = "./data/victims.json";

const elements = {
  loading: document.querySelector("#loading-state"),
  error: document.querySelector("#error-state"),
  errorMessage: document.querySelector("#error-message"),
  empty: document.querySelector("#empty-state"),
  emptyTitle: document.querySelector("#empty-title"),
  emptyCopy: document.querySelector("#empty-copy"),
  tableWrap: document.querySelector("#table-wrap"),
  pagination: document.querySelector("#table-pagination"),
  previousPage: document.querySelector("#previous-page"),
  nextPage: document.querySelector("#next-page"),
  pageStatus: document.querySelector("#page-status"),
  rows: document.querySelector("#victim-rows"),
  search: document.querySelector("#search-input"),
  group: document.querySelector("#group-filter"),
  country: document.querySelector("#country-filter"),
  state: document.querySelector("#state-filter"),
  resultCount: document.querySelector("#result-count"),
  total: document.querySelector("#metric-total"),
  listed: document.querySelector("#metric-listed"),
  groups: document.querySelector("#metric-groups"),
  sources: document.querySelector("#metric-sources"),
  updated: document.querySelector("#updated-at"),
};

let dataset = null;
let currentPage = 1;
const PAGE_SIZE = 100;

function setText(element, value) {
  element.textContent = value == null || value === "" ? "—" : String(value);
}

function displayDate(value, includeTime = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const options = includeTime
    ? { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }
    : { dateStyle: "medium", timeZone: "UTC" };
  return new Intl.DateTimeFormat(undefined, options).format(date);
}

function normalizedState(state) {
  return ["listed", "not_seen", "unknown"].includes(state) ? state : "unknown";
}

function stateLabel(state) {
  return {
    listed: "Currently listed",
    not_seen: "No longer seen",
    unknown: "Unknown / stale",
  }[normalizedState(state)];
}

function usableOrganizationName(value) {
  const name = String(value || "").replace(/[\[\]*_`~]/g, "").trim();
  if (!/[\p{L}\p{N}]/u.test(name)) return false;
  return !/^(?:n\/?a|unknown|unidentified|not available|none|null)$/i.test(name);
}

function displayedOrganization(item) {
  if (usableOrganizationName(item.organization)) return item.organization.trim();
  if (usableOrganizationName(item.post_title)) return item.post_title.trim();
  return "";
}

function postType(item) {
  if (["headline", "review"].includes(item.post_type)) return item.post_type;
  // Old or malformed data can label a punctuation-only placeholder as a
  // victim. Keep those records in the data, but out of victim totals.
  if (item.post_type === "victim") {
    if (usableOrganizationName(item.organization)) return "victim";
    if (item.organization && !usableOrganizationName(item.organization)) return "review";
  }
  // Older schema files may lack both a type and a normalized organization.
  // Reclassify their title using the same obvious headline exclusions.
  const title = String(item.post_title || item.organization || "").trim().toLocaleLowerCase();
  const normalizedTitle = title.replace(/[\[\]*_`~]/g, "").replace(/\s+/g, " ").trim();
  if (!usableOrganizationName(normalizedTitle)) return "review";
  if (["welcome", "important announcement", "home", "about", "contact", "news", "blog", "victims", "victim list", "recent victims", "all victims", "load more", "read more", "why it matters", "what is stored", "warning", "press", "notice", "jurisdiction", "cooperation reached"].includes(normalizedTitle)) return "headline";
  if (/^announcement\s+(for|about)\b/.test(normalizedTitle)) return "review";
  if (/^(view all|load more|read more|what time does|what time is|response to |publication hold|press release|statement:|article:|why it matters|what is stored|warning:|notice:|jurisdiction:|cooperation reached)/.test(normalizedTitle)) return "headline";
  if (/\b(article|interview|press release|announcement)\b/.test(normalizedTitle)) return "headline";
  return "victim";
}

function victimSightings() {
  return (dataset?.sightings || []).filter((item) => postType(item) === "victim");
}

function populateSelect(select, values, firstLabel) {
  select.replaceChildren(new Option(firstLabel, ""));
  for (const value of values) {
    select.add(new Option(value, value));
  }
}

function renderMetrics() {
  const sightings = victimSightings();
  const listedCount = sightings.filter((item) => normalizedState(item.listing_state) === "listed").length;
  const sourceTotal = (dataset.sources || []).length;
  const groupCount = (dataset.groups || []).length;
  setText(elements.total, sightings.length.toLocaleString());
  setText(elements.listed, listedCount.toLocaleString());
  setText(elements.groups, groupCount.toLocaleString());
  setText(elements.sources, sourceTotal.toLocaleString());
  elements.updated.textContent = dataset.updated_at
    ? "Last crawl " + displayDate(dataset.updated_at, true) + " UTC"
    : "No crawl has completed yet";
}

function populateFilters() {
  const sightings = victimSightings();
  const groupNames = new Map();
  for (const item of sightings) {
    if (item.group_id && item.group_name) groupNames.set(item.group_id, item.group_name);
  }
  elements.group.replaceChildren(new Option("All groups", ""));
  for (const [groupId, groupName] of [...groupNames.entries()].sort((left, right) => left[1].localeCompare(right[1]))) {
    elements.group.add(new Option(groupName, groupId));
  }
  populateSelect(
    elements.country,
    [...new Set(sightings.map((item) => item.country).filter(Boolean))]
      .sort((left, right) => left.localeCompare(right)),
    "All countries",
  );
}

function searchText(item) {
  return [
    item.organization,
    item.group_name,
    item.country,
    item.sector,
    item.reported_date,
  ].filter(Boolean).join(" ").toLocaleLowerCase();
}

function parseSortDate(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  const text = value.trim();
  const months = new Map([
    ["jan", 0], ["january", 0], ["feb", 1], ["february", 1],
    ["mar", 2], ["march", 2], ["apr", 3], ["april", 3],
    ["may", 4], ["jun", 5], ["june", 5], ["jul", 6], ["july", 6],
    ["aug", 7], ["august", 7], ["sep", 8], ["sept", 8], ["september", 8],
    ["oct", 9], ["october", 9], ["nov", 10], ["november", 10],
    ["dec", 11], ["december", 11],
  ]);
  const monthDate = text.match(/^(\d{1,2})\s+([a-z]+)[,.]?\s+(\d{4})$/i)
    || text.match(/^([a-z]+)\s+(\d{1,2})[,]?\s+(\d{4})$/i);
  if (monthDate) {
    const dayFirst = /^\d/.test(monthDate[1]);
    const day = Number(dayFirst ? monthDate[1] : monthDate[2]);
    const month = months.get((dayFirst ? monthDate[2] : monthDate[1]).toLocaleLowerCase());
    const year = Number(monthDate[3]);
    if (month === undefined || day < 1 || day > 31) return null;
    const timestamp = Date.UTC(year, month, day);
    const date = new Date(timestamp);
    return date.getUTCFullYear() === year && date.getUTCMonth() === month && date.getUTCDate() === day
      ? timestamp
      : null;
  }

  const parsed = Date.parse(text);
  return Number.isFinite(parsed) ? parsed : null;
}

function claimTimestamp(item) {
  const timestamp = parseSortDate(item.reported_date) ?? parseSortDate(item.first_seen_at);
  if (timestamp === null) return 0;
  const date = new Date(timestamp);
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

function compareSightings(left, right) {
  const dateOrder = claimTimestamp(right) - claimTimestamp(left);
  if (dateOrder) return dateOrder;
  const organizationOrder = displayedOrganization(left).localeCompare(
    displayedOrganization(right), undefined, { sensitivity: "base", numeric: true },
  );
  if (organizationOrder) return organizationOrder;
  const groupOrder = String(left.group_name || "").localeCompare(
    String(right.group_name || ""), undefined, { sensitivity: "base", numeric: true },
  );
  if (groupOrder) return groupOrder;
  return String(left.id || "").localeCompare(String(right.id || ""));
}

function addCell(row, className, text) {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text || "—";
  row.append(cell);
  return cell;
}

function appendClaimDetails(cell, item) {
  const details = item.claim_details && typeof item.claim_details === "object" ? item.claim_details : {};
  const entries = [];
  const title = typeof item.post_title === "string" ? item.post_title.trim() : "";
  const organization = typeof item.organization === "string" ? item.organization.trim() : "";
  if (title && title.toLocaleLowerCase() !== organization.toLocaleLowerCase()) {
    entries.push(["Original listing title", title]);
  }
  entries.push(
    ["Listing description", details.description],
    ["Claimed data size", details.claimed_data_size],
    ["Claimed file count", details.file_count],
    ["Claimed deadline", details.deadline],
    ["Organization website shown", details.organization_website],
  );
  const visibleEntries = entries.filter((entry) => {
    if (typeof entry[1] !== "string" || !entry[1].trim()) return false;
    return !/^(?:[-—–]+|n\/?a|unknown|none|null)$/i.test(entry[1].trim());
  });
  if (!visibleEntries.length) return;

  const disclosure = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "View note and listing details";
  disclosure.append(summary);
  const list = document.createElement("dl");
  list.className = "claim-details-list";
  for (const [label, value] of visibleEntries) {
    const term = document.createElement("dt");
    term.textContent = label;
    const description = document.createElement("dd");
    description.textContent = value;
    list.append(term, description);
  }
  disclosure.append(list);
  const note = document.createElement("p");
  note.className = "detail-attribution";
  note.textContent = "Information displayed by the threat actor; not independently verified.";
  disclosure.append(note);
  cell.append(disclosure);
}

function appendCountry(cell, item) {
  cell.textContent = item.country || "—";
  if (item.country && item.country_basis === "flag_inferred") {
    const note = document.createElement("span");
    note.className = "inferred-label";
    note.textContent = "Inferred from flag";
    cell.append(document.createElement("br"), note);
  }
}

function makeRow(item) {
  const row = document.createElement("tr");
  const organizationCell = addCell(row, "organization-cell", displayedOrganization(item));
  organizationCell.replaceChildren();
  const organizationName = document.createElement("div");
  organizationName.className = "organization-name";
  organizationName.textContent = displayedOrganization(item) || "Unidentified listing";
  organizationCell.append(organizationName);
  appendClaimDetails(organizationCell, item);

  addCell(row, "group-cell", item.group_name);
  addCell(row, "date-cell", item.reported_date || "—");
  const countryCell = document.createElement("td");
  appendCountry(countryCell, item);
  row.append(countryCell);
  addCell(row, "", item.sector);
  addCell(row, "date-cell", displayDate(item.last_seen_at));

  const stateCell = document.createElement("td");
  const state = normalizedState(item.listing_state);
  const pill = document.createElement("span");
  pill.className = "state-pill " + state;
  pill.textContent = stateLabel(state);
  stateCell.append(pill);
  row.append(stateCell);
  return row;
}

function filteredSightings() {
  const query = elements.search.value.trim().toLocaleLowerCase();
  const group = elements.group.value;
  const country = elements.country.value;
  const state = elements.state.value;
  return victimSightings()
    .filter((item) => !query || searchText(item).includes(query))
    .filter((item) => !group || item.group_id === group)
    .filter((item) => !country || item.country === country)
    .filter((item) => !state || normalizedState(item.listing_state) === state)
    .sort(compareSightings);
}

function renderTable() {
  const items = filteredSightings();
  const pageCount = Math.max(1, Math.ceil(items.length / PAGE_SIZE));
  currentPage = Math.min(currentPage, pageCount);
  const startIndex = (currentPage - 1) * PAGE_SIZE;
  const pageItems = items.slice(startIndex, startIndex + PAGE_SIZE);
  elements.rows.replaceChildren(...pageItems.map(makeRow));
  elements.resultCount.textContent = items.length.toLocaleString() + " shown";
  elements.pagination.hidden = items.length <= PAGE_SIZE;
  elements.previousPage.disabled = currentPage <= 1;
  elements.nextPage.disabled = currentPage >= pageCount;
  const firstVisible = items.length ? startIndex + 1 : 0;
  const lastVisible = Math.min(startIndex + PAGE_SIZE, items.length);
  elements.pageStatus.textContent = items.length
    ? "Page " + currentPage.toLocaleString() + " of " + pageCount.toLocaleString() +
      " · showing " + firstVisible.toLocaleString() + "–" + lastVisible.toLocaleString()
    : "";
  const hasData = victimSightings().length > 0;
  const hasFilters = Boolean(
    elements.search.value || elements.group.value || elements.country.value || elements.state.value,
  );
  elements.tableWrap.hidden = items.length === 0;
  elements.empty.hidden = items.length !== 0;
  if (!items.length) {
    elements.emptyTitle.textContent = hasData && hasFilters ? "No matching sightings" : "No victim claims yet";
    elements.emptyCopy.textContent = hasData && hasFilters
      ? "Change a filter or clear the search."
      : "The dashboard will populate after a successful leak-site crawl.";
  }
}

async function loadData() {
  try {
    const response = await fetch(DATA_URL, { cache: "no-cache" });
    if (!response.ok) throw new Error("Data request returned " + response.status);
    const result = await response.json();
    if (!result || !Array.isArray(result.sightings) || !Array.isArray(result.sources)) {
      throw new Error("The victim data file has an unexpected format.");
    }
    dataset = result;
    renderMetrics();
    populateFilters();
    elements.loading.hidden = true;
    renderTable();
  } catch (error) {
    elements.loading.hidden = true;
    elements.error.hidden = false;
    elements.errorMessage.textContent = error.message || "Try again later.";
    elements.resultCount.textContent = "";
  }
}

for (const control of [elements.search, elements.group, elements.country, elements.state]) {
  const resetPageAndRender = () => {
    currentPage = 1;
    renderTable();
  };
  control.addEventListener("input", resetPageAndRender);
  control.addEventListener("change", resetPageAndRender);
}

elements.previousPage.addEventListener("click", () => {
  currentPage = Math.max(1, currentPage - 1);
  renderTable();
});
elements.nextPage.addEventListener("click", () => {
  currentPage += 1;
  renderTable();
});

loadData();
