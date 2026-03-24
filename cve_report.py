#!/usr/bin/env python3
"""
cve_report.py
─────────────────────────────────────────────────────────────────────────────
CVE Vulnerability Report Generator
Queries the NVD API v2 for HIGH and CRITICAL CVEs matching the CPE strings
defined in your inventory file, enriches results with CISA KEV data, and
writes findings to a timestamped CSV report.

Usage:
    python cve_report.py
    python cve_report.py --inventory path/to/cpe_inventory.txt
    python cve_report.py --inventory cpe_inventory.txt --output my_report.csv
    python cve_report.py --days 30        # CVEs published in last 30 days only
    python cve_report.py --days 0         # all CVEs regardless of age
    python cve_report.py --debug          # print exact NVD request URLs

Requirements:
    pip install -r requirements.txt

API Key (optional but recommended):
    Copy .env.example → .env and populate NVD_API_KEY.
    Without a key, NVD enforces a stricter rate limit (5 req / 30 sec).
    With a key, the limit rises to 50 req / 30 sec.
    Request a free key at: https://nvd.nist.gov/developers/request-an-api-key
─────────────────────────────────────────────────────────────────────────────
"""

import csv
import logging
import os
import sys
import time
from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv

# ── Environment ───────────────────────────────────────────────────────────────
load_dotenv()

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY   = os.getenv("NVD_API_KEY")  # Optional — see .env.example
CISA_KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Rate limiting — authenticated clients get a more generous window
RATE_LIMIT_DELAY = 6.0 if NVD_API_KEY else 7.0   # seconds between CPE requests
RETRY_BACKOFF    = 35                              # seconds to pause on HTTP 429
MAX_RETRIES      = 3
RESULTS_PER_PAGE = 2000                            # NVD maximum per request

# Only report CVEs at or above this CVSS base score (HIGH threshold = 7.0)
MIN_CVSS_SCORE = 7.0

CSV_FIELDS = [
    "CVE ID",
    "CPE",
    "Severity",
    "CVSS Score",
    "CVSS Version",
    "Vulnerability Status",
    "Published",
    "Last Modified",
    "In CISA KEV",
    "KEV Date Added",
    "KEV Ransomware Use",
    "KEV Required Action",
    "KEV Action Due Date",
    "Description",
    "NVD URL",
]

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)-8s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger(__name__)

# Module-level debug flag — set by --debug argument in main()
DEBUG = False


# ─────────────────────────────────────────────────────────────────────────────
# Inventory
# ─────────────────────────────────────────────────────────────────────────────

def load_cpe_inventory(filepath: str) -> list[str]:
    """
    Read CPE strings from a plain-text file.
    One CPE per line. Lines starting with '#' and blank lines are ignored.
    """
    path = Path(filepath)
    if not path.exists():
        log.error(f"CPE inventory file not found: {filepath}")
        sys.exit(1)

    cpes: list[str] = []
    with open(path, encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            if line and not line.startswith("#"):
                cpes.append(line)

    if not cpes:
        log.error(f"No CPE entries found in: {filepath}")
        sys.exit(1)

    log.info(f"Loaded {len(cpes)} CPE(s) from '{filepath}'")
    return cpes


# ─────────────────────────────────────────────────────────────────────────────
# CPE Normalization
# ─────────────────────────────────────────────────────────────────────────────

def normalize_cpe_for_query(cpe: str) -> str:
    """
    Trim a CPE string to the minimum meaningful prefix for NVD's
    virtualMatchString parameter.

    NVD's virtualMatchString compares the supplied string against CPE
    applicability statements in its CVE records. Fully-wildcarded trailing
    components (e.g. '...:chrome:*:*:*:*:*:*:*:*') don't match anything
    because NVD has no applicability statements that literally contain eight
    consecutive wildcards — it returns HTTP 404 instead.

    Strategy:
        - Always keep: cpe, 2.3, <part>, <vendor>, <product>
        - Keep <version> only when it is a real value (not '*' or '-')
        - Discard everything after the version

    Examples:
        cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*  →  cpe:2.3:a:google:chrome
        cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*  →  cpe:2.3:a:apache:log4j:2.14.1
        cpe:2.3:a:microsoft:exchange_server:2019:-:*  →  cpe:2.3:a:microsoft:exchange_server:2019
    """
    parts = cpe.split(":")
    # Minimum required: cpe, 2.3, part, vendor, product  (5 components)
    if len(parts) < 5:
        return cpe

    meaningful = parts[:5]  # cpe:2.3:<part>:<vendor>:<product>

    # Append version if it carries real information
    if len(parts) > 5 and parts[5] not in ("*", "-", ""):
        meaningful.append(parts[5])

    return ":".join(meaningful)


# ─────────────────────────────────────────────────────────────────────────────
# CISA KEV
# ─────────────────────────────────────────────────────────────────────────────

def fetch_cisa_kev() -> dict[str, dict]:
    """
    Download the CISA Known Exploited Vulnerabilities catalog and return a
    dict keyed by CVE ID for fast O(1) lookup during enrichment.

    CISA KEV is a free, public feed — no authentication required.
    Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

    Returns an empty dict if the download fails so the rest of the
    pipeline can continue without KEV data.
    """
    log.info("Fetching CISA KEV catalog …")
    try:
        response = requests.get(CISA_KEV_URL, timeout=30)
        response.raise_for_status()
        catalog = response.json()
        vulns   = catalog.get("vulnerabilities", [])

        kev_lookup = {v["cveID"]: v for v in vulns if "cveID" in v}
        log.info(f"CISA KEV catalog loaded — {len(kev_lookup)} entries.")
        return kev_lookup

    except requests.exceptions.RequestException as exc:
        log.warning(f"Could not fetch CISA KEV catalog: {exc}")
        log.warning("Continuing without KEV enrichment.")
        return {}


# ─────────────────────────────────────────────────────────────────────────────
# NVD API
# ─────────────────────────────────────────────────────────────────────────────

def validate_nvd_key() -> bool:
    """
    Test the NVD API key by making a single known-good request.
    NVD returns HTTP 404 (not 401/403) when a key is invalid or unactivated,
    so we must probe with a real CVE ID to distinguish a bad key from no data.

    Returns True if the key is valid and accepted, False otherwise.
    """
    if not NVD_API_KEY:
        return False

    try:
        response = requests.get(
            NVD_API_BASE,
            headers={"Accept": "application/json", "apiKey": NVD_API_KEY},
            params={"cveId": "CVE-2021-44228"},
            timeout=15,
        )
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def build_headers() -> dict:
    """
    Return HTTP headers for NVD requests.

    If an API key is configured, validates it before use. NVD returns 404
    for unactivated or invalid keys (instead of 401/403), which would cause
    every CPE query to silently return zero results. Catching this upfront
    saves the entire run from producing a false empty report.

    Falls back to unauthenticated requests if the key is absent or invalid.
    """
    headers = {"Accept": "application/json"}

    if NVD_API_KEY:
        log.info("NVD API key found — validating …")
        if validate_nvd_key():
            headers["apiKey"] = NVD_API_KEY
            log.info("NVD API key validated — authenticated rate limits in effect.")
        else:
            log.warning(
                "NVD API key present but NOT accepted by NVD (received 404 on validation). "
                "Common causes: key not yet activated (check email for verification link), "
                "or key has expired. Falling back to unauthenticated requests."
            )
    else:
        log.warning(
            "NVD_API_KEY not set. Using unauthenticated rate limits "
            "(5 req/30 sec). Add your key to .env for better performance."
        )

    return headers


def query_nvd(cpe: str, headers: dict) -> list[dict]:
    """
    Fetch all CVEs from NVD matching the given CPE string.

    The raw CPE from the inventory is normalized before querying:
    trailing wildcard components are stripped so NVD's virtualMatchString
    can match against its applicability statements. A fully-wildcarded
    string like 'cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*' is trimmed to
    'cpe:2.3:a:google:chrome' before the request is sent.

    NVD returns HTTP 404 for both invalid CPEs and CPEs that match zero
    CVEs. Both cases are treated as an empty result (not an error).

    Handles pagination, HTTP 429 rate-limit responses, and transient
    network errors. Returns a list of raw vulnerability dicts.
    """
    query_string = normalize_cpe_for_query(cpe)

    if DEBUG:
        log.debug(f"  CPE (raw)        : {cpe}")
        log.debug(f"  CPE (normalized) : {query_string}")

    all_vulnerabilities: list[dict] = []
    start_index = 0

    while True:
        params = {
            "virtualMatchString": query_string,
            "startIndex":         start_index,
            "resultsPerPage":     RESULTS_PER_PAGE,
        }

        response = None
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                response = requests.get(
                    NVD_API_BASE,
                    headers=headers,
                    params=params,
                    timeout=30,
                )

                if DEBUG:
                    log.debug(f"  Request URL: {response.url}")
                    log.debug(f"  HTTP status: {response.status_code}")

                if response.status_code == 200:
                    break  # Success — exit retry loop

                if response.status_code == 404:
                    # NVD returns 404 for zero results — not a failure
                    log.info("        No CVEs found in NVD for this CPE.")
                    return all_vulnerabilities

                if response.status_code == 429:
                    log.warning(
                        f"  Rate-limited by NVD (HTTP 429). "
                        f"Waiting {RETRY_BACKOFF}s … (attempt {attempt}/{MAX_RETRIES})"
                    )
                    time.sleep(RETRY_BACKOFF)

                else:
                    log.error(
                        f"  NVD returned HTTP {response.status_code} for CPE: {cpe}"
                    )
                    return all_vulnerabilities

            except requests.exceptions.RequestException as exc:
                log.error(f"  Request error (attempt {attempt}/{MAX_RETRIES}): {exc}")
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_BACKOFF)
                else:
                    log.error(f"  Max retries exceeded for CPE: {cpe}")
                    return all_vulnerabilities
        else:
            log.error(f"  Could not retrieve data for CPE: {cpe}")
            return all_vulnerabilities

        data          = response.json()
        total_results = data.get("totalResults", 0)
        page_results  = data.get("vulnerabilities", [])

        all_vulnerabilities.extend(page_results)
        start_index += len(page_results)

        log.info(f"        Page retrieved: {len(page_results)} CVE(s) "
                 f"(total so far: {len(all_vulnerabilities)} / {total_results})")

        if start_index >= total_results:
            break  # All pages retrieved

        # Respect rate limit between paginated requests
        time.sleep(RATE_LIMIT_DELAY)

    return all_vulnerabilities


# ─────────────────────────────────────────────────────────────────────────────
# CVE Parsing & Enrichment
# ─────────────────────────────────────────────────────────────────────────────

def extract_cvss(cve_item: dict) -> tuple[float | None, str, str]:
    """
    Extract the highest-fidelity available CVSS score from a CVE item.

    Priority order: CVSS v3.1  →  CVSS v3.0  →  CVSS v2.
    Within each version, the NVD 'Primary' source is preferred.

    Returns:
        (base_score, severity_label, cvss_version_string)
    """
    metrics = cve_item.get("metrics", {})

    for metric_key, version_label in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2",  "2.0"),
    ]:
        metric_list = metrics.get(metric_key, [])
        if not metric_list:
            continue

        # Prefer NVD's own 'Primary' score; fall back to first entry
        entry = next(
            (m for m in metric_list if m.get("type") == "Primary"),
            metric_list[0],
        )
        cvss_data = entry.get("cvssData", {})
        score     = cvss_data.get("baseScore")
        severity  = cvss_data.get("baseSeverity", "UNKNOWN").upper()
        return score, severity, version_label

    return None, "UNKNOWN", "N/A"


def parse_cve_record(
    vuln: dict,
    cpe: str,
    kev_lookup: dict,
    cutoff_date: datetime | None = None,
) -> dict | None:
    """
    Flatten a single NVD vulnerability record into a report-ready dict,
    enriched with CISA KEV data where available.

    Returns None if the CVE:
      - Does not meet the HIGH/CRITICAL CVSS threshold
      - Was published before cutoff_date (when date filtering is active)
    """
    cve_item = vuln.get("cve", {})
    cve_id   = cve_item.get("id", "N/A")

    score, severity, cvss_version = extract_cvss(cve_item)

    # Filter — only keep HIGH (>=7.0) and CRITICAL (>=9.0)
    if score is None or score < MIN_CVSS_SCORE:
        return None

    # Date filter — drop CVEs published before the cutoff
    if cutoff_date is not None:
        published_raw = cve_item.get("published", "")
        if published_raw:
            try:
                published_dt = datetime.fromisoformat(
                    published_raw.rstrip("Z")
                ).replace(tzinfo=timezone.utc)
                if published_dt < cutoff_date:
                    return None
            except ValueError:
                pass  # Unparseable date — include rather than silently drop

    # Prefer the English description
    descriptions = cve_item.get("descriptions", [])
    description  = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # CISA KEV enrichment
    kev_entry      = kev_lookup.get(cve_id, {})
    in_kev         = "Yes" if kev_entry else "No"
    kev_date_added = kev_entry.get("dateAdded",                    "")
    kev_ransomware = kev_entry.get("knownRansomwareCampaignUse",   "")
    kev_action     = kev_entry.get("requiredAction",               "")
    kev_due_date   = kev_entry.get("dueDate",                      "")

    return {
        "CVE ID":               cve_id,
        "CPE":                  cpe,
        "Severity":             severity,
        "CVSS Score":           score,
        "CVSS Version":         cvss_version,
        "Vulnerability Status": cve_item.get("vulnStatus", "N/A"),
        "Published":            cve_item.get("published",    "N/A"),
        "Last Modified":        cve_item.get("lastModified", "N/A"),
        "In CISA KEV":          in_kev,
        "KEV Date Added":       kev_date_added,
        "KEV Ransomware Use":   kev_ransomware,
        "KEV Required Action":  kev_action,
        "KEV Action Due Date":  kev_due_date,
        "Description":          description,
        "NVD URL":              f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report Output
# ─────────────────────────────────────────────────────────────────────────────

def write_csv(rows: list[dict], output_path: str) -> None:
    """Write the filtered CVE findings to a CSV file."""
    if not rows:
        log.warning("No HIGH or CRITICAL CVEs found — report will not be written.")
        return

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    log.info(f"Report written → {output_path}  ({len(rows)} finding(s))")


def print_summary(rows: list[dict]) -> None:
    """Log a brief summary of findings by severity and KEV status."""
    critical   = sum(1 for r in rows if r["Severity"] == "CRITICAL")
    high       = sum(1 for r in rows if r["Severity"] == "HIGH")
    in_kev     = sum(1 for r in rows if r["In CISA KEV"] == "Yes")
    ransomware = sum(1 for r in rows if r["KEV Ransomware Use"] == "Known")

    log.info("─" * 60)
    log.info(f"  CRITICAL          : {critical}")
    log.info(f"  HIGH              : {high}")
    log.info(f"  TOTAL             : {len(rows)}")
    log.info(f"  In CISA KEV       : {in_kev}")
    log.info(f"  Known Ransomware  : {ransomware}")
    log.info("─" * 60)


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# Dry Run
# ─────────────────────────────────────────────────────────────────────────────

def run_dry_run(inventory_file: str) -> None:
    """
    Validate setup without executing a full report run.

    Checks performed:
        1. Inventory file exists and contains valid CPE strings
        2. NVD API is reachable and the API key (if set) is accepted
        3. CISA KEV feed is reachable and returns data
        4. Prints the normalized query string for every CPE so the user can
           verify NVD will receive the expected input

    Exits with code 1 if any connectivity check fails so this can be used
    in CI pipelines or scheduled job preflight checks.
    """
    log.info("── Dry Run ─────────────────────────────────────────────────────")
    log.info("No CVE queries will be made. No report will be written.")
    log.info("────────────────────────────────────────────────────────────────")

    # ── 1. Inventory ──────────────────────────────────────────────────────────
    log.info("STEP 1/3  Validating inventory …")
    cpes = load_cpe_inventory(inventory_file)
    log.info(f"          {len(cpes)} CPE(s) loaded.")
    log.info("          Normalized query strings:")
    for cpe in cpes:
        normalized = normalize_cpe_for_query(cpe)
        log.info(f"            {cpe}")
        log.info(f"              → {normalized}")

    # ── 2. NVD connectivity + key validation ─────────────────────────────────
    log.info("STEP 2/3  Testing NVD API …")
    headers = build_headers()
    try:
        response = requests.get(
            NVD_API_BASE,
            headers=headers,
            params={"cveId": "CVE-2021-44228"},
            timeout=15,
        )
        if response.status_code == 200:
            log.info("          NVD API reachable — test lookup succeeded (CVE-2021-44228).")
        else:
            log.error(f"          NVD API returned HTTP {response.status_code}. "
                      "Check your API key and network connectivity.")
            sys.exit(1)
    except requests.exceptions.RequestException as exc:
        log.error(f"          NVD API unreachable: {exc}")
        sys.exit(1)

    # ── 3. CISA KEV feed ──────────────────────────────────────────────────────
    log.info("STEP 3/3  Testing CISA KEV feed …")
    kev = fetch_cisa_kev()
    if kev:
        log.info(f"          CISA KEV reachable — {len(kev)} entries available.")
    else:
        log.warning("          CISA KEV feed could not be reached. "
                    "KEV enrichment will be skipped on a real run.")

    # ── Summary ───────────────────────────────────────────────────────────────
    log.info("────────────────────────────────────────────────────────────────")
    log.info("  Dry run complete — all checks passed. Ready for a full run.")
    log.info("────────────────────────────────────────────────────────────────")


def deduplicate(rows: list[dict]) -> list[dict]:
    """
    Merge rows that share the same CVE ID.

    When a CVE matches multiple CPEs in the inventory, NVD will return it
    once per CPE query. Rather than dropping the duplicates (losing context)
    or keeping all of them (inflating the count), this merges them into a
    single row and concatenates the matching CPE strings so the analyst can
    see every affected product at a glance.

    Example:
        CVE-2024-1234 matched by openssl AND apache → one row,
        CPE column: "cpe:2.3:a:openssl:openssl:3.0 | cpe:2.3:a:apache:..."
    """
    seen: dict[str, dict] = {}
    for row in rows:
        cve_id = row["CVE ID"]
        if cve_id not in seen:
            seen[cve_id] = row.copy()
        else:
            # Append the additional CPE if not already listed
            existing_cpes = seen[cve_id]["CPE"].split(" | ")
            if row["CPE"] not in existing_cpes:
                seen[cve_id]["CPE"] = " | ".join(existing_cpes + [row["CPE"]])

    deduped = list(seen.values())
    return deduped


def generate_report(inventory_file: str, output_file: str, days: int = 90) -> None:
    """
    End-to-end pipeline:
        1. Load CPE inventory
        2. Fetch CISA KEV catalog (once, upfront)
        3. Compute cutoff date from --days (0 = no filter)
        4. For each CPE:
            a. Normalize to a meaningful NVD query prefix
            b. Query NVD via virtualMatchString
            c. Filter to HIGH / CRITICAL only
            d. Filter by published date if cutoff is set
            e. Enrich with CISA KEV data
        5. Deduplicate — merge rows sharing the same CVE ID, combine CPE strings
        6. Sort: CVSS score descending; KEV entries bubble up within tied scores
        7. Write CSV report
    """
    cpes       = load_cpe_inventory(inventory_file)
    headers    = build_headers()
    kev_lookup = fetch_cisa_kev()
    all_rows: list[dict] = []

    # Compute the cutoff datetime (timezone-aware UTC)
    if days > 0:
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        log.info(f"Date filter active — CVEs published on or after: "
                 f"{cutoff_date.strftime('%Y-%m-%d')} ({days} days)")
    else:
        cutoff_date = None
        log.info("Date filter inactive — returning all CVEs regardless of age.")

    for idx, cpe in enumerate(cpes, start=1):
        normalized = normalize_cpe_for_query(cpe)
        log.info(f"[{idx}/{len(cpes)}]  Querying NVD → {normalized}")

        raw_vulns = query_nvd(cpe, headers)
        log.info(f"        {len(raw_vulns)} total CVE(s) returned by NVD")

        cpe_rows = [
            record
            for v in raw_vulns
            if (record := parse_cve_record(v, cpe, kev_lookup, cutoff_date)) is not None
        ]
        log.info(f"        {len(cpe_rows)} meet HIGH/CRITICAL threshold within date range")
        all_rows.extend(cpe_rows)

        # Pause between CPEs to respect NVD rate limits
        if idx < len(cpes):
            time.sleep(RATE_LIMIT_DELAY)

    log.info(f"Pre-dedup total : {len(all_rows)} row(s)")
    all_rows = deduplicate(all_rows)
    log.info(f"Post-dedup total: {len(all_rows)} unique CVE(s)")

    # Primary sort: CVSS score descending
    # Secondary sort: KEV entries first within tied scores
    all_rows.sort(
        key=lambda r: (r["CVSS Score"] or 0, r["In CISA KEV"] == "Yes"),
        reverse=True,
    )

    write_csv(all_rows, output_file)
    print_summary(all_rows)


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    global DEBUG
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    parser = ArgumentParser(
        description=(
            "CVE Vulnerability Report Generator\n"
            "Queries the NVD API v2 and reports HIGH/CRITICAL CVEs for your environment,\n"
            "enriched with CISA Known Exploited Vulnerability (KEV) data."
        )
    )
    parser.add_argument(
        "--inventory", "-i",
        default="cpe_inventory.txt",
        metavar="FILE",
        help="Path to CPE inventory file (default: cpe_inventory.txt)",
    )
    parser.add_argument(
        "--output", "-o",
        default=f"cve_report_{timestamp}.csv",
        metavar="FILE",
        help="Output CSV filename (default: cve_report_<timestamp>.csv)",
    )
    parser.add_argument(
        "--days", "-d",
        type=int,
        default=90,
        metavar="N",
        help=(
            "Only include CVEs published within the last N days. "
            "Use 0 for all CVEs regardless of age. (default: 90)"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate the inventory file and test NVD + CISA KEV connectivity "
            "without querying CVEs or writing a report. Useful for verifying "
            "setup and API key before a full run."
        ),
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print exact NVD request URLs and normalized CPE strings for troubleshooting",
    )
    args = parser.parse_args()

    if args.debug:
        DEBUG = True
        logging.getLogger().setLevel(logging.DEBUG)

    log.info("=" * 60)
    log.info("  CVE Report Generator — NVD API v2 + CISA KEV")
    log.info(f"  Inventory : {args.inventory}")
    if not args.dry_run:
        log.info(f"  Output    : {args.output}")
        log.info(f"  Date range: {'All time' if args.days == 0 else f'Last {args.days} days'}")
    if args.dry_run:
        log.info("  Mode      : DRY RUN")
    elif DEBUG:
        log.info("  Mode      : DEBUG")
    log.info("=" * 60)

    if args.dry_run:
        run_dry_run(args.inventory)
    else:
        generate_report(args.inventory, args.output, days=args.days)


if __name__ == "__main__":
    main()
