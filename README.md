# C.O.V.E.R. 2

CISA Observed Vulnerability Exploitation Report version 2

This project is a tool written in python that maps your software inventory (via CPE strings) to CVE data from the [NVD API v2](https://nvd.nist.gov/developers/vulnerabilities), enriches findings with [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) data, and produces a report of **HIGH** and **CRITICAL** severity vulnerabilities impacting your environment.

This is the second iteration of C.O.V.E.R. which adds the ability to read the CPE strings and query NVD and CISA KEV. The prior version of C.O.V.E.R. relied on a general software/vendor list. The accuracy of this data depended upon the accuracy of the supplied list. The intention of adding the CPE strinng functionality is that users could query existing tooling (vulnerability scanners or EDR) currently existing in their environments and get an accurate list stuff that may be in the shadows.

The main goal of this tool is to help teams prioritize remediation and patching while also providing a quick way to obtain up-to-date vulnerability threat intelligence impacting their environments.

Before you get started, it will be helpful to have a free NVD API key. Additionally, if you like the results, finding an automated and accurate way to obtain all the CPEs in your environment is equally helpful.

---

## Features

- Queries the **NVD API v2** for CVEs matching each CPE in your inventory
- Filters to **HIGH (≥ 7.0)** and **CRITICAL (≥ 9.0)** CVSS base scores
- Prefers **CVSS v3.1** scores, falls back to v3.0, then v2.0
- **Date filtering** via `--days` — scope results to the last N days (default: 90)
- **Deduplication** — CVEs matching multiple CPEs are merged into one row; the CPE field lists all affected products
- **CISA KEV enrichment** — flags actively exploited vulnerabilities, ransomware association, required action, and remediation due date
- **API key validation** at startup — detects unactivated or invalid keys before wasting a full run
- Results sorted by CVSS score descending; KEV entries surface first within tied scores
- **Dry run mode** — validates inventory and tests connectivity without querying CVEs
- Handles NVD **rate limiting**, **pagination**, and transient errors automatically
- No hardcoded credentials — all secrets loaded from `.env`

---

## Requirements

- Python 3.10+
- `requests`, `python-dotenv`

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/cve-report.git
cd cve-report
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate      # macOS / Linux
venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure your API key

```bash
cp .env.example .env
```

Edit `.env` and add your NVD API key:

```
NVD_API_KEY=your_nvd_api_key_here
```

> **Get a free NVD API key:** https://nvd.nist.gov/developers/request-an-api-key
>
> After requesting a key, check your email for a verification link — the key will not activate until it is clicked.
>
> Without a key the script still works but is rate-limited to 5 requests per 30 seconds. With a validated key the limit rises to 50 per 30 seconds, which matters significantly for larger inventories.

### 5. Verify your setup with a dry run

Before running a full report, confirm connectivity and inventory are correct:

```bash
python cve_report.py --dry-run
```

This validates your inventory file, tests the NVD API (including key acceptance), and tests the CISA KEV feed — without making any CVE queries or writing any output. Exit code 1 on any connectivity failure.

---

## Configuring Your CPE Inventory

Edit `cpe_inventory.txt` — one CPE string per line. Lines beginning with `#` are treated as comments.

```
# Web servers
cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

# Cryptography
cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*

# Operating systems (wildcard version — all CVEs for this product)
cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
```

The script normalizes CPE strings before querying NVD — trailing wildcard components are stripped automatically so you do not need to manage query formatting manually:

| Inventory entry | Sent to NVD |
|---|---|
| `cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*` | `cpe:2.3:a:google:chrome` |
| `cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*` | `cpe:2.3:a:apache:log4j:2.14.1` |

**Finding CPE strings for your software:**
- NVD CPE Search: https://nvd.nist.gov/products/cpe/search

---

## Usage

### Default — last 90 days, reads `cpe_inventory.txt`

```bash
python cve_report.py
```

### Specify date window

```bash
python cve_report.py --days 7      # last 7 days  (weekly cadence)
python cve_report.py --days 30     # last 30 days
python cve_report.py --days 0      # all CVEs regardless of age
```

### Specify inventory and output files

```bash
python cve_report.py --inventory /path/to/inventory.txt --output report.csv
```

### Dry run — validate setup without running

```bash
python cve_report.py --dry-run
python cve_report.py --dry-run --inventory /path/to/inventory.txt
```

### Debug mode — print normalized CPE strings and request URLs

```bash
python cve_report.py --debug
```

### Short flags

```bash
python cve_report.py -i inventory.txt -o report.csv -d 30
```

---

## Output

A timestamped CSV file (e.g. `cve_report_20250101_120000.csv`) with the following columns:

| Column | Description |
|---|---|
| CVE ID | CVE identifier (e.g. CVE-2024-12345) |
| CPE | CPE string(s) from your inventory that matched. Multiple values separated by ` \| ` when a CVE affects more than one inventoried product |
| Severity | CRITICAL or HIGH |
| CVSS Score | Base score (0.0 – 10.0) |
| CVSS Version | CVSS version used (3.1, 3.0, or 2.0) |
| Vulnerability Status | NVD status (e.g. Analyzed, Modified) |
| Published | CVE publication date |
| Last Modified | Date of most recent NVD update |
| In CISA KEV | **Yes** if this CVE is actively exploited per CISA |
| KEV Date Added | Date CISA added the CVE to the catalog |
| KEV Ransomware Use | **Known** if linked to ransomware campaigns |
| KEV Required Action | CISA's remediation directive |
| KEV Action Due Date | Federal remediation deadline (useful context for any org) |
| Description | English description from NVD |
| NVD URL | Direct link to the full NVD entry |

---

## Deduplication

When a CVE matches more than one CPE in your inventory, the script merges the matches into a single row rather than reporting the same CVE multiple times. The CPE column will contain all matching products, pipe-separated:

```
CVE-2024-1234 | cpe:2.3:a:openssl:openssl:3.0 | cpe:2.3:o:microsoft:windows_server_2022
```

The summary output shows both pre- and post-dedup totals so you can see the overlap across your inventory.

---

## Security Notes

- **No credentials are hardcoded.** The NVD API key is loaded exclusively from `.env` at runtime.
- `.env` is listed in `.gitignore` and must never be committed.
- `.env.example` is the safe, committed template — it contains only placeholder values.
- All generated CSV reports are excluded from version control by default. Report output may contain details about your software inventory and should be treated as sensitive.
- The API key is validated at startup. If the key is present but rejected by NVD (a common symptom of an unactivated key), the script warns you immediately and falls back to unauthenticated requests rather than silently returning empty results.

---

## Rate Limiting

The script automatically:
- Pauses between CPE queries to respect NVD's rolling rate limits
- Detects HTTP 429 responses and backs off before retrying
- Retries transient failures up to 3 times before skipping a CPE

For large inventories an API key is strongly recommended.

---

## Project Structure

```
cve-report/
├── cve_report.py        # Main script
├── cpe_inventory.txt    # Your CPE asset inventory (edit this)
├── nvd_diagnose.py      # Standalone API diagnostic tool
├── .env.example         # Template — copy to .env and add your API key
├── .env                 # Your secrets (never committed — in .gitignore)
├── .gitignore
├── requirements.txt
└── README.md
```
