# vt-crux

A lightweight, automated pipeline that builds an inventory of popular country-specific domains from the Chrome User Experience Report (CrUX) and queries their threat intelligence data from the VirusTotal API.

## Features

- **Domain Inventory Construction**: Fetches top country-specific CSV files from the CrUX top lists dataset, parses the domains, extracts their canonical hosts, and maintains a sorted master domain list by popularity rank.
- **Batched VirusTotal Queries**: Queries domains in batches of 500. Handles API rate limiting (with backoff and retry) and saves responses in compressed JSON Lines (`.jsonl.gz`) files.
- **State Preservation**: Tracks the query index (`cursor`) and already-processed domains to resume smoothly without duplicate queries.
- **GitHub Actions Automation**: Automatically schedules a monthly update to refresh the inventory, query the next batch, and commit changes back to the repository.

## Project Structure

- `scripts/build_domain_inventory.py`: Downloads top lists from CrUX and saves them sorted in `data/domains.txt`.
- `scripts/query_vt_batch.py`: Batch-queries VirusTotal and saves gzip-compressed JSON responses to `data/vt/`.
- `scripts/utils.py`: Utility functions for rate-limiting, requests, state persistence, and parsing.
- `.github/workflows/monthly-vt.yml`: Automation workflow scheduled for the 15th of every month.

## Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/vt-crux.git
   cd vt-crux
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   Create or export your VirusTotal API key:
   ```bash
   export VT_API_KEY="your-virustotal-api-key"
   ```

## Usage

### 1. Build the Domain Inventory
To download the latest country-specific domains from CrUX and build `data/domains.txt`:
```bash
python scripts/build_domain_inventory.py
```

### 2. Query VirusTotal (Batch of 500)
To run a batch query for the next 500 domains:
```bash
python scripts/query_vt_batch.py
```
This updates `data/state.json` (cursor status) and `data/queried.txt` (list of queried domains) and appends results to `data/vt/YYYY-MM.jsonl.gz`.
