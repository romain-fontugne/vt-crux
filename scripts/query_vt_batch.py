import json
import gzip
import os

import time
from datetime import datetime, timezone, timedelta

import requests

from utils import (
    read_set,
    read_json,
    load_state,
    save_state,
    RateLimiter,
)

VT_KEY = os.environ["VT_API_KEY"]

BATCH_SIZE = 500
REFRESH_DATA_TIMEOUT = timedelta(days=365)

HEADERS = {
    "x-apikey": VT_KEY
}

VT_URL = (
    "https://www.virustotal.com/api/v3/domains/{}"
)

# VirusTotal's public API is limited to roughly 4 requests per minute, so keep
# a ~16s spacing between calls to stay comfortably within that budget.
VT_LIMITER = RateLimiter(min_interval=16.0)

# Maximum number of retries when the API returns a transient HTTP error.
MAX_RETRIES = 5

# Base backoff (in seconds) used for exponential wait between retries.
RETRY_BACKOFF = 20.0


def fetch_domain(domain):
    attempt = 0

    while True:
        VT_LIMITER.wait()

        try:
            r = requests.get(VT_URL.format(domain), headers=HEADERS, timeout=30)
        except requests.exceptions.RequestException as exc:
            attempt += 1

            if attempt > MAX_RETRIES:
                return {
                    "domain": domain,
                    "error": True,
                    "message": str(exc),
                }

            wait_seconds = RETRY_BACKOFF * (2 ** (attempt - 1))

            print(
                f"Request for {domain} failed ({exc}); "
                f"retrying in {wait_seconds:.1f}s "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

            time.sleep(wait_seconds)
            continue

        if r.status_code == 200:
            return r.json()

        # A 404 means VirusTotal has no record for the domain; this is a valid
        # answer rather than a transient failure, so record it as-is.
        if r.status_code == 404:
            return {
                "domain": domain,
                "status": r.status_code,
                "error": True,
            }

        # Retry on rate limiting (429) and server-side (5xx) errors, honouring
        # the Retry-After header when the server provides one.
        if r.status_code == 429 or r.status_code >= 500:
            attempt += 1

            if attempt > MAX_RETRIES:
                return {
                    "domain": domain,
                    "status": r.status_code,
                    "error": True,
                }

            wait_seconds = RETRY_BACKOFF * (2 ** (attempt - 1))

            retry_after = r.headers.get("Retry-After")

            if retry_after:
                try:
                    wait_seconds = max(wait_seconds, float(retry_after))
                except ValueError:
                    pass

            print(
                f"HTTP {r.status_code} for {domain}; "
                f"retrying in {wait_seconds:.1f}s "
                f"(attempt {attempt}/{MAX_RETRIES})"
            )

            time.sleep(wait_seconds)
            continue

        # Any other status code is treated as a non-retryable error.
        return {
            "domain": domain,
            "status": r.status_code,
            "error": True,
        }


def main():
    domains = read_set("data/domains.txt")

    queried = read_json("data/queried.json")

    # Remove domains queried a long time ago
    now = datetime.now(timezone.utc)
    for k, v in queried.items():
        queried_date = datetime.fromisoformat(v)

        if now - queried_date > REFRESH_DATA_TIMEOUT:
            queried.pop(k)

    state = load_state("data/state.json")

    today = datetime.now(timezone.utc).strftime("%Y-%m")

    output_file = (f"data/vt/{today}.jsonl.gz")

    os.makedirs("data/vt", exist_ok=True)

    processed = 0

    with gzip.open(output_file, "at") as fp:

        for domain in domains:

            if domain in queried:
                continue

            print(domain)

            result = fetch_domain(domain)

            record = {
                "domain": domain,
                "collected_at": datetime.now(timezone.utc)
                .isoformat(),
                "response": result
            }

            fp.write(json.dumps(record))

            fp.write("\n")

            queried[domain] = datetime.now(timezone.utc).isoformat()

            processed += 1

            if processed == BATCH_SIZE:
                break

    state["processed"] = processed

    state["last_run"] = datetime.now(timezone.utc).isoformat()

    save_state("data/state.json", state)

    with open("data/queried.txt", "w") as fp:
        json.dump(queried, fp, indent=2)

    metadata = {
        "processed_this_run": processed,
        "total_domains": len(domains),
        "remaining_domains": max(0, len(domains - set(queried.keys())))
    }

    with open("data/metadata.json", "w") as fp:
        json.dump(metadata, fp, indent=2)


if __name__ == "__main__":
    main()
