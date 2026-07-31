import gzip
import io
import json
import os
import zipfile
from pathlib import Path

import tldextract

from utils import RateLimiter, throttled_get

TOPK_CRUX = 1000
TOPK_TRANCO = 10000

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"

COUNTRY_INDEX_URL = (
    "https://api.github.com/repos/"
    "InternetHealthReport/crux-top-lists-country/"
    "contents/data/country"
)

# Use GITHUB_TOKEN if available to authenticate requests and get higher rate limits (5,000 req/hr).
# If authenticated, use a fast interval (1.0s); otherwise, keep a conservative delay (15.0s).
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
HEADERS = {}
if GITHUB_TOKEN:
    HEADERS["Authorization"] = f"token {GITHUB_TOKEN}"

interval = 1.0 if GITHUB_TOKEN else 15.0
GITHUB_LIMITER = RateLimiter(min_interval=interval)


def extract_domain(origin):
    try:
        ext = tldextract.extract(origin)
        return ext.top_domain_under_public_suffix or None
    except Exception:
        return None


def get_country_dirs():
    r = throttled_get(
        COUNTRY_INDEX_URL,
        limiter=GITHUB_LIMITER,
        headers=HEADERS,
        timeout=60,
    )

    dirs = []

    for item in r.json():
        if item["type"] == "dir":
            dirs.append(item["url"])

    return dirs


def get_latest_country_file(dir_url):
    r = throttled_get(
        dir_url,
        limiter=GITHUB_LIMITER,
        headers=HEADERS,
        timeout=60,
    )

    latest_name = None
    latest_url = None

    for item in r.json():
        name = item["name"]

        if not name.endswith(".csv.gz"):
            continue

        # File names follow the YYYYMM.csv.gz pattern, so a plain
        # lexicographic comparison also yields the chronologically latest one.
        if latest_name is None or name > latest_name:
            latest_name = name
            latest_url = item["download_url"]

    return latest_url, latest_name


def download_ranked_domains(csv_url):
    print(f"Downloading {csv_url}")

    r = throttled_get(csv_url, limiter=GITHUB_LIMITER, timeout=120)

    text = gzip.decompress(r.content).decode()

    ranked = {}

    lines = text.splitlines()

    for row in lines[1:]:
        parts = row.split(",")

        if len(parts) < 2:
            continue

        domain = extract_domain(parts[0])

        if not domain:
            continue

        try:
            rank = int(parts[1])
        except ValueError:
            continue

        domain = domain.lower()

        # Lower rank means a more popular domain, so keep the best (lowest).
        if domain not in ranked or rank < ranked[domain]:
            ranked[domain] = rank

    return ranked


def download_tranco_domains(limit=TOPK_TRANCO):
    print(f"Downloading {TRANCO_URL}")

    r = throttled_get(TRANCO_URL, timeout=120)

    with zipfile.ZipFile(io.BytesIO(r.content)) as archive:
        # The archive contains a single CSV file (top-1m.csv).
        csv_name = archive.namelist()[0]
        text = archive.read(csv_name).decode()

    ranked = {}

    for row in text.splitlines():
        parts = row.split(",")

        if len(parts) < 2:
            continue

        try:
            rank = int(parts[0])
        except ValueError:
            continue

        if rank > limit:
            continue

        domain = parts[1]

        if not domain:
            continue

        domain = domain.lower()

        # Lower rank means a more popular domain, so keep the best (lowest).
        if domain not in ranked or rank < ranked[domain]:
            ranked[domain] = rank

    return ranked


def main():
    dirs = get_country_dirs()

    ranked = {}
    processed_countries = 0
    files_name = ''

    for dir_url in dirs:
        csv_url, files_name = get_latest_country_file(dir_url)

        if not csv_url:
            continue

        for domain, rank in download_ranked_domains(csv_url).items():
            if rank <= TOPK_CRUX:
                if domain not in ranked or rank < ranked[domain]:
                    ranked[domain] = rank

        processed_countries += 1

    crux_domains = set(ranked)

    # Sort crux domains by crux rank (ascending), breaking ties alphabetically.
    ordered = [
        domain
        for domain, _ in sorted(
            ranked.items(), key=lambda item: (item[1], item[0])
        )
    ]

    # Append the Tranco top 10k domains that are not already covered by crux,
    # sorted by their Tranco rank (ascending), breaking ties alphabetically.
    tranco_ranked = download_tranco_domains(TOPK_TRANCO)

    tranco_only = {
        domain: rank
        for domain, rank in tranco_ranked.items()
        if domain not in crux_domains
    }

    ordered.extend(
        domain
        for domain, _ in sorted(
            tranco_only.items(), key=lambda item: (item[1], item[0])
        )
    )

    Path("data/domains.txt").write_text("\n".join(ordered) + "\n")

    print(
        f"{len(ordered):,} domains written "
        f"({len(crux_domains):,} from crux, "
        f"{len(tranco_only):,} additional from tranco)"
    )

    fname = ""
    if files_name is not None:
        fname = files_name.partition('.')[0]

    metadata = {
        "processed_countries": processed_countries,
        "crux_domains": len(crux_domains),
        "tranco_domains": len(tranco_only),
        "total_domains": len(ordered),
        "files_date": fname
    }

    with open("data/crux_metadata.json", "w") as fp:
        json.dump(metadata, fp, indent=2)


if __name__ == "__main__":
    main()
