import gzip
import os
from pathlib import Path
from urllib.parse import urlparse

from utils import RateLimiter, throttled_get

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
        return urlparse(origin).hostname
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

    return latest_url


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


def main():
    dirs = get_country_dirs()

    ranked = {}

    for dir_url in dirs:
        csv_url = get_latest_country_file(dir_url)

        if not csv_url:
            continue

        for domain, rank in download_ranked_domains(csv_url).items():
            if domain not in ranked or rank < ranked[domain]:
                ranked[domain] = rank

    # Sort by crux rank (ascending), breaking ties alphabetically.
    ordered = sorted(ranked.items(), key=lambda item: (item[1], item[0]))

    Path("data/domains.txt").write_text(
        "\n".join(domain for domain, _ in ordered) + "\n"
    )

    print(f"{len(ordered):,} domains written (sorted by crux rank)")


if __name__ == "__main__":
    main()
