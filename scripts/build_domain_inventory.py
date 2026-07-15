from urllib.parse import urlparse
import requests

from utils import read_set, write_sorted_set

COUNTRY_INDEX_URL = (
    "https://api.github.com/repos/"
    "InternetHealthReport/crux-top-lists-country/"
    "contents/data/country"
)


def extract_domain(origin):
    try:
        return urlparse(origin).hostname
    except Exception:
        return None


def get_country_files():
    r = requests.get(COUNTRY_INDEX_URL, timeout=60)
    r.raise_for_status()

    files = []

    for item in r.json():
        if item["name"].endswith(".csv"):
            files.append(item["download_url"])

    return files


def download_domains(csv_url):
    print(f"Downloading {csv_url}")

    r = requests.get(csv_url, timeout=120)
    r.raise_for_status()

    domains = set()

    lines = r.text.splitlines()

    for row in lines[1:]:
        parts = row.split(",")

        if not parts:
            continue

        domain = extract_domain(parts[0])

        if domain:
            domains.add(domain.lower())

    return domains


def main():
    inventory = read_set("data/domains.txt")

    files = get_country_files()

    discovered = set()

    for url in files:
        discovered |= download_domains(url)

    inventory |= discovered

    write_sorted_set(
        "data/domains.txt",
        inventory
    )

    print(
        f"{len(discovered):,} domains discovered "
        f"({len(inventory):,} total)"
    )


if __name__ == "__main__":
    main()
