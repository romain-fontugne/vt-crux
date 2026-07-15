import json
import gzip
import os

from datetime import datetime

import requests

from utils import (
    read_set,
    load_state,
    save_state,
)

VT_KEY = os.environ["VT_API_KEY"]

BATCH_SIZE = 500

HEADERS = {
    "x-apikey": VT_KEY
}

VT_URL = (
    "https://www.virustotal.com/api/v3/domains/{}"
)


def fetch_domain(domain):
    r = requests.get(
        VT_URL.format(domain),
        headers=HEADERS,
        timeout=30,
    )

    if r.status_code == 200:
        return r.json()

    return {
        "domain": domain,
        "status": r.status_code,
        "error": True
    }


def main():
    domains = sorted(
        read_set("data/domains.txt")
    )

    queried = read_set(
        "data/queried.txt"
    )

    state = load_state(
        "data/state.json"
    )

    cursor = state["cursor"]

    batch = domains[
        cursor:cursor + BATCH_SIZE
    ]

    if not batch:
        print("No domains remaining")
        return

    today = datetime.utcnow().strftime(
        "%Y-%m"
    )

    output_file = (
        f"data/vt/{today}.jsonl.gz"
    )

    os.makedirs(
        "data/vt",
        exist_ok=True
    )

    processed = 0

    with gzip.open(output_file, "at") as fp:

        for domain in batch:

            if domain in queried:
                continue

            print(domain)

            result = fetch_domain(domain)

            record = {
                "domain": domain,
                "collected_at": datetime.utcnow()
                .isoformat(),
                "response": result
            }

            fp.write(
                json.dumps(record)
            )

            fp.write("\n")

            queried.add(domain)

            processed += 1

    cursor += len(batch)

    state["cursor"] = cursor

    state["last_run"] = (
        datetime.utcnow().isoformat()
    )

    save_state(
        "data/state.json",
        state
    )

    with open(
        "data/queried.txt",
        "w"
    ) as fp:

        for domain in sorted(queried):
            fp.write(domain + "\n")

    metadata = {
        "cursor": cursor,
        "processed_this_run": processed,
        "total_domains": len(domains),
        "remaining_domains":
            max(
                0,
                len(domains) - cursor
            )
    }

    with open(
        "data/metadata.json",
        "w"
    ) as fp:
        json.dump(
            metadata,
            fp,
            indent=2
        )


if __name__ == "__main__":
    main()
