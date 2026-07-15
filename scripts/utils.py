import json
from pathlib import Path


def read_set(path):
    p = Path(path)

    if not p.exists():
        return set()

    return {
        line.strip()
        for line in p.read_text().splitlines()
        if line.strip()
    }


def write_sorted_set(path, values):
    Path(path).write_text(
        "\n".join(sorted(values)) + "\n"
    )


def load_state(path):
    p = Path(path)

    if not p.exists():
        return {"cursor": 0}

    return json.loads(p.read_text())


def save_state(path, state):
    Path(path).write_text(
        json.dumps(state, indent=2)
    )
