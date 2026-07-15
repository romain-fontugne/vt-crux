import json
import time
from pathlib import Path

import requests


class RateLimiter:
    """Simple rate limiter enforcing a minimum interval between calls."""

    def __init__(self, min_interval):
        self.min_interval = min_interval
        self._last_call = 0.0

    def wait(self):
        if self.min_interval <= 0:
            return

        elapsed = time.monotonic() - self._last_call
        remaining = self.min_interval - elapsed

        if remaining > 0:
            time.sleep(remaining)

        self._last_call = time.monotonic()


def throttled_get(
    url,
    limiter=None,
    max_retries=5,
    backoff=2.0,
    **kwargs,
):
    """Perform a GET request while throttling and retrying on errors.

    - ``limiter`` enforces a minimum delay between successive requests.
    - On an HTTP error (or connection error) the call is retried with an
      exponential backoff, honouring the ``Retry-After`` header when present.
    """
    attempt = 0

    while True:
        if limiter is not None:
            limiter.wait()

        try:
            r = requests.get(url, **kwargs)
            r.raise_for_status()
            return r
        except requests.exceptions.RequestException as exc:
            attempt += 1

            if attempt > max_retries:
                raise

            wait_seconds = backoff * (2 ** (attempt - 1))

            # Honour the server-provided Retry-After header when available.
            response = getattr(exc, "response", None)

            if response is not None:
                retry_after = response.headers.get("Retry-After")

                if retry_after:
                    try:
                        wait_seconds = max(wait_seconds, float(retry_after))
                    except ValueError:
                        pass

            print(
                f"Request to {url} failed ({exc}); "
                f"retrying in {wait_seconds:.1f}s "
                f"(attempt {attempt}/{max_retries})"
            )

            time.sleep(wait_seconds)


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
