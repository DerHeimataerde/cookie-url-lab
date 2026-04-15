#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from typing import Dict, List
from urllib.parse import urljoin

import requests

DEFAULT_BASE = "http://127.0.0.1:8765"
SCENARIOS = [
    "/site/plain?cid=user-123",
    "/site/base64?cid=user-456",
    "/site/split?cid=user-789",
    "/site/lookup?cid=user-999",
    "/site/random",
]


def capture_chain(session: requests.Session, url: str) -> List[dict]:
    events: List[dict] = []
    resp = session.get(url, allow_redirects=True, timeout=5)
    chain = list(resp.history) + [resp]

    for idx, r in enumerate(chain):
        redirect_to = chain[idx + 1].request.url if idx + 1 < len(chain) else None
        sent_cookie_header = r.request.headers.get("Cookie", "")
        cookies_sent: Dict[str, str] = {}
        if sent_cookie_header:
            for part in sent_cookie_header.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies_sent[k] = v

        set_cookies: Dict[str, str] = requests.utils.dict_from_cookiejar(r.cookies)
        events.append(
            {
                "ts": time.time(),
                "request_url": r.request.url,
                "status_code": r.status_code,
                "cookies_sent": cookies_sent,
                "set_cookies": set_cookies,
                "redirect_to": redirect_to,
            }
        )
    return events


def main():
    parser = argparse.ArgumentParser(description="Capture synthetic URL/cookie mapping traces.")
    parser.add_argument("--base", default=DEFAULT_BASE)
    parser.add_argument("--output", default="capture.json")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    session = requests.Session()
    all_events: List[dict] = []
    for _ in range(args.runs):
        for path in SCENARIOS:
            url = urljoin(args.base, path)
            all_events.extend(capture_chain(session, url))

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_events, f, indent=2)
    print(f"Wrote {len(all_events)} events to {args.output}")


if __name__ == "__main__":
    main()
