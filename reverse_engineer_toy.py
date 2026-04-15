#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from urllib.parse import parse_qsl, urlparse


def summarize_pairs(events, cookie_name: str, param_name: str):
    pairs = []
    for ev in events:
        params = dict(parse_qsl(urlparse(ev["request_url"]).query, keep_blank_values=True))
        if param_name in params and cookie_name in ev.get("set_cookies", {}):
            pairs.append((params[param_name], ev["set_cookies"][cookie_name]))
    return pairs


def main():
    parser = argparse.ArgumentParser(description="Summarize toy URL/cookie pairs for your local lab only.")
    parser.add_argument("capture_file")
    parser.add_argument("cookie_name")
    parser.add_argument("param_name")
    args = parser.parse_args()

    with open(args.capture_file, "r", encoding="utf-8") as f:
        events = json.load(f)

    pairs = summarize_pairs(events, args.cookie_name, args.param_name)
    if not pairs:
        print("No matching pairs found.")
        return

    by_len = Counter(len(p[0]) for p in pairs)
    print("Token lengths:", dict(by_len))
    print("Examples:")
    for url_tok, cookie_val in pairs[:10]:
        print(f"  url={url_tok!r} -> cookie={cookie_val!r}")

    exact = sum(1 for u, c in pairs if u == c)
    contains = sum(1 for u, c in pairs if u in c or c in u)
    print(f"Exact equal pairs: {exact}/{len(pairs)}")
    print(f"Substring-related pairs: {contains}/{len(pairs)}")
    print("This helper is intentionally limited to your synthetic lab data.")


if __name__ == "__main__":
    main()
