#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import re
from collections import defaultdict
from typing import Iterable, List, Tuple
from urllib.parse import parse_qsl, unquote, urlparse


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freqs = [s.count(ch) / len(s) for ch in set(s)]
    return -sum(p * math.log2(p) for p in freqs)


def safe_b64decode(s: str):
    s2 = s + "=" * ((4 - len(s) % 4) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(s2)
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return raw.hex()
        except Exception:
            pass
    return None


def safe_hexdecode(s: str):
    if re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) % 2 == 0:
        try:
            raw = bytes.fromhex(s)
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                return raw.hex()
        except Exception:
            pass
    return None


def candidate_transforms(s: str) -> set[Tuple[str, str]]:
    out: set[Tuple[str, str]] = set()
    dec = unquote(s)
    out.add(("identity", s))
    out.add(("urldecode", dec))
    b64 = safe_b64decode(dec)
    if b64:
        out.add(("b64", b64))
    hx = safe_hexdecode(dec)
    if hx:
        out.add(("hex", hx))

    for sep in [".", "_", "-", "~", "|", ":"]:
        if sep in dec:
            parts = [p for p in dec.split(sep) if p]
            for i, p in enumerate(parts):
                out.add((f"split:{sep}:{i}", p))
                p_b64 = safe_b64decode(p)
                if p_b64:
                    out.add((f"split+b64:{sep}:{i}", p_b64))

    for n in range(1, min(len(dec), 9)):
        out.add((f"strip_prefix:{n}", dec[n:]))
        out.add((f"strip_suffix:{n}", dec[:-n]))

    return out


def similarity(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0
    aset, bset = set(a), set(b)
    jaccard = len(aset & bset) / max(1, len(aset | bset))
    len_score = 1 - abs(len(a) - len(b)) / max(len(a), len(b))
    ent_score = 1 - abs(shannon_entropy(a) - shannon_entropy(b)) / max(1.0, shannon_entropy(a), shannon_entropy(b))
    prefix = 0.0
    for n in (4, 6, 8):
        if len(a) >= n and len(b) >= n and a[:n] == b[:n]:
            prefix = max(prefix, n / 8)
    return 0.35 * jaccard + 0.25 * len_score + 0.20 * ent_score + 0.20 * prefix


def extract_url_tokens(url: str):
    toks = []
    p = urlparse(url)
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        toks.append(("query", k, v))
    for i, seg in enumerate([x for x in p.path.split("/") if x]):
        toks.append(("path", str(i), seg))
    if p.fragment:
        toks.append(("fragment", "", p.fragment))
    return toks


def score_pair(token: str, cookie_value: str):
    best = None
    for tname, transformed in candidate_transforms(token):
        score = similarity(transformed, cookie_value)
        if transformed == cookie_value:
            score += 1.0
        if transformed in cookie_value or cookie_value in transformed:
            score += 0.35
        sha = hashlib.sha256(transformed.encode()).hexdigest()
        if len(cookie_value) >= 8 and sha[:8] in cookie_value:
            score += 0.25
        candidate = {
            "transform": tname,
            "transformed": transformed,
            "score": round(score, 3),
        }
        if best is None or candidate["score"] > best["score"]:
            best = candidate
    return best


def detect(events: List[dict], threshold: float = 0.95):
    raw_findings = []
    for i, ev in enumerate(events):
        url_tokens = extract_url_tokens(ev["request_url"])
        cookies = dict(ev.get("set_cookies", {}))
        if not cookies:
            continue
        for loc, name, tok in url_tokens:
            for ck_name, ck_val in cookies.items():
                best = score_pair(tok, ck_val)
                if best and best["score"] >= threshold:
                    raw_findings.append(
                        {
                            "event_index": i,
                            "request_url": ev["request_url"],
                            "url_component": loc,
                            "param_or_index": name,
                            "token": tok,
                            "cookie_name": ck_name,
                            "cookie_value": ck_val,
                            **best,
                        }
                    )

    grouped = defaultdict(list)
    for f in raw_findings:
        key = (f["url_component"], f["param_or_index"], f["cookie_name"], f["transform"])
        grouped[key].append(f)

    ranked = []
    for key, vals in grouped.items():
        avg_score = sum(v["score"] for v in vals) / len(vals)
        ranked.append(
            {
                "mapping": {
                    "url_component": key[0],
                    "param_or_index": key[1],
                    "cookie_name": key[2],
                    "transform": key[3],
                },
                "count": len(vals),
                "avg_score": round(avg_score, 3),
                "examples": vals[:3],
            }
        )
    ranked.sort(key=lambda x: (x["count"], x["avg_score"]), reverse=True)
    return ranked


def main():
    parser = argparse.ArgumentParser(description="Detect candidate URL-to-cookie mappings from captured traces.")
    parser.add_argument("capture_file")
    parser.add_argument("--threshold", type=float, default=0.95)
    parser.add_argument("--output", default="findings.json")
    args = parser.parse_args()

    with open(args.capture_file, "r", encoding="utf-8") as f:
        events = json.load(f)
    findings = detect(events, threshold=args.threshold)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)
    print(json.dumps(findings[:10], indent=2))
    print(f"Wrote {len(findings)} ranked findings to {args.output}")


if __name__ == "__main__":
    main()
