#!/usr/bin/env python3
import os
import sys
import json
import argparse
import subprocess
import urllib.parse
import urllib.request
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

ST_BASE = "https://api.securitytrails.com/v1"

ANSI_RESET = "\033[0m"
ANSI_RED = "\033[31m"
ANSI_BLUE = "\033[34m"
ANSI_YELLOW = "\033[33m"


RED_KEYWORDS = [
    "cloudfront",
    "impervadns",
    "edgecastcdn",
    "fastly",
    "ioriveredge",
    "edgekey",
    "cloudflare",
]

BLUE_KEYWORDS = [
    "vercel-dns",
    "adobeaemcloud",
    "azurewebsites",
    "amazonaws",
]

YELLOW_KEYWORDS = [
    "api",
]


def run_cmd(cmd: list[str], timeout: int = 12) -> str:
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if p.returncode != 0:
        return ""
    return p.stdout.strip()


def http_get_json(url: str, headers: dict[str, str], timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read().decode("utf-8", errors="replace")
        return json.loads(data)


def st_list_subdomains(apex: str, api_key: str, children_only: bool, include_inactive: bool) -> list[str]:
    apex = apex.strip().lower().strip(".")
    params = {
        "children_only": "true" if children_only else "false",
        "include_inactive": "true" if include_inactive else "false",
    }
    url = f"{ST_BASE}/domain/{apex}/subdomains?{urllib.parse.urlencode(params)}"

    headers = {
        "APIKEY": api_key,
        "Accept": "application/json",
        "User-Agent": "MetaDIG/1.0",
    }

    data = http_get_json(url, headers=headers)
    subs = data.get("subdomains", []) or []

    fqdn_list: list[str] = []
    for s in subs:
        s = (s or "").strip().strip(".")
        if s:
            fqdn_list.append(f"{s}.{apex}".lower())

    seen = set()
    out: list[str] = []
    for f in fqdn_list:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def dig_answers(name: str) -> list[dict]:
    out = run_cmd(["dig", "+noall", "+answer", name], timeout=12)
    if not out:
        return []

    answers: list[dict] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        try:
            ttl = int(parts[1])
        except ValueError:
            ttl = None
        rr_type = parts[3].upper()
        rdata = " ".join(parts[4:]).strip()
        answers.append({"type": rr_type, "ttl": ttl, "value": rdata})
    return answers


def cymru_asn(ip: str) -> dict:
    out = run_cmd(["whois", "-h", "whois.cymru.com", "-v", ip], timeout=12)
    if not out:
        return {}

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    if len(lines) < 2:
        return {}

    cols = [c.strip() for c in lines[1].split("|")]
    if len(cols) < 7:
        return {}

    return {"asn": cols[0], "cc": cols[3], "as_name": cols[6]}


def summarize_fqdn(fqdn: str, do_asn: bool) -> str:
    answers = dig_answers(fqdn)

    cnames = [a for a in answers if a["type"] == "CNAME"]
    arecs = [a for a in answers if a["type"] == "A"]

    cname_part = f"CNAME {cnames[0]['value']}" if cnames else ""

    a_parts: list[str] = []
    for a in arecs:
        ip = a["value"]
        ttl = a["ttl"]
        extra = ""
        if do_asn and ip:
            info = cymru_asn(ip)
            if info:
                extra = f"{info.get('cc','')} {info.get('as_name','')} AS{info.get('asn','')}"
        if ttl is None:
            a_parts.append(f"A {ip} {extra}".strip())
        else:
            a_parts.append(f"TTL {ttl} A {ip} {extra}".strip())

    a_blob = " ; ".join(a_parts)
    bits = [fqdn]
    if cname_part:
        bits.append(cname_part)
    if a_blob:
        bits.append(a_blob)
    return " ".join(bits).strip()


def _build_color_patterns() -> list[tuple[re.Pattern, str]]:
    patterns: list[tuple[re.Pattern, str]] = []

    for kw in sorted(RED_KEYWORDS, key=len, reverse=True):
        patterns.append((re.compile(re.escape(kw), re.IGNORECASE), ANSI_RED))

    for kw in sorted(BLUE_KEYWORDS, key=len, reverse=True):
        patterns.append((re.compile(re.escape(kw), re.IGNORECASE), ANSI_BLUE))

    # Put api last so it does not interfere with longer matches
    for kw in sorted(YELLOW_KEYWORDS, key=len, reverse=True):
        patterns.append((re.compile(re.escape(kw), re.IGNORECASE), ANSI_YELLOW))

    return patterns


COLOR_PATTERNS = _build_color_patterns()
ALL_KEYWORDS_ORDERED = RED_KEYWORDS + BLUE_KEYWORDS + YELLOW_KEYWORDS


def colorize(text: str) -> str:
    # Apply patterns in order. This can recolor already colored text if keywords overlap.
    # Ordering reduces annoying cases, but does not eliminate all overlaps.
    out = text
    for pattern, color in COLOR_PATTERNS:
        out = pattern.sub(lambda m: f"{color}{m.group(0)}{ANSI_RESET}", out)
    return out


def update_freq(freq: dict[str, int], text: str) -> None:
    lowered = text.lower()
    for kw in ALL_KEYWORDS_ORDERED:
        if kw.lower() in lowered:
            freq[kw] = freq.get(kw, 0) + 1


def main():
    ap = argparse.ArgumentParser(description="SecurityTrails subdomains → dig CNAME/A → optional ASN enrichment, colored output, keyword stats")
    ap.add_argument("apex", help="Apex domain, e.g. accor.com")
    ap.add_argument("--api-key", default=os.getenv("SECURITYTRAILS_APIKEY", ""), help="SecurityTrails API key or env SECURITYTRAILS_APIKEY")
    ap.add_argument("--children-only", action="store_true")
    ap.add_argument("--include-inactive", action="store_true")
    ap.add_argument("--no-asn", action="store_true")
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if not args.api_key:
        print("Missing API key. Use --api-key or set SECURITYTRAILS_APIKEY.", file=sys.stderr)
        sys.exit(2)

    subs = st_list_subdomains(args.apex, args.api_key, args.children_only, args.include_inactive)
    if args.limit and args.limit > 0:
        subs = subs[: args.limit]

    if not subs:
        print("No subdomains returned by SecurityTrails.", file=sys.stderr)
        sys.exit(1)

    do_asn = not args.no_asn

    results: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(summarize_fqdn, fqdn, do_asn): fqdn for fqdn in subs}
        for fut in as_completed(futs):
            line = fut.result()
            if not line:
                continue
            name, *rest = line.split(" ", 1)
            rest = rest[0] if rest else ""
            results.append((name, rest))

    results.sort(key=lambda x: x[0])

    # Dynamic column width: minimum 40, maximum 90
    width = 40
    if results:
        width = max(width, min(90, max(len(n) for n, _ in results) + 2))

    freq: dict[str, int] = {}

    for name, rest in results:
        update_freq(freq, name)
        update_freq(freq, rest)

        line_plain = f"{name:<{width}} {rest}".rstrip()
        print(colorize(line_plain))

    print()
    print(f"Subdomains count: {len(results)}")

    # Pretty aligned frequency breakdown, in the requested order
    if results:
        key_width = max(20, min(40, max(len(k) for k in ALL_KEYWORDS_ORDERED) + 2))
    else:
        key_width = 20

    for kw in ALL_KEYWORDS_ORDERED:
        print(f"{kw:<{key_width}} {freq.get(kw, 0)}")


if __name__ == "__main__":
    main()