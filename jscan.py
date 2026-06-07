#!/usr/bin/env python3

import re
import argparse
import requests
import os
from urllib.parse import urlparse

# ----------------------------
# Patterns
# ----------------------------

REGEX_PATTERNS = {
    "Google_API_Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Google_Captcha": r"6L[0-9A-Za-z\-_]{38}|^6[0-9A-Za-z\-_]{39}$",
    "AWS_Access_Key": r"A[SK]IA[0-9A-Z]{16}",
    "AWS_MWS_Token": r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "Facebook_Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Mailgun_API_Key": r"key-[0-9a-zA-Z]{32}",
    "Twilio_API_Key": r"SK[0-9a-fA-F]{32}",
    "Stripe_Live_Key": r"sk_live_[0-9a-zA-Z]{24}",
    "JWT_Token": r"ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Bearer_JWT": r"Bearer [A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Email_Address": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "URL": r"https?://(?:www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[\w\-._~:/?#\[\]@!$&'()*+,;=]*)?",
}

RELATIVE_URL_REGEX = r"""(?:
    (?:"|')
    (?P<q>/[a-zA-Z0-9_\-/?.=&%#]+)
    (?:"|')
|
    (?<!["'=])
    (?P<n>/[a-zA-Z0-9_\-/?.=&%#]+)
)"""

# ----------------------------
# Scope logic
# ----------------------------

def parse_scopes(scope_string):
    if not scope_string:
        return []

    return [s.strip().lower() for s in scope_string.split(",") if s.strip()]


def derive_scope_from_url(url):
    try:
        host = urlparse(url).hostname
        if not host:
            return []

        parts = host.split(".")
        if len(parts) >= 2:
            root = ".".join(parts[-2:])
            return [f"*.{root}"]

        return [host]
    except:
        return []


def url_in_scope(url, scopes):
    try:
        host = urlparse(url).hostname
        if not host:
            return False

        host = host.lower()

        for scope in scopes:
            scope = scope.lower()

            if scope.startswith("*."):
                base = scope[2:]
                if host == base or host.endswith("." + base):
                    return True
            else:
                if host == scope:
                    return True

        return False

    except:
        return False


def resolve_url(base, path):
    if not base:
        return None
    return base.rstrip("/") + "/" + path.lstrip("/")


# ----------------------------
# Scanner
# ----------------------------

def scan_text_for_secrets(text, filename, patterns, scopes=None, base_url=None, debug=False):
    findings = []
    scopes = scopes or []

    url_pattern = re.compile(patterns["URL"])
    rel_pattern = re.compile(RELATIVE_URL_REGEX, re.VERBOSE)

    seen = set()

    # -------------------------
    # 1. NORMAL SECRETS (NO FILTER)
    # -------------------------
    for name, regex in patterns.items():
        if name in ["URL"]:
            continue  # handled separately

        pattern = re.compile(regex)

        for match in pattern.finditer(text):
            value = match.group(0)

            if value not in seen:
                seen.add(value)
                findings.append((name, value))

    # -------------------------
    # 2. ABSOLUTE URLS (SCOPED)
    # -------------------------
    for m in url_pattern.finditer(text):
        url = m.group(0)

        if scopes and not url_in_scope(url, scopes):
            continue

        if url not in seen:
            seen.add(url)
            findings.append(("URL", url))

    # -------------------------
    # 3. RELATIVE URLS (SCOPED + RESOLVED)
    # -------------------------
    for m in rel_pattern.finditer(text):
        path = m.group("q") or m.group("n")
        if not path:
            continue

        full = resolve_url(base_url, path)
        if not full:
            continue

        if scopes and not url_in_scope(full, scopes):
            continue

        if full not in seen:
            seen.add(full)
            findings.append(("RELATIVE_URL", full))

    # -------------------------
    # OUTPUT
    # -------------------------
    if findings:
        print(f"\n🔍 Findings in: {filename}")

        for name, value in findings:
            print(f"  - {name}: {value}")

    return findings

def scan_local_file(path, patterns, scopes=None, base_url=None, debug=False):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        scan_text_for_secrets(text, path, patterns, scopes, base_url, debug)
    except Exception as e:
        print(f"⚠️ Could not open {path}: {e}")


def scan_remote_file(url, patterns, scopes=None, base_url=None, debug=False):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            scan_text_for_secrets(r.text, url, patterns, scopes, base_url, debug)
        else:
            print(f"⚠️ HTTP {r.status_code} for {url}")
    except Exception as e:
        print(f"⚠️ Failed: {url} -> {e}")


# ----------------------------
# Main
# ----------------------------

def main():
    parser = argparse.ArgumentParser(description="JS secret & endpoint scanner")

    parser.add_argument("-i", "--input", type=str)
    parser.add_argument("-l", "--list", type=str)

    parser.add_argument("-s", "--scope", help="*.company.com,*.test.com")
    parser.add_argument("--base", help="Base URL for resolving relative paths")
    parser.add_argument("--debug", action="store_true")

    parser.add_argument("--include")
    parser.add_argument("--exclude")
    parser.add_argument("--list-patterns", action="store_true")

    args = parser.parse_args()

    if args.list_patterns:
        for k, v in REGEX_PATTERNS.items():
            print(f"{k}: {v}")
        return

    if not args.input and not args.list:
        parser.error("Provide -i or -l")

    scopes = parse_scopes(args.scope)

    if args.input and args.input.startswith("http") and not scopes:
        scopes = derive_scope_from_url(args.input)
        if scopes:
            print(f"[*] Auto scope: {scopes}")

    if not args.base and args.input and args.input.startswith("http"):
        args.base = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(args.input))

    patterns = REGEX_PATTERNS

    if args.input:
        if args.input.startswith("http"):
            scan_remote_file(args.input, patterns, scopes, args.base, args.debug)
        elif os.path.isfile(args.input):
            scan_local_file(args.input, patterns, scopes, args.base, args.debug)

    if args.list:
        with open(args.list, "r") as f:
            for line in f:
                t = line.strip()
                if t.startswith("http"):
                    scan_remote_file(t, patterns, scopes, args.base, args.debug)
                elif os.path.isfile(t):
                    scan_local_file(t, patterns, scopes, args.base, args.debug)


if __name__ == "__main__":
    main()
