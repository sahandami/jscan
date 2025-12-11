#!/usr/bin/env python3
import re
import argparse
import requests
import os
from textwrap import shorten

# --- SECRET PATTERNS FROM THE REPO ---
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
    "URL": r"https?://(?:www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[\w\-._~:/?#\[\]@!$&'()*+,;=]*)?",
}

def print_pattern_table():
    """Print all regex patterns in a clean table."""
    print("\nAvailable Regex Patterns:\n")

    name_width = max(len(name) for name in REGEX_PATTERNS.keys())
    regex_width = max(len(p) for p in REGEX_PATTERNS.values())

    header = f"+{'-'*(name_width+2)}+{'-'*(regex_width+2)}+"
    print(header)
    print(f"| {'Pattern Name'.ljust(name_width)} | {'Regex Pattern'.ljust(regex_width)} |")
    print(header)

    for name, pattern in REGEX_PATTERNS.items():
        print(f"| {name.ljust(name_width)} | {pattern.ljust(regex_width)} |")

    print(header)
    print()

def filter_patterns(include, exclude):
    """Return filtered regex dict based on include/exclude rules."""
    filtered = {}

    for name, pattern in REGEX_PATTERNS.items():
        if include and name not in include:
            continue
        if exclude and name in exclude:
            continue
        filtered[name] = pattern

    return filtered


def scan_text_for_secrets(text, filename, patterns, debug=False):
    """Scan text and print all matching regex patterns."""
    findings = []

    for name, regex in patterns.items():
        pattern = re.compile(regex)
        for match in pattern.finditer(text):
            findings.append((name, regex, match.group(0)))

    if findings:
        print(f"\n🔍 Secrets found in: {filename}")
        for name, regex, secret in findings:
            print(f"  - {name}: {secret}")
            if debug:
                print(f"      ↳ Regex matched: {regex}")

    return findings


def scan_local_file(path, patterns, debug=False):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        scan_text_for_secrets(text, path, patterns, debug)
    except Exception as e:
        print(f"⚠️ Could not open {path}: {e}")


def scan_remote_file(url, patterns, debug=False):
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            scan_text_for_secrets(r.text, url, patterns, debug)
        else:
            print(f"⚠️ HTTP {r.status_code} for {url}")
    except Exception as e:
        print(f"⚠️ Failed to fetch {url}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Scan JS for leaked secrets/api keys")

    parser.add_argument("-i", "--input", help="Single file path or URL", type=str)
    parser.add_argument("-l", "--list", help="List of file paths or URLs", type=str)

    parser.add_argument("--debug", action="store_true", help="Show matched regex patterns")

    parser.add_argument("--include", help="Only run specific regex names (comma separated)")
    parser.add_argument("--exclude", help="Exclude specific regex names (comma separated)")

    parser.add_argument("--list-patterns", action="store_true", help="Show all regex patterns in a table")

    args = parser.parse_args()

    # If user wants to display all patterns
    if args.list_patterns:
        print_pattern_table()
        return

    # No scanning input provided
    if not args.input and not args.list:
        parser.error("Please provide -i, -l OR --list-patterns")

    include = args.include.split(",") if args.include else []
    exclude = args.exclude.split(",") if args.exclude else []

    filtered_patterns = filter_patterns(include, exclude)

    if args.input:
        target = args.input.strip()
        if target.startswith("http"):
            scan_remote_file(target, filtered_patterns, args.debug)
        elif os.path.isfile(target):
            scan_local_file(target, filtered_patterns, args.debug)
        else:
            print(f"⚠️ Invalid file/URL: {target}")

    if args.list:
        with open(args.list, "r") as f:
            for line in f:
                target = line.strip()
                if not target:
                    continue
                if target.startswith("http"):
                    scan_remote_file(target, filtered_patterns, args.debug)
                elif os.path.isfile(target):
                    scan_local_file(target, filtered_patterns, args.debug)
                else:
                    print(f"⚠️ Skipping invalid: {target}")


if __name__ == "__main__":
    main()
