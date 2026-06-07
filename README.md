# jscan 🔍 SecretScanner — Multi-Pattern JavaScript Secret Finder
SecretScanner is a powerful Python 3 tool designed to scan JavaScript files for leaked API keys, tokens, credentials, and other secrets.
It uses the regex database from:

➡️ https://github.com/Lu3ky13/Search-for-all-leaked-keys-secrets-using-one-regex-

This tool supports:

✔ Single file scanning (-i file.js)

✔ Directory scanning (-d folder/)

✔ List-based scanning (-l files.txt)

✔ Debug mode → shows which regex name matched a secret

✔ Include / exclude regex pattern names

✔ List all patterns in a table

✔ Output results to file

✔ Usable as a global system command

✔ Can be turned into a standalone binary (no Python needed)


# 📥 Installation
1. Clone the repository
```bash
git clone https://github.com/sahandami/jscan.git
cd jscan
```
# ⚙️ Usage
```bash
> jscan -h
usage: jscan [-h] [-i INPUT] [-l LIST] [-s SCOPE] [--base BASE]
             [--debug] [--include INCLUDE] [--exclude EXCLUDE]
             [--list-patterns]

Scan JS files for leaked secrets and endpoints

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Single file path or URL
  -l LIST, --list LIST  List of file paths or URLs
  -s SCOPE, --scope SCOPE
                        Comma separated scope list (*.company.com,*.test.com)
  --base BASE           Base URL for resolving relative endpoints
  --debug               Show matched regex patterns
  --include INCLUDE     Only run specific regex names (comma separated)
  --exclude EXCLUDE     Exclude specific regex names (comma separated)
  --list-patterns      Show all regex patterns in a table
```
# 🔗 Chaining With Other Recon Tools

```bash
> echo "https://hackerone.com" | subjs | tee -a js.txt
> jscan -l js.txt

> jscan -i app.js --base https://company.com -s "*.company.com"
```
