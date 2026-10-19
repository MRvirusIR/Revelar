#!/usr/bin/env bash
# Optional helpers. Revelar works fully without any of these; install them for extra
# coverage with:  Revelar -tools -brute -w SecLists/Discovery/DNS/subdomains-top1million-5000.txt
set -euo pipefail

command -v go >/dev/null || { echo "[x] Go is required: https://go.dev/dl/"; exit 1; }

echo "[*] Installing subfinder (optional) ..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo "[!] subfinder failed (optional)"

echo "[*] Installing amass (optional) ..."
go install -v github.com/owasp-amass/amass/v4/...@master || echo "[!] amass failed (optional)"

echo "[*] Downloading SecLists DNS wordlists (optional) ..."
mkdir -p SecLists/Discovery/DNS
base="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS"
for f in subdomains-top1million-5000.txt subdomains-top1million-110000.txt; do
  curl -fsSL "$base/$f" -o "SecLists/Discovery/DNS/$f" || echo "[!] could not fetch $f"
done

echo "[+] Done. Ensure \$(go env GOPATH)/bin is on your PATH."
