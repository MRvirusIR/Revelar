# Revelar – Origin Reveal PRO

[![Go Version](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![GitHub stars](https://img.shields.io/github/stars/MRvirusIR/revelar?style=social)](https://github.com/MRvirusIR/revelar/stargazers)

---

## 🔹 Overview

**Revelar (Origin Reveal PRO)** is a professional Go-based CLI tool for uncovering **real/origin IP addresses of websites behind CDNs** such as Cloudflare, Akamai, Fastly, Imperva, and AWS CloudFront.

It combines **passive reconnaissance**, **heuristic analysis**, and optional **active verification** to provide **comprehensive reports in JSON and HTML formats**.

---

## ⚙️ Features

- Detects **CDN providers** automatically.
- Collects **DNS records (A, AAAA, MX, Reverse DNS)**.
- Extracts SSL **Subject Alternative Names (SANs)**.
- Integrates with optional external tools (`subfinder`, `amass`, `dnsx`, `httpx`, `nuclei`).
- Filters **CDN IP ranges** to isolate real origin candidates.
- **Active verification** engine:
  - Compares **status codes**
  - Extracts **page titles**
  - Matches **server headers**
  - Validates **content hash (SHA256)**
- Generates **detailed JSON** + **HTML reports** per domain.
- User can **selectively enable/disable tools** or run default mode (all tools).
- Supports **custom wordlists** with the `-w` flag (defaults to [SecLists](https://github.com/danielmiessler/SecLists) if installed).

---

## 🛠 Prerequisites

- **Go 1.21+**
- Internet access for passive/active lookups
- (Optional) Installed external tools for enhanced recon:
  - `subfinder`, `amass`, `dnsx`, `httpx`, `nuclei`
- (Optional) A wordlist (e.g., from **SecLists**) for brute-force subdomain discovery

---

## 📥 Installation

### Install via `go install`:

```bash
go install github.com/MRvirusIR/revelar@latest
```
Binary will be available at $GOPATH/bin/revelar (or $HOME/go/bin/revelar).

Run directly from source:
```
git clone https://github.com/MRvirusIR/revelar.git
cd revelar
revelar -d example.com
# OR
go run ./script.go -d example.com
```

---

## 💻 Usage

Passive Scan
```bash
revelar -d example.com
```
Active Verification (requires authorization)
```bash
revelar -d example.com -active
```
Scan Multiple Domains
```bash
revelar -f domains.txt -active
```
Use Custom Wordlist
```bash
revelar -d example.com -w /path/to/wordlist.txt
```
> ⚠️ If -w is not provided, Revelar defaults to a standard wordlist from SecLists (if available).



Selective Tool Control

Enable only specific tools:
```bash
revelar -d example.com -tools=subfinder,dnsx
```
Disable all external tools:
```bash
revelar -d example.com -tools=none
```

---

## 🧩 Flags

| Flag              | Description                                                           |
| ----------------- | --------------------------------------------------------------------- |
| `-d`              | Single domain to scan (e.g., example.com)                             |
| `-f`              | File containing multiple domains                                      |
| `-w`              | Path to custom wordlist (default: SecLists if available)              |
| `-timeout`        | Passive source timeout in seconds (default: 25)                       |
| `-active`         | Enable active verification against candidate IPs                      |
| `-active-timeout` | Timeout for active probes (default: 12)                               |
| `-ua`             | Custom HTTP User-Agent string                                         |
| `-scheme`         | `http` or `https` for active fetch (default: https)                   |
| `-ports`          | Comma-separated ports for probing (default: 80,443)                   |
| `-tools`          | Run only specific tools (comma-separated: subfinder,amass,dnsx,httpx) |
| `-no-tools`       | Skip running external tools                                           |
| `-progress`       | Show/hide step-by-step progress logs (default: true)                  |




---

## 📂 Output

Reports are saved per-domain under results/<domain>/

Example:
```text
results/example.com/
  ├─ results.json   # structured JSON
  ├─ results.html   # HTML report
  ├─ subfinder.log
  ├─ amass.log
  ├─ dnsx.log
  └─ httpx.log
```


---

## ⚖️ Legal Notice

This tool is for authorized security testing only.
Do NOT scan systems without explicit permission.
The authors assume no liability for misuse.


---

## 🔗 Links

Repository: https://github.com/MRvirusIR/revelar

[![Telegram](https://www.freepnglogos.com/uploads/telegram-logo-png-0.png)](#): [![BugCod3](BugCod3)](https://t.me/BugCod3) | [![Exploit_Forge](Exploit_Forge)](https://t.me/Exploit_Forge)

License: MIT

---

## 🎬 Demo

[![asciicast](https://asciinema.org/a/8NYbe08LbPzknFG7CZFwn7NP6.svg)](https://asciinema.org/a/8NYbe08LbPzknFG7CZFwn7NP6)

[![picture](https://mrvirusir.ir/Image/cdn-finder-01.png)]([https://asciinema.org/a/8NYbe08LbPzknFG7CZFwn7NP6](https://mrvirusir.ir/Image/cdn-finder-01.png))

[![picture](https://mrvirusir.ir/Image/cdn-finder-02.png)]([https://asciinema.org/a/8NYbe08LbPzknFG7CZFwn7NP6](https://mrvirusir.ir/Image/cdn-finder-02.png))

---
