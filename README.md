# CDN Finder – Origin Reveal PRO

[![Go Version](https://img.shields.io/badge/go-1.21+-blue)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![GitHub stars](https://img.shields.io/github/stars/MRvirusIR/cdn-finder?style=social)](https://github.com/MRvirusIR/cdn-finder/stargazers)

---

## 🔹 Overview

**CDN Finder / Origin Reveal PRO** is a professional Go-based CLI tool for uncovering **real/origin IP addresses of websites behind CDNs** such as Cloudflare, Akamai, Fastly, Imperva, and AWS CloudFront.  

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

---

## 🛠 Prerequisites

- **Go 1.21+**
- Internet access for passive/active lookups
- (Optional) Installed external tools for enhanced recon:
  - `subfinder`, `amass`, `dnsx`, `httpx`, `nuclei`

---

## 📥 Installation

### Install via `go install`:

```bash
go install github.com/MRvirusIR/cdn-finder@latest
‍‍‍```
Binary will be available at $GOPATH/bin/cdn-finder (or $HOME/go/bin/cdn-finder).

Run from source:
```bash
git clone https://github.com/MRvirusIR/cdn-finder.git
cd cdn-finder
go run ./script.go -d example.com
```

---

💻 Usage

Passive Scan
```bash
cdn-finder -d example.com
```
Active Verification (requires authorization)
```bash
cdn-finder -d example.com -active
```
Scan Multiple Domains
```bash
cdn-finder -f domains.txt -active
```
Selective Tool Control

You can enable/disable external tools individually:
```bash
cdn-finder -d example.com -tools=subfinder,dnsx
```
Or disable all:
```bash
cdn-finder -d example.com -no-tools
```

---

🧩 Flags

Flag	Description

-d	Single domain to scan (e.g., example.com)
-f	File containing multiple domains
-timeout	Passive source timeout in seconds (default: 25)
-active	Enable active verification against candidate IPs
-active-timeout	Timeout for active probes (default: 12)
-ua	Custom HTTP User-Agent string
-scheme	http or https for active fetch (default: https)
-ports	Comma-separated ports for probing (default: 80,443)
-no-tools	Skip running external tools
-tools	Run only specific tools (comma-separated: subfinder,amass,dnsx,httpx)



---

📂 Output

Reports are saved per-domain under results/<domain>/

Files generated:

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

⚖️ Legal Notice

This tool is for authorized security testing only.
Do NOT scan systems without explicit permission.
The authors assume no liability for misuse.


---

🔗 Links

Repository: https://github.com/MRvirusIR/cdn-finder

Telegram: BugCod3 | Exploit Forge

License: MIT



---

🎬 Demo

Coming soon – screenshots and sample reports.
