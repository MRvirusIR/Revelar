# CDN-Finder

CDN-Finder is a Go-based tool to discover real/origin IPs of websites behind CDNs like Cloudflare, CloudFront, etc.

---

## Installation

```bash
go install github.com/MRvirusIR/cdn-finder@latest
```

---

## Usage

```bash
cdn-finder -d example.com
cdn-finder -f domains.txt
cdn-finder -d example.com -active
```

Logs are saved in `cdn-finder.log`.
