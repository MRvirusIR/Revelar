# Changelog

## v2.0.0

A full modular rewrite focused on finding the real origin IP behind CDNs/WAFs.

### Added
- Modular Go architecture split into tested packages (`cdn`, `dnsr`, `sources`,
  `favicon`, `asn`, `verify`, `report`, `tools`, `scanner`, `util`).
- Live CDN range feeds (Cloudflare / Fastly / CloudFront) cached 24h, merged with
  a built-in list covering 15+ providers (incl. ArvanCloud, DDoS-Guard, Gcore, Derak).
- 18 passive sources: crt.sh, CertSpotter, HackerTarget, OTX, urlscan, Anubis,
  Wayback, RapidDNS + keyed SecurityTrails, Shodan, Censys, VirusTotal, ViewDNS,
  Netlas, FOFA, ZoomEye, BinaryEdge, Quake (auto-enabled via env vars).
- Active verification: baseline fingerprint (status, title, body SHA-256, SimHash,
  TLS cert SANs) with 0–100 candidate scoring.
- TLS-certificate-on-IP pivoting (works even when HTTP is blocked/altered).
- Alternate Cloudflare-compatible origin ports (8080, 8443, 2053, 2083, …).
- Deep mode (`-active -deep[-asn]`): sweeps SPF networks and candidate ASNs
  (via RIPEstat) to brute-force the origin when the site is fully proxied.
- Shodan-compatible mmh3 favicon-hash pivot.
- ASN/org enrichment (Team Cymru) and ASN-org CDN filtering.
- Native concurrent subdomain brute-force with wildcard detection.
- SPF/MX/NS parsing, modern neon HTML report, JSON output, CSV summary.
- CI (vet + race tests + build) and cross-platform release workflow.

### Changed
- CDN detection now combines IP ranges, reverse DNS, CNAME chains and HTTP headers.
- Replaced the single `script.go` with a proper package layout and CLI.

### Removed
- Dead `dns.bufferover.run` source and the committed binary.
