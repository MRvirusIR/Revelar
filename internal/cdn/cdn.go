// Package cdn detects CDN / WAF providers by IP range, reverse DNS, CNAME and HTTP headers.
// Ranges for the largest providers are refreshed live from their official feeds and cached.
package cdn

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// builtin ranges are used as a fallback when live feeds are unavailable.
var builtin = map[string][]string{
	"Cloudflare": {
		"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
		"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
		"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
		"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
		"2a06:98c0::/29", "2c0f:f248::/32",
	},
	"Fastly": {
		"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24",
		"104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17", "146.75.0.0/17", "151.101.0.0/16",
		"157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
		"172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
		"2a04:4e40::/32", "2a04:4e42::/32",
	},
	"Akamai": {
		"23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "72.246.0.0/15", "96.16.0.0/15",
		"96.6.0.0/15", "104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14", "2.16.0.0/13",
		"95.100.0.0/15", "88.221.0.0/16",
	},
	"Amazon CloudFront": {
		"13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14", "13.249.0.0/16", "18.64.0.0/14", "18.154.0.0/15",
		"18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15", "52.46.0.0/18", "52.84.0.0/15", "52.222.128.0/17",
		"54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16", "99.86.0.0/16",
		"108.138.0.0/15", "108.156.0.0/14", "143.204.0.0/16", "204.246.164.0/22", "205.251.192.0/19",
		"2600:9000::/28",
	},
	"Imperva": {
		"199.83.128.0/21", "198.143.32.0/19", "149.126.72.0/21", "103.28.248.0/22", "45.64.64.0/22",
		"185.11.124.0/22", "192.230.64.0/18", "107.154.0.0/16", "45.60.0.0/16", "45.223.0.0/16",
		"131.125.128.0/17", "2a02:e980::/29",
	},
	"Sucuri":    {"192.88.134.0/23", "185.93.228.0/22", "66.248.200.0/22", "208.109.0.0/22", "2a02:fe80::/29"},
	"StackPath": {"151.139.0.0/16", "94.46.144.0/20", "103.66.28.0/22"},
	"ArvanCloud": {
		"185.143.232.0/22", "185.143.236.0/22", "185.143.240.0/22", "185.143.244.0/22", "185.143.248.0/22",
		"185.143.252.0/22", "94.101.182.0/27", "188.229.116.16/29", "92.114.16.80/28", "2.144.3.128/28",
		"89.45.48.64/28", "37.32.16.0/27", "37.32.17.0/27", "37.32.18.0/27", "37.32.19.0/27",
		"185.215.232.0/22", "2a0b:2c40::/29",
	},
	"DDoS-Guard": {"185.178.208.0/22", "190.115.16.0/20", "186.2.160.0/20", "45.10.240.0/22", "2a01:b6c0::/32"},
	"Gcore":      {"92.223.84.0/22", "92.223.88.0/22", "5.188.0.0/16", "2a03:90c0::/32"},
}

var rdnsHints = map[string]string{
	"cloudflare": "Cloudflare", "cloudfront": "Amazon CloudFront", "fastly": "Fastly",
	"akamai": "Akamai", "akamaiedge": "Akamai", "edgesuite": "Akamai", "edgekey": "Akamai",
	"imperva": "Imperva", "incapsula": "Imperva", "stackpath": "StackPath", "sucuri": "Sucuri",
	"cdn77": "CDN77", "cachefly": "CacheFly", "arvancloud": "ArvanCloud", "ddos-guard": "DDoS-Guard",
	"azureedge": "Azure CDN", "azurefd": "Azure Front Door", "gcorelabs": "Gcore", "bunnycdn": "BunnyCDN",
	"b-cdn.net": "BunnyCDN", "netlify": "Netlify", "vercel": "Vercel", "edgecastcdn": "Edgio",
	"llnwd": "Edgio", "kxcdn": "KeyCDN", "derak": "Derak Cloud",
}

type headerRule struct{ header, contains, provider string }

var headerRules = []headerRule{
	{"Cf-Ray", "", "Cloudflare"}, {"Server", "cloudflare", "Cloudflare"},
	{"X-Amz-Cf-Id", "", "Amazon CloudFront"}, {"Via", "cloudfront", "Amazon CloudFront"},
	{"X-Served-By", "cache-", "Fastly"}, {"X-Fastly-Request-Id", "", "Fastly"},
	{"Server", "akamaighost", "Akamai"}, {"X-Akamai-Transformed", "", "Akamai"},
	{"X-Iinfo", "", "Imperva"}, {"X-Cdn", "incapsula", "Imperva"},
	{"X-Sucuri-Id", "", "Sucuri"}, {"Server", "sucuri", "Sucuri"},
	{"Server", "arvancloud", "ArvanCloud"}, {"Ar-Poweredby", "", "ArvanCloud"}, {"Ar-Request-Id", "", "ArvanCloud"},
	{"Server", "ddos-guard", "DDoS-Guard"}, {"X-Azure-Ref", "", "Azure Front Door"},
	{"Server", "bunnycdn", "BunnyCDN"}, {"X-Vercel-Id", "", "Vercel"}, {"X-Nf-Request-Id", "", "Netlify"},
	{"Server", "derak", "Derak Cloud"},
}

type netEntry struct {
	n        *net.IPNet
	provider string
}

// DB is a CDN range database.
type DB struct {
	mu      sync.RWMutex
	entries []netEntry
	Source  string // "builtin" or "live"
}

// NewBuiltin returns a DB with the static ranges only.
func NewBuiltin() *DB {
	db := &DB{Source: "builtin"}
	db.load(builtin)
	return db
}

func (db *DB) load(m map[string][]string) {
	entries := []netEntry{}
	for p, cidrs := range m {
		for _, c := range cidrs {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil {
				entries = append(entries, netEntry{n, p})
			}
		}
	}
	db.mu.Lock()
	db.entries = entries
	db.mu.Unlock()
}

// Lookup returns the provider owning ip, or "".
func (db *DB) Lookup(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, e := range db.entries {
		if e.n.Contains(ip) {
			return e.provider
		}
	}
	return ""
}

// Count returns the number of loaded CIDRs.
func (db *DB) Count() int {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return len(db.entries)
}

// ByHostname returns a provider if a PTR/CNAME hostname hints at a CDN.
func ByHostname(h string) string {
	h = strings.ToLower(h)
	for k, p := range rdnsHints {
		if strings.Contains(h, k) {
			return p
		}
	}
	return ""
}

// ByHeaders returns a provider detected from HTTP response headers.
func ByHeaders(h http.Header) string {
	for _, r := range headerRules {
		v := h.Get(r.header)
		if v == "" {
			continue
		}
		if r.contains == "" || strings.Contains(strings.ToLower(v), r.contains) {
			return r.provider
		}
	}
	return ""
}

type cacheFile struct {
	Fetched time.Time           `json:"fetched"`
	Ranges  map[string][]string `json:"ranges"`
}

func cachePath() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "revelar", "cdn-ranges.json")
}

// Refresh downloads current ranges from official provider feeds (cached for 24h)
// and merges them with the builtin list.
func (db *DB) Refresh(ctx context.Context, client *http.Client) error {
	merged := map[string][]string{}
	for k, v := range builtin {
		merged[k] = append([]string{}, v...)
	}
	if b, err := os.ReadFile(cachePath()); err == nil {
		var cf cacheFile
		if json.Unmarshal(b, &cf) == nil && time.Since(cf.Fetched) < 24*time.Hour && len(cf.Ranges) > 0 {
			for k, v := range cf.Ranges {
				merged[k] = append(merged[k], v...)
			}
			db.load(merged)
			db.Source = "live (cached)"
			return nil
		}
	}
	live := map[string][]string{}
	get := func(u string) []byte {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 20<<20))
		return b
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	add := func(p string, cidrs []string) {
		mu.Lock()
		live[p] = append(live[p], cidrs...)
		mu.Unlock()
	}
	wg.Add(3)
	go func() {
		defer wg.Done()
		for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
			if b := get(u); b != nil {
				add("Cloudflare", strings.Fields(string(b)))
			}
		}
	}()
	go func() {
		defer wg.Done()
		var f struct {
			A  []string `json:"addresses"`
			A6 []string `json:"ipv6_addresses"`
		}
		if b := get("https://api.fastly.com/public-ip-list"); b != nil && json.Unmarshal(b, &f) == nil {
			add("Fastly", append(f.A, f.A6...))
		}
	}()
	go func() {
		defer wg.Done()
		var f struct {
			P []struct {
				IP  string `json:"ip_prefix"`
				Svc string `json:"service"`
			} `json:"prefixes"`
			P6 []struct {
				IP  string `json:"ipv6_prefix"`
				Svc string `json:"service"`
			} `json:"ipv6_prefixes"`
		}
		if b := get("https://ip-ranges.amazonaws.com/ip-ranges.json"); b != nil && json.Unmarshal(b, &f) == nil {
			out := []string{}
			for _, p := range f.P {
				if p.Svc == "CLOUDFRONT" {
					out = append(out, p.IP)
				}
			}
			for _, p := range f.P6 {
				if p.Svc == "CLOUDFRONT" {
					out = append(out, p.IP)
				}
			}
			add("Amazon CloudFront", out)
		}
	}()
	wg.Wait()
	if len(live) == 0 {
		db.load(merged)
		return nil
	}
	if b, err := json.Marshal(cacheFile{Fetched: time.Now(), Ranges: live}); err == nil {
		_ = os.MkdirAll(filepath.Dir(cachePath()), 0o755)
		_ = os.WriteFile(cachePath(), b, 0o644)
	}
	for k, v := range live {
		merged[k] = append(merged[k], v...)
	}
	db.load(merged)
	db.Source = "live"
	return nil
}
