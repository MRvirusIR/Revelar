// Package asn enriches IPs with ASN and organisation data using Team Cymru's free
// DNS-based whois service (origin.asn.cymru.com). No API key required.
package asn

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 20 * time.Second}

// Info is ASN data for one IP.
type Info struct {
	ASN string
	Org string
}

// Resolver looks up ASN info with caching.
type Resolver struct {
	res *net.Resolver
	mu  sync.Mutex
	c   map[string]Info
}

// New builds an ASN resolver.
func New() *Resolver {
	return &Resolver{res: net.DefaultResolver, c: map[string]Info{}}
}

func reverse4(ip net.IP) string {
	p := ip.To4()
	itoa := func(b byte) string { return strconv.Itoa(int(b)) }
	return itoa(p[3]) + "." + itoa(p[2]) + "." + itoa(p[1]) + "." + itoa(p[0])
}

// Lookup returns ASN info for ipStr (IPv4 only; IPv6 returns empty).
func (r *Resolver) Lookup(ctx context.Context, ipStr string) Info {
	r.mu.Lock()
	if v, ok := r.c[ipStr]; ok {
		r.mu.Unlock()
		return v
	}
	r.mu.Unlock()

	ip := net.ParseIP(ipStr)
	var info Info
	if ip != nil && ip.To4() != nil {
		name := reverse4(ip) + ".origin.asn.cymru.com"
		if txts, err := r.res.LookupTXT(ctx, name); err == nil && len(txts) > 0 {
			// Format: "ASN | BGP prefix | CC | registry | allocated"
			parts := strings.Split(txts[0], "|")
			if len(parts) > 0 {
				asn := strings.TrimSpace(parts[0])
				info.ASN = "AS" + strings.Fields(asn)[0]
				if org := r.asName(ctx, strings.Fields(asn)[0]); org != "" {
					info.Org = org
				}
			}
		}
	}
	r.mu.Lock()
	r.c[ipStr] = info
	r.mu.Unlock()
	return info
}

func (r *Resolver) asName(ctx context.Context, asn string) string {
	txts, err := r.res.LookupTXT(ctx, "AS"+asn+".asn.cymru.com")
	if err != nil || len(txts) == 0 {
		return ""
	}
	// "ASN | CC | registry | allocated | AS Name"
	parts := strings.Split(txts[0], "|")
	if len(parts) >= 5 {
		return strings.TrimSpace(parts[4])
	}
	return ""
}

// prefixCache memoizes ASN → prefixes lookups.
var (
	prefixMu    sync.Mutex
	prefixCache = map[string][]string{}
)

// Prefixes returns the IPv4 CIDR prefixes announced by an ASN (e.g. "AS13335"),
// using RIPEstat's free public API. IPv6 prefixes are intentionally omitted.
func (r *Resolver) Prefixes(ctx context.Context, asn string) []string {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return nil
	}
	prefixMu.Lock()
	if v, ok := prefixCache[asn]; ok {
		prefixMu.Unlock()
		return v
	}
	prefixMu.Unlock()

	num := strings.TrimPrefix(strings.ToUpper(asn), "AS")
	u := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS" + url.QueryEscape(num)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var out struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if json.NewDecoder(resp.Body).Decode(&out) != nil {
		return nil
	}
	pfx := []string{}
	for _, p := range out.Data.Prefixes {
		if ip, _, err := net.ParseCIDR(p.Prefix); err == nil && ip.To4() != nil {
			pfx = append(pfx, p.Prefix)
		}
	}
	prefixMu.Lock()
	prefixCache[asn] = pfx
	prefixMu.Unlock()
	return pfx
}
