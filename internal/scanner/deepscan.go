package scanner

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/MRvirusIR/Revelar/internal/util"
	"github.com/MRvirusIR/Revelar/internal/verify"
)

// deepScan brute-forces candidate origins by probing every IP in the SPF-advertised
// networks (and, when enabled, in the ASNs of already-found candidates) with the correct
// Host header, scoring each against the baseline. This can reveal an origin even when the
// site is otherwise fully proxied. It only runs with -active and -deep, and is bounded by
// -deep-max to avoid scanning huge ranges.
func (s *Scanner) deepScan(ctx context.Context, r *ScanResult, base verify.Fingerprint) {
	if base.Error != "" || base.StatusCode == 0 {
		r.Notes = append(r.Notes, "Deep scan skipped: could not fetch a baseline of the real site.")
		return
	}
	nets := map[string]*net.IPNet{}
	for _, c := range r.SPFNetworks {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets[n.String()] = n
		}
	}
	// Expand ASNs of existing non-CDN candidates into their announced prefixes.
	if s.cfg.DeepASN {
		seen := map[string]bool{}
		for _, c := range r.Candidates {
			if c.ASN == "" || seen[c.ASN] {
				continue
			}
			seen[c.ASN] = true
			for _, c2 := range s.asn.Prefixes(ctx, c.ASN) {
				if _, n, err := net.ParseCIDR(c2); err == nil {
					nets[n.String()] = n
				}
			}
		}
	}
	if len(nets) == 0 {
		return
	}

	// Enumerate hosts, enforcing the budget.
	ips := []string{}
	budget := s.cfg.DeepMax
	keys := make([]string, 0, len(nets))
	for k := range nets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, ip := range hostsOf(nets[k], budget-len(ips)) {
			ips = append(ips, ip)
			if len(ips) >= budget {
				break
			}
		}
		if len(ips) >= budget {
			r.Notes = append(r.Notes, "Deep scan hit the -deep-max budget; increase it to scan more of the ranges.")
			break
		}
	}
	// Drop CDN-owned and already-tested IPs.
	known := map[string]bool{}
	for _, c := range r.Candidates {
		known[c.IP] = true
	}
	todo := []string{}
	for _, ip := range ips {
		if known[ip] || s.cdnDB.Lookup(ip) != "" || !util.IsPublicIP(ip) {
			continue
		}
		todo = append(todo, ip)
	}
	if len(todo) == 0 {
		return
	}
	s.log.Step("deep scan: probing %d IPs across %d network(s)", len(todo), len(nets))

	p := &verify.Prober{Scheme: s.cfg.Scheme, UA: s.cfg.UA, Timeout: s.cfg.ActiveTimeout}
	ports := s.defaultPorts()
	var mu sync.Mutex
	hits := 0
	util.ParallelEach(todo, s.cfg.Threads, func(ip string) {
		if ctx.Err() != nil {
			return
		}
		best := -1
		var bestFp verify.Fingerprint
		bestNote := ""
		for _, port := range ports {
			pctx, cancel := context.WithTimeout(ctx, s.cfg.ActiveTimeout+3*time.Second)
			fp := p.Probe(pctx, r.Domain, ip, port)
			cancel()
			sc, note := verify.Score(base, fp)
			if sc > best {
				best, bestFp, bestNote = sc, fp, note
			}
		}
		if best < s.cfg.MinScore {
			return
		}
		ai := s.asn.Lookup(ctx, ip)
		c := Candidate{
			IP:         ip,
			IsIPv6:     util.IsIPv6(ip),
			Sources:    []string{"deepscan"},
			PTR:        s.res.PTR(ctx, ip),
			ASN:        ai.ASN,
			ASOrg:      ai.Org,
			MatchScore: best,
			MatchNote:  bestNote,
			Probe:      &bestFp,
			Verified:   true,
		}
		mu.Lock()
		r.Candidates = append(r.Candidates, c)
		hits++
		mu.Unlock()
		s.log.OK("deep scan match: %s score %d (%s)", ip, best, bestNote)
	})
	if hits > 0 {
		sort.SliceStable(r.Candidates, func(i, j int) bool {
			return r.Candidates[i].MatchScore > r.Candidates[j].MatchScore
		})
		r.BestOrigin = r.Candidates[0].IP
		r.BestScore = r.Candidates[0].MatchScore
		r.Notes = append(r.Notes, "Deep scan actively confirmed origin(s) by probing provider ranges.")
	}
}

// hostsOf returns up to limit usable host IPs in n (IPv4 only; IPv6 ranges are skipped).
func hostsOf(n *net.IPNet, limit int) []string {
	if limit <= 0 {
		return nil
	}
	ip4 := n.IP.To4()
	if ip4 == nil {
		return nil // never enumerate IPv6 space
	}
	ones, bits := n.Mask.Size()
	if bits-ones > 20 { // cap individual nets at /12 worth; larger handled by budget
	}
	out := []string{}
	ip := make(net.IP, len(ip4))
	copy(ip, ip4)
	for {
		out = append(out, ip.String())
		if len(out) >= limit {
			break
		}
		if !inc(ip) || !n.Contains(ip) {
			break
		}
	}
	return out
}

func inc(ip net.IP) bool {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return true
		}
	}
	return false
}
