// Package util contains small helpers shared across Revelar packages.
package util

import (
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// UniqSorted trims, de-duplicates and sorts a string slice.
func UniqSorted(ss ...[]string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, s := range ss {
		for _, v := range s {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if _, ok := m[v]; !ok {
				m[v] = struct{}{}
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}

// InScope reports whether host equals domain or is a subdomain of it.
func InScope(host, domain string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// NormalizeHost lowercases and strips wildcards, schemes, ports and paths.
func NormalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimPrefix(h, "*.")
	return strings.TrimSuffix(h, ".")
}

// IsPublicIP reports whether ip is a globally routable unicast address.
func IsPublicIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return false
	}
	for _, c := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32",
		"64:ff9b::/96", "64:ff9b:1::/48", "2002::/16"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

// IsIPv6 reports whether s is an IPv6 literal.
func IsIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil
}

// WriteFile writes data creating parent directories.
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// FileExists reports whether p is an existing regular file.
func FileExists(p string) bool {
	if p == "" {
		return false
	}
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// StringSet is a concurrency-safe set of strings.
type StringSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

// NewStringSet creates an empty set.
func NewStringSet() *StringSet { return &StringSet{m: map[string]struct{}{}} }

// Add inserts values; returns how many were new.
func (s *StringSet) Add(vs ...string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, v := range vs {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := s.m[v]; !ok {
			s.m[v] = struct{}{}
			n++
		}
	}
	return n
}

// Has reports membership.
func (s *StringSet) Has(v string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[v]
	return ok
}

// Len returns the size.
func (s *StringSet) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// Sorted returns the sorted members.
func (s *StringSet) Sorted() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.m))
	for k := range s.m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ParallelEach runs fn over items with at most workers goroutines.
func ParallelEach[T any](items []T, workers int, fn func(T)) {
	if workers < 1 {
		workers = 1
	}
	ch := make(chan T)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for it := range ch {
				fn(it)
			}
		}()
	}
	for _, it := range items {
		ch <- it
	}
	close(ch)
	wg.Wait()
}
