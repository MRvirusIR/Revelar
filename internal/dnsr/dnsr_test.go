package dnsr

import "testing"

func TestParseSPF(t *testing.T) {
	s := ParseSPF([]string{
		"google-site-verification=xyz",
		"v=spf1 ip4:203.0.113.10 ip4:198.51.100.0/24 +ip6:2001:db8::1 a:mail.example.com include:_spf.google.com ~all",
	})
	if len(s.IPs) != 2 || s.IPs[0] != "2001:db8::1" || s.IPs[1] != "203.0.113.10" {
		t.Fatalf("ips=%v", s.IPs)
	}
	if len(s.Networks) != 1 || s.Networks[0] != "198.51.100.0/24" {
		t.Fatalf("nets=%v", s.Networks)
	}
	if len(s.Hosts) != 2 {
		t.Fatalf("hosts=%v", s.Hosts)
	}
}
