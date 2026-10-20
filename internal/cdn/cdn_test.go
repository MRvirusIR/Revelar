package cdn

import (
	"net/http"
	"testing"
)

func TestLookup(t *testing.T) {
	db := NewBuiltin()
	cases := map[string]string{
		"104.16.1.1":      "Cloudflare",
		"151.101.1.69":    "Fastly",
		"2606:4700::1111": "Cloudflare",
		"185.143.233.5":   "ArvanCloud",
		"89.187.160.5":    "BunnyCDN",
		"43.152.0.5":      "Tencent Cloud EdgeOne",
		"47.88.0.5":       "Alibaba Cloud CDN",
		"180.76.0.5":      "Baidu Cloud CDN",
		"8.8.8.8":         "",
	}
	for ip, want := range cases {
		if got := db.Lookup(ip); got != want {
			t.Errorf("Lookup(%s)=%q want %q", ip, got, want)
		}
	}
}

func TestByHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "cloudflare")
	if ByHeaders(h) != "Cloudflare" {
		t.Fatal("expected Cloudflare")
	}
	h = http.Header{}
	h.Set("X-Amz-Cf-Id", "abc")
	if ByHeaders(h) != "Amazon CloudFront" {
		t.Fatal("expected CloudFront")
	}
}

func TestByHostname(t *testing.T) {
	if ByHostname("server-13-32-1-1.fra56.r.cloudfront.net") != "Amazon CloudFront" {
		t.Fatal("cloudfront")
	}
	if ByHostname("mail.example.com") != "" {
		t.Fatal("false positive")
	}
	if ByHostname("foo.alikunlun.com") != "Alibaba Cloud CDN" {
		t.Fatal("alibaba")
	}
	if ByHostname("x.cdntip.com") != "Tencent Cloud EdgeOne" {
		t.Fatal("tencent")
	}
}
