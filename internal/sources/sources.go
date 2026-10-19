// Package sources implements passive reconnaissance sources (certificate transparency,
// passive DNS, threat-intel and internet-scan engines). Free sources run by default;
// keyed sources are enabled automatically when their API key is present in the environment.
package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// IPHit is an IP observed by a source.
type IPHit struct {
	IP     string `json:"ip"`
	Host   string `json:"host,omitempty"`
	Source string `json:"source"`
	Note   string `json:"note,omitempty"`
}

// Result is what a source returns.
type Result struct {
	Hosts []string
	IPs   []IPHit
}

// Query carries scan-specific inputs to sources.
type Query struct {
	Domain      string
	FaviconHash int32 // Shodan-style mmh3 favicon hash, 0 if unknown
	CertSHA256  string
	Title       string
}

// Source is a passive recon provider.
type Source interface {
	Name() string
	NeedsKey() bool
	Enabled() bool
	Run(ctx context.Context, c *Client, q Query) (Result, error)
}

// Client is a small HTTP helper shared by sources.
type Client struct {
	HTTP *http.Client
	UA   string
}

func (c *Client) do(ctx context.Context, method, u string, body io.Reader, hdr map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Accept", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	var resp *http.Response
	for attempt := 0; attempt < 3; attempt++ {
		resp, err = c.HTTP.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			time.Sleep(time.Duration(attempt+1) * 700 * time.Millisecond)
			continue
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			resp.Body.Close()
			err = fmt.Errorf("http %d", resp.StatusCode)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 1500 * time.Millisecond):
			}
			continue
		}
		break
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return b, nil
}

func (c *Client) getJSON(ctx context.Context, u string, hdr map[string]string, v any) error {
	b, err := c.do(ctx, http.MethodGet, u, nil, hdr)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func env(k string) string { return strings.TrimSpace(os.Getenv(k)) }

// All returns every known source.
func All() []Source {
	return []Source{
		&crtsh{}, &certspotter{}, &hackertarget{}, &otx{}, &urlscan{}, &anubis{}, &wayback{},
		&securitytrails{}, &shodan{}, &censys{}, &virustotal{}, &viewdns{},
		&netlas{}, &fofa{}, &zoomeye{}, &binaryedge{}, &quake{}, &rapiddns{},
	}
}

// Select filters sources by a comma-separated list ("all", "free", "none" or names).
func Select(spec string) []Source {
	spec = strings.ToLower(strings.TrimSpace(spec))
	all := All()
	if spec == "" || spec == "all" {
		return all
	}
	if spec == "none" {
		return nil
	}
	if spec == "free" {
		out := []Source{}
		for _, s := range all {
			if !s.NeedsKey() {
				out = append(out, s)
			}
		}
		return out
	}
	want := map[string]bool{}
	for _, t := range strings.Split(spec, ",") {
		want[strings.TrimSpace(t)] = true
	}
	out := []Source{}
	for _, s := range all {
		if want[s.Name()] {
			out = append(out, s)
		}
	}
	return out
}
