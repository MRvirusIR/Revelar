// Package scanner orchestrates the whole discovery pipeline and produces a ScanResult.
package scanner

import (
	"github.com/MRvirusIR/Revelar/internal/sources"
	"github.com/MRvirusIR/Revelar/internal/tools"
	"github.com/MRvirusIR/Revelar/internal/verify"
)

// Candidate is a potential origin IP with accumulated evidence.
type Candidate struct {
	IP           string   `json:"ip"`
	IsIPv6       bool     `json:"is_ipv6"`
	Sources      []string `json:"sources"`
	Hostnames    []string `json:"hostnames,omitempty"`
	PTR          []string `json:"ptr,omitempty"`
	ASN          string   `json:"asn,omitempty"`
	ASOrg        string   `json:"as_org,omitempty"`
	CDN          string   `json:"cdn,omitempty"`
	Notes        []string `json:"notes,omitempty"`
	PassiveScore int      `json:"passive_score"`
	// Active verification
	Verified   bool                `json:"verified"`
	MatchScore int                 `json:"match_score,omitempty"`
	MatchNote  string              `json:"match_note,omitempty"`
	Probe      *verify.Fingerprint `json:"probe,omitempty"`
}

// ScanResult is the full report for one domain.
type ScanResult struct {
	Domain         string  `json:"domain"`
	ScannedAt      string  `json:"scanned_at"`
	DurationSec    float64 `json:"duration_sec"`
	RevelarVersion string  `json:"revelar_version"`

	FrontIPsV4  []string `json:"front_ips_v4"`
	FrontIPsV6  []string `json:"front_ips_v6"`
	CDNProvider string   `json:"cdn_provider"`
	CDNEvidence []string `json:"cdn_evidence,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	MXHosts     []string `json:"mx_hosts,omitempty"`

	Subdomains  []string `json:"subdomains"`
	CertSANs    []string `json:"cert_sans,omitempty"`
	FaviconHash int32    `json:"favicon_hash,omitempty"`

	SPFIPs      []string `json:"spf_ips,omitempty"`
	SPFNetworks []string `json:"spf_networks,omitempty"`

	Candidates []Candidate `json:"candidates"`
	BestOrigin string      `json:"best_origin,omitempty"`
	BestScore  int         `json:"best_score,omitempty"`

	ActiveEnabled bool                `json:"active_enabled"`
	Baseline      *verify.Fingerprint `json:"baseline,omitempty"`

	SourcesUsed map[string]string `json:"sources_used"`
	ToolsUsed   []tools.Usage     `json:"tools_used,omitempty"`
	Notes       []string          `json:"notes,omitempty"`

	rawIPHits []sources.IPHit
}
