// Package tools optionally shells out to well-known external recon tools when they are
// installed. Everything here is best-effort: a missing tool is reported, never fatal.
package tools

import (
	"bufio"
	"bytes"
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/MRvirusIR/Revelar/internal/util"
)

// Usage records the outcome of invoking an external tool.
type Usage struct {
	Tool    string `json:"tool"`
	Status  string `json:"status"`
	Hosts   int    `json:"hosts_found"`
	Message string `json:"message,omitempty"`
}

// Available reports whether a binary is on PATH.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func run(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	c, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(c, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.Bytes(), err
}

func parseHosts(out []byte, domain string) []string {
	hosts := []string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		for _, f := range strings.Fields(sc.Text()) {
			h := util.NormalizeHost(f)
			if util.InScope(h, domain) {
				hosts = append(hosts, h)
			}
		}
	}
	return util.UniqSorted(hosts)
}

// Subfinder runs projectdiscovery/subfinder if present.
func Subfinder(ctx context.Context, domain string, timeout time.Duration) ([]string, Usage) {
	if !Available("subfinder") {
		return nil, Usage{Tool: "subfinder", Status: "not installed"}
	}
	out, err := run(ctx, timeout, "subfinder", "-d", domain, "-all", "-silent")
	hosts := parseHosts(out, domain)
	u := Usage{Tool: "subfinder", Status: "ok", Hosts: len(hosts)}
	if err != nil && len(hosts) == 0 {
		u.Status, u.Message = "error", err.Error()
	}
	return hosts, u
}

// Amass runs owasp/amass passive enumeration if present.
func Amass(ctx context.Context, domain string, timeout time.Duration) ([]string, Usage) {
	if !Available("amass") {
		return nil, Usage{Tool: "amass", Status: "not installed"}
	}
	out, err := run(ctx, timeout, "amass", "enum", "-passive", "-norecursive", "-silent", "-d", domain)
	hosts := parseHosts(out, domain)
	u := Usage{Tool: "amass", Status: "ok", Hosts: len(hosts)}
	if err != nil && len(hosts) == 0 {
		u.Status, u.Message = "error", err.Error()
	}
	return hosts, u
}
