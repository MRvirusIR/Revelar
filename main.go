// Revelar — Origin Reveal PRO
// A fast, modular CLI for discovering the real/origin IP of sites behind CDNs and WAFs.
// Authorized security testing only.
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const version = "2.1.0"

const (
	cReset = "\033[0m"
	cRed   = "\033[31m"
	cGrn   = "\033[32m"
	cYel   = "\033[33m"
	cBlu   = "\033[34m"
	cCyn   = "\033[36m"
	cMag   = "\033[35m"
	cDim   = "\033[2m"
)

const banner = `
   ██████╗ ███████╗██╗   ██╗███████╗██╗      █████╗ ██████╗ 
   ██╔══██╗██╔════╝██║   ██║██╔════╝██║     ██╔══██╗██╔══██╗
   ██████╔╝█████╗  ██║   ██║█████╗  ██║     ███████║██████╔╝
   ██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     ██╔══██║██╔══██╗
   ██║  ██║███████╗ ╚████╔╝ ███████╗███████╗██║  ██║██║  ██║
   ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝`

const tagline = "   Origin Reveal PRO  ·  v%s  ·  unmask the real IP behind any CDN/WAF\n   t.me/BugCod3   ·   t.me/RootAccessClub\n"

type clog struct {
	enabled bool
	prefix  string
	noColor bool
}

func (l clog) p(color, sym, f string, a ...any) {
	if !l.enabled {
		return
	}
	msg := fmt.Sprintf(f, a...)
	if l.noColor {
		fmt.Printf("%s[%s] %s\n", l.prefix, sym, msg)
		return
	}
	fmt.Printf("%s%s[%s] %s%s\n", color, l.prefix, sym, msg, cReset)
}
func (l clog) Step(f string, a ...any) { l.p(cCyn, ">", f, a...) }
func (l clog) OK(f string, a ...any)   { l.p(cGrn, "+", f, a...) }
func (l clog) Warn(f string, a ...any) { l.p(cYel, "!", f, a...) }
func (l clog) Info(f string, a ...any) { l.p(cBlu, "i", f, a...) }
func (l clog) Err(f string, a ...any)  { l.p(cRed, "x", f, a...) }

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*s = append(*s, p)
		}
	}
	return nil
}

func parsePorts(csv string) []int {
	out := []int{}
	for _, p := range strings.Split(csv, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

func main() {
	os.Exit(run())
}
