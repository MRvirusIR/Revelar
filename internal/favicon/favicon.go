// Package favicon computes the Shodan-compatible mmh3 hash of a site favicon,
// used to pivot to origin servers hosting the same icon.
package favicon

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
)

// murmur3_32 implements the 32-bit MurmurHash3 used by Shodan (seed 0, signed output).
func murmur3_32(data []byte) int32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	var h uint32
	n := len(data) / 4
	for i := 0; i < n; i++ {
		k := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
		h = (h << 13) | (h >> 19)
		h = h*5 + 0xe6546b64
	}
	var k uint32
	tail := data[n*4:]
	switch len(tail) {
	case 3:
		k ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k ^= uint32(tail[0])
		k *= c1
		k = (k << 15) | (k >> 17)
		k *= c2
		h ^= k
	}
	h ^= uint32(len(data))
	h ^= h >> 16
	h *= 0x85ebca6b
	h ^= h >> 13
	h *= 0xc2b2ae35
	h ^= h >> 16
	return int32(h)
}

// b64chunked base64-encodes with a newline every 76 chars plus a trailing newline,
// matching Python's base64.encodebytes that Shodan expects.
func b64chunked(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var sb strings.Builder
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		sb.WriteString(enc[i:end])
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// Hash downloads scheme://domain/favicon.ico and returns its mmh3 hash, or 0.
func Hash(ctx context.Context, client *http.Client, scheme, domain string) int32 {
	u := scheme + "://" + domain + "/favicon.ico"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil || len(b) == 0 {
		return 0
	}
	return murmur3_32(b64chunked(b))
}
