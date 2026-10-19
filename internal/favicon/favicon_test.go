package favicon

import "testing"

// Reference values computed with Python: mmh3.hash(base64.encodebytes(data)),
// which is exactly what Shodan's http.favicon.hash uses.
func TestMurmurMatchesShodan(t *testing.T) {
	big := []byte{}
	for i := 0; i < 3; i++ {
		for b := 0; b < 256; b++ {
			big = append(big, byte(b))
		}
	}
	cases := []struct {
		in   []byte
		want int32
	}{
		{[]byte("hello"), 1155597304},
		{big, 1836528006},
	}
	for _, c := range cases {
		if got := murmur3_32(b64chunked(c.in)); got != c.want {
			t.Errorf("hash=%d want %d", got, c.want)
		}
	}
}
