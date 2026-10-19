package verify

import "testing"

func TestSimhashSimilar(t *testing.T) {
	a := simhash([]byte("<html><body>the quick brown fox jumps over the lazy dog today</body></html>"))
	b := simhash([]byte("<html><body>the quick brown fox jumps over the lazy dog today!</body></html>"))
	if hamming(a, b) > 10 {
		t.Fatalf("expected small distance, got %d", hamming(a, b))
	}
	c := simhash([]byte("<html>completely unrelated content about finance markets and stocks</html>"))
	if hamming(a, c) < 10 {
		t.Fatalf("expected large distance, got %d", hamming(a, c))
	}
}

func TestScoreIdentical(t *testing.T) {
	base := Fingerprint{StatusCode: 200, BodySHA256: "abc", Title: "Home", Server: "nginx"}
	probe := Fingerprint{StatusCode: 200, BodySHA256: "abc", Title: "Home", Server: "nginx"}
	s, _ := Score(base, probe)
	if s < 85 {
		t.Fatalf("expected high score, got %d", s)
	}
}
