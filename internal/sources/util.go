package sources

import (
	"encoding/base64"
)

func basic(id, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
}
