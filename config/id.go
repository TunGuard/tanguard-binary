package config

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// RandomID returns a short random hex token. It is the identifier source for
// everything the server registers for itself: mesh nodes, TRP proxies and
// policy groups all need an id that is unguessable enough not to collide and
// short enough to sit in a log line or a URL.
func RandomID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
