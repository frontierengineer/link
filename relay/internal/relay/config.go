// Package relay is the Link relay (spec/protocol.md sections 4, 5.2, 6 and 9).
package relay

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Config holds every setting. A zero limit is off. The environment names are those of
// section 9; the timings below them are fixed by the spec and settable (also through
// LINK_PING_INTERVAL, LINK_PAIR_TIMEOUT and LINK_HELLO_TIMEOUT) only so tests can shorten
// them.
type Config struct {
	Addr              string        // LINK_ADDR
	Origin            string        // LINK_ORIGIN; empty: the request's Host
	TrustProxy        bool          // LINK_TRUST_PROXY
	TLSCert, TLSKey   string        // LINK_TLS_CERT, LINK_TLS_KEY; both empty: plain HTTP
	RateBps           int64         // LINK_RATE_BPS
	QuotaBytesHour    int64         // LINK_QUOTA_BYTES_HOUR
	TrickleBps        int64         // LINK_TRICKLE_BPS
	QueueBytes        int64         // LINK_QUEUE_BYTES
	SlowPeer          time.Duration // LINK_SLOW_PEER_SEC
	IPRegisterPerMin  int           // LINK_IP_REGISTER_PER_MIN
	IPPairPerMin      int           // LINK_IP_PAIR_PER_MIN
	IPNetworksPerHour int           // LINK_IP_NETWORKS_PER_HOUR
	NetworkTTL        time.Duration // LINK_NETWORK_TTL

	PingInterval time.Duration // 30 s (section 9); LINK_PING_INTERVAL
	PairTimeout  time.Duration // 60 s (section 5.2); LINK_PAIR_TIMEOUT
	HelloTimeout time.Duration // 30 s between hello and register or pair (section 4.1); LINK_HELLO_TIMEOUT
	CloseGrace   time.Duration // time allowed to finish a frame, send a close and see the reply
}

// Defaults is the self-hosted configuration: every limit off.
func Defaults() Config {
	return Config{
		Addr:         ":8080",
		NetworkTTL:   7 * 24 * time.Hour,
		PingInterval: 30 * time.Second,
		PairTimeout:  60 * time.Second,
		HelloTimeout: 30 * time.Second,
		CloseGrace:   5 * time.Second,
	}
}

// FromEnv reads the section 9 variables over Defaults.
func FromEnv(getenv func(string) string) (Config, error) {
	c := Defaults()
	var errs []string
	str := func(name string, dst *string) {
		if v := getenv(name); v != "" {
			*dst = v
		}
	}
	i64 := func(name string, dst *int64) {
		if v := getenv(name); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 0 {
				errs = append(errs, name+": not a non-negative integer")
			}
			*dst = n
		}
	}
	num := func(name string, dst *int) {
		var n int64
		i64(name, &n)
		*dst = int(n)
	}
	str("LINK_ADDR", &c.Addr)
	str("LINK_ORIGIN", &c.Origin)
	str("LINK_TLS_CERT", &c.TLSCert)
	str("LINK_TLS_KEY", &c.TLSKey)
	if v := getenv("LINK_TRUST_PROXY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, "LINK_TRUST_PROXY: not a boolean")
		}
		c.TrustProxy = b
	}
	i64("LINK_RATE_BPS", &c.RateBps)
	i64("LINK_QUOTA_BYTES_HOUR", &c.QuotaBytesHour)
	i64("LINK_TRICKLE_BPS", &c.TrickleBps)
	i64("LINK_QUEUE_BYTES", &c.QueueBytes)
	var slow int64
	i64("LINK_SLOW_PEER_SEC", &slow)
	c.SlowPeer = time.Duration(slow) * time.Second
	num("LINK_IP_REGISTER_PER_MIN", &c.IPRegisterPerMin)
	num("LINK_IP_PAIR_PER_MIN", &c.IPPairPerMin)
	num("LINK_IP_NETWORKS_PER_HOUR", &c.IPNetworksPerHour)
	dur := func(name string, dst *time.Duration) {
		if v := getenv(name); v != "" {
			d, err := parseDuration(v)
			if err != nil || d <= 0 {
				errs = append(errs, name+": not a positive duration such as 168h or 30s")
			}
			*dst = d
		}
	}
	dur("LINK_NETWORK_TTL", &c.NetworkTTL)
	dur("LINK_PING_INTERVAL", &c.PingInterval)
	dur("LINK_PAIR_TIMEOUT", &c.PairTimeout)
	dur("LINK_HELLO_TIMEOUT", &c.HelloTimeout)
	if (c.TLSCert == "") != (c.TLSKey == "") {
		errs = append(errs, "LINK_TLS_CERT and LINK_TLS_KEY must be set together")
	}
	if len(errs) > 0 {
		return c, fmt.Errorf("config: %s", strings.Join(errs, "; "))
	}
	return c, nil
}

// parseDuration takes a Go duration ("168h") or a bare number of seconds.
func parseDuration(v string) (time.Duration, error) {
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Duration(n) * time.Second, nil
	}
	return time.ParseDuration(v)
}
