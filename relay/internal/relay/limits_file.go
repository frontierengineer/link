package relay

import (
	jsonv2 "encoding/json/v2"
	"fmt"
	"maps"
	"net"
	"os"
	"strings"
	"sync/atomic"
)

// netLimits are the limits charged to one network (section 9): its rate, its hourly quota and
// the rate once the quota is spent. Zero is off.
type netLimits struct {
	RateBps        int64
	QuotaBytesHour int64
	TrickleBps     int64
}

// origin is one origin named in LINK_LIMITS_FILE: the relay reports on it, drains it, and
// charges the networks first registered through it its limits. An origin once named is kept
// for the life of the process, so connections and networks may point at it without a lock;
// one no longer named reverts to the defaults and is no longer reported.
type origin struct {
	name   string
	limits atomic.Pointer[netLimits] // nil: the defaults
	named  atomic.Bool
}

// limitsFile is the document LINK_LIMITS_FILE holds. Absent fields keep the environment's.
type limitsFile struct {
	RateBps        *int64                    `json:"rateBps"`
	QuotaBytesHour *int64                    `json:"quotaBytesHour"`
	TrickleBps     *int64                    `json:"trickleBps"`
	Origins        map[string]originOverride `json:"origins"`
}

type originOverride struct {
	RateBps        *int64 `json:"rateBps"`
	QuotaBytesHour *int64 `json:"quotaBytesHour"`
	TrickleBps     *int64 `json:"trickleBps"`
}

// maxOrigins bounds the origins one limits file may name.
const maxOrigins = 1 << 16

func (o originOverride) over(l netLimits) netLimits {
	set := func(dst *int64, v *int64) {
		if v != nil {
			*dst = *v
		}
	}
	set(&l.RateBps, o.RateBps)
	set(&l.QuotaBytesHour, o.QuotaBytesHour)
	set(&l.TrickleBps, o.TrickleBps)
	return l
}

func (o originOverride) check(name string) error {
	for _, v := range []*int64{o.RateBps, o.QuotaBytesHour, o.TrickleBps} {
		if v != nil && *v < 0 {
			return fmt.Errorf("%s: limits must be non-negative", name)
		}
	}
	return nil
}

// normalOrigin is host as a member signs it (section 4.1): lowercased, without the port when
// it is 80 or 443.
func normalOrigin(host string) string {
	host = strings.ToLower(host)
	if h, p, err := net.SplitHostPort(host); err == nil && (p == "80" || p == "443") {
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
		host = h
	}
	return host
}

// envLimits are the limits the environment sets.
func (s *Server) envLimits() netLimits {
	return netLimits{RateBps: s.cfg.RateBps, QuotaBytesHour: s.cfg.QuotaBytesHour, TrickleBps: s.cfg.TrickleBps}
}

// limitsOf is what network n is charged under: its origin's limits, else the defaults.
func (s *Server) limitsOf(n *network) *netLimits {
	if o := n.origin; o != nil {
		if l := o.limits.Load(); l != nil {
			return l
		}
	}
	return s.limits.Load()
}

// originNamed finds the origin host is named as, or nil.
func (s *Server) originNamed(host string) *origin {
	o := (*s.origins.Load())[host]
	if o == nil || !o.named.Load() {
		return nil
	}
	return o
}

// ReloadLimits reads LINK_LIMITS_FILE and puts it in force, for networks already live too.
// On an error nothing changes. Without LINK_LIMITS_FILE it restores the environment's limits.
func (s *Server) ReloadLimits() error {
	var f limitsFile
	if s.cfg.LimitsFile != "" {
		b, err := os.ReadFile(s.cfg.LimitsFile)
		if err != nil {
			return err
		}
		if err := decodeLimitsFile(b, &f); err != nil {
			return fmt.Errorf("%s: %w", s.cfg.LimitsFile, err)
		}
	}
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	def := originOverride{RateBps: f.RateBps, QuotaBytesHour: f.QuotaBytesHour, TrickleBps: f.TrickleBps}.over(s.envLimits())
	old := *s.origins.Load()
	next := maps.Clone(old)
	for name, ov := range f.Origins {
		o := next[name]
		if o == nil {
			o = &origin{name: name}
			next[name] = o
		}
		l := ov.over(def)
		o.limits.Store(&l)
		o.named.Store(true)
	}
	for name, o := range next {
		if _, ok := f.Origins[name]; !ok {
			o.limits.Store(nil)
			o.named.Store(false)
		}
	}
	s.limits.Store(&def)
	s.origins.Store(&next)
	return nil
}

func decodeLimitsFile(b []byte, f *limitsFile) error {
	// Names match exactly, a repeated or unknown one is an error, and so is trailing data.
	if err := jsonv2.Unmarshal(b, f, jsonv2.RejectUnknownMembers(true)); err != nil {
		return err
	}
	top := originOverride{RateBps: f.RateBps, QuotaBytesHour: f.QuotaBytesHour, TrickleBps: f.TrickleBps}
	if err := top.check("defaults"); err != nil {
		return err
	}
	if len(f.Origins) > maxOrigins {
		return fmt.Errorf("more than %d origins", maxOrigins)
	}
	for name, ov := range f.Origins {
		if name == "" || name != normalOrigin(name) || strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789.-_:[]") != "" {
			return fmt.Errorf("origin %q: not a lowercase host[:port] without :80 or :443", name)
		}
		if err := ov.check(name); err != nil {
			return err
		}
	}
	return nil
}
