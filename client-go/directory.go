package link

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Choosing a relay for a new network. A relay operator may publish a directory: regions, each
// with a URL to time and a relay URL template over its shards. The primary times every region
// once, when it creates the network, takes the closest, and hashes the network id onto one of
// its shards. The URL that comes out goes into the roster (section 3) and the network keeps it:
// the directory is consulted at creation only, never on reconnect.

// MaxShards is the most shards a region may have.
const MaxShards = 0x10000

// A directory or probe body larger than this is cut off; a region's /health is a few bytes.
const maxDirectoryBody = 1 << 20

// RelayDirectory is a relay operator's list of regions (version 1).
type RelayDirectory struct {
	Version int               `json:"version"`
	Regions []DirectoryRegion `json:"regions"`
}

// DirectoryRegion is one region of a directory.
type DirectoryRegion struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// Probe is an http(s) URL to time: a GET answered quickly from the region (a relay's /health).
	Probe string `json:"probe"`
	// Relay is the relay URL, with {shard} where the shard goes (or none, for a region of one relay).
	Relay string `json:"relay"`
	// Shards is the region's shard count, 1 to MaxShards; 0 means 1. {shard} in its template is
	// one of them, in lowercase hex. Each region has its own count, so one region can grow
	// without touching the others; a change only affects networks created afterwards, since a
	// network keeps the URL it was given.
	Shards int `json:"shards,omitempty"`
	// Accepting false: the region takes no new networks; those already on it are unaffected.
	Accepting bool `json:"accepting"`
}

// PickRelayOptions configures PickRelay. Set exactly one of Directory and DirectoryURL.
type PickRelayOptions struct {
	// Network is the new network's id (its primary's node id).
	Network string
	// Directory is the directory itself...
	Directory *RelayDirectory
	// ...or DirectoryURL the URL to fetch it from.
	DirectoryURL string
	// Probes is the number of requests timed per region; the fastest counts. 0 means 3.
	Probes int
	// Timeout is how long a region has for all of its probes (and the directory fetch). 0 means 3 s.
	Timeout time.Duration
	// Client makes the requests; nil means http.DefaultClient.
	Client *http.Client
}

// PickedRelay is what PickRelay chose.
type PickedRelay struct {
	// URL is the relay URL for the network's roster.
	URL    string
	Region string
	Shard  string
	// RTT is the region's fastest probe.
	RTT time.Duration
}

// ShardOf returns the shard a network belongs to among shards: the first four bytes of SHA-256
// of its id, big-endian, modulo shards, in lowercase hex padded to the width of shards - 1 (two
// digits for 256). It fails invalid unless shards is from 1 to MaxShards.
func ShardOf(network string, shards int) (string, error) {
	if shards < 1 || shards > MaxShards {
		return "", invalidError("shards must be an integer from 1 to 65536")
	}
	h := sha256.Sum256([]byte(network))
	n := binary.BigEndian.Uint32(h[:4])
	width := max(1, len(strconv.FormatInt(int64(shards-1), 16)))
	return fmt.Sprintf("%0*x", width, n%uint32(shards)), nil
}

func directoryError(why string) *Error { return invalidError("relay directory: " + why) }

// ParseDirectory decodes a directory and checks its shape; it fails invalid on anything it
// cannot use. Members this version does not define are ignored.
func ParseDirectory(data []byte) (*RelayDirectory, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, directoryError("not JSON: " + err.Error())
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, directoryError("not JSON: data after the value")
	}
	d, ok := v.(map[string]any)
	if !ok {
		return nil, directoryError("not an object")
	}
	if n, ok := number(d["version"]); !ok || n != 1 {
		return nil, directoryError("version is not 1")
	}
	list, ok := d["regions"].([]any)
	if !ok || len(list) == 0 {
		return nil, directoryError("no regions")
	}
	dir := &RelayDirectory{Version: 1, Regions: make([]DirectoryRegion, len(list))}
	for i, r := range list {
		g, ok := r.(map[string]any)
		if !ok {
			return nil, directoryError(fmt.Sprintf("region %d is not an object", i))
		}
		id, _ := g["id"].(string)
		if id == "" {
			return nil, directoryError(fmt.Sprintf("region %d has no id", i))
		}
		reg := &dir.Regions[i]
		reg.ID = id
		reg.Name, _ = g["name"].(string)
		if reg.Probe, ok = g["probe"].(string); !ok || !isHTTPURL(reg.Probe) {
			return nil, directoryError(fmt.Sprintf("region %s: probe is not an http(s) URL", id))
		}
		if reg.Relay, ok = g["relay"].(string); !ok || !isWSURL(reg.Relay) {
			return nil, directoryError(fmt.Sprintf("region %s: relay is not a ws(s) URL", id))
		}
		if reg.Accepting, ok = g["accepting"].(bool); !ok {
			return nil, directoryError(fmt.Sprintf("region %s: accepting is not a boolean", id))
		}
		if s, present := g["shards"]; present {
			n, ok := number(s)
			if !ok || n != math.Trunc(n) || n < 1 || n > MaxShards {
				return nil, directoryError(fmt.Sprintf("region %s: shards is not an integer from 1 to 65536", id))
			}
			reg.Shards = int(n)
		}
	}
	return dir, nil
}

// number reads a JSON number as a double, as JSON.parse does.
func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func isWSURL(s string) bool {
	return strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://")
}

// check applies ParseDirectory's rules to a directory built in code.
func (d *RelayDirectory) check() error {
	if d.Version != 1 {
		return directoryError("version is not 1")
	}
	if len(d.Regions) == 0 {
		return directoryError("no regions")
	}
	for i, r := range d.Regions {
		switch {
		case r.ID == "":
			return directoryError(fmt.Sprintf("region %d has no id", i))
		case !isHTTPURL(r.Probe):
			return directoryError(fmt.Sprintf("region %s: probe is not an http(s) URL", r.ID))
		case !isWSURL(r.Relay):
			return directoryError(fmt.Sprintf("region %s: relay is not a ws(s) URL", r.ID))
		case r.Shards < 0 || r.Shards > MaxShards:
			return directoryError(fmt.Sprintf("region %s: shards is not an integer from 1 to 65536", r.ID))
		}
	}
	return nil
}

// PickRelay times every accepting region of the directory and returns the relay URL for
// opts.Network in the closest. It fails unreachable when no region answers in time (or the
// directory cannot be fetched), and invalid on a directory it cannot use; the caller then
// falls back to a relay of its own choosing.
func PickRelay(ctx context.Context, opts PickRelayOptions) (PickedRelay, error) {
	client := opts.Client
	if client == nil {
		client = http.DefaultClient
	}
	probes := opts.Probes
	if probes < 1 {
		probes = 3
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	dir := opts.Directory
	switch {
	case (dir == nil) == (opts.DirectoryURL == ""):
		return PickedRelay{}, invalidError("relay directory: set one of Directory and DirectoryURL")
	case dir == nil:
		var err error
		if dir, err = fetchDirectory(ctx, client, opts.DirectoryURL, timeout); err != nil {
			return PickedRelay{}, err
		}
	default:
		if err := dir.check(); err != nil {
			return PickedRelay{}, err
		}
	}

	var accepting []DirectoryRegion
	for _, r := range dir.Regions {
		if r.Accepting {
			accepting = append(accepting, r)
		}
	}
	rtts := make([]time.Duration, len(accepting))
	done := make(chan struct{})
	for i, r := range accepting {
		go func() {
			rtts[i] = timeRegion(ctx, client, r.Probe, probes, timeout)
			done <- struct{}{}
		}()
	}
	for range accepting {
		<-done
	}
	pick := -1
	for i, rtt := range rtts {
		if rtt >= 0 && (pick < 0 || rtt < rtts[pick]) {
			pick = i
		}
	}
	if pick < 0 {
		return PickedRelay{}, &Error{Code: CodeUnreachable, Message: "relay directory: no accepting region answered"}
	}
	region := accepting[pick]
	shards := region.Shards
	if shards == 0 {
		shards = 1
	}
	shard, err := ShardOf(opts.Network, shards)
	if err != nil {
		return PickedRelay{}, err
	}
	return PickedRelay{URL: strings.ReplaceAll(region.Relay, "{shard}", shard), Region: region.ID, Shard: shard, RTT: rtts[pick]}, nil
}

func fetchDirectory(ctx context.Context, client *http.Client, url string, timeout time.Duration) (*RelayDirectory, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	unreachable := func(why string) *Error {
		return &Error{Code: CodeUnreachable, Message: fmt.Sprintf("relay directory: %s %s", url, why)}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, invalidError("relay directory: " + err.Error())
	}
	req.Header.Set("Cache-Control", "no-store")
	resp, err := client.Do(req)
	if err != nil {
		return nil, unreachable("failed: " + err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, unreachable(fmt.Sprintf("answered %d", resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDirectoryBody))
	if err != nil {
		return nil, unreachable("failed: " + err.Error())
	}
	return ParseDirectory(body)
}

// timeRegion GETs probe up to probes times, one after another, all within timeout, and returns
// the fastest 2xx answer read to its end, or -1 if none came.
func timeRegion(ctx context.Context, client *http.Client, probe string, probes int, timeout time.Duration) time.Duration {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	best := time.Duration(-1)
	for range probes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe, nil)
		if err != nil {
			break
		}
		req.Header.Set("Cache-Control", "no-store")
		t0 := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			break // timed out or unreachable: what was measured stands
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDirectoryBody))
		resp.Body.Close()
		if err != nil {
			break
		}
		if rtt := time.Since(t0); resp.StatusCode >= 200 && resp.StatusCode <= 299 && (best < 0 || rtt < best) {
			best = rtt
		}
	}
	return best
}
