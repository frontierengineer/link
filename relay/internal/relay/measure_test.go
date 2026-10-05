package relay

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/frontierengineer/link/relay/internal/link"
)

// TestMeasureIdle measures the relay's memory per idle registered connection: the real
// binary in its own process, LINK_MEASURE connections in networks of three, RSS from /proc.
// It runs only when asked (LINK_MEASURE=20000 go test -run MeasureIdle -v ./internal/relay),
// once with idle connections parked and once with a goroutine each.
func TestMeasureIdle(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("LINK_MEASURE"))
	if n <= 0 || runtime.GOOS != "linux" {
		t.Skip("set LINK_MEASURE to a number of connections (Linux)")
	}
	bin := os.Getenv("LINK_MEASURE_BIN") // another build to compare with
	if bin == "" {
		bin = filepath.Join(t.TempDir(), "link-relay")
		if out, err := exec.Command("go", "build", "-o", bin, "../../cmd/link-relay").CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, out)
		}
	}
	for _, park := range []string{"true", "false"} {
		perConn := measureIdle(t, bin, park, n)
		t.Logf("LINK_PARK_IDLE=%s: %d connections, %.0f bytes of RSS per idle connection", park, n, perConn)
	}
}

func measureIdle(t *testing.T, bin, park string, n int) float64 {
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "LINK_ADDR=127.255.0.1:0", "LINK_PARK_IDLE="+park, "LINK_PING_INTERVAL=1h")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()
	sc := bufio.NewScanner(stderr)
	var addr string
	for sc.Scan() {
		if m := regexp.MustCompile(`listening on (\S+)`).FindStringSubmatch(sc.Text()); m != nil {
			addr = m[1]
			break
		}
	}
	go func() {
		for sc.Scan() {
		}
	}()
	h := &harness{t: t, addr: addr, origin: addr}
	rss := func() int64 {
		time.Sleep(time.Second)
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "VmRSS:" {
				kb, _ := strconv.ParseInt(f[1], 10, 64)
				return kb << 10
			}
		}
		t.Fatal("no VmRSS")
		return 0
	}
	before := rss()
	seedKeys := func(i int) *link.Keys {
		seed := make([]byte, 32)
		binary.BigEndian.PutUint64(seed, uint64(i)+1)
		seed[31] = 0x5a
		k, err := link.DeriveKeys(seed)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	type netw struct {
		p  *link.Keys
		cs []*client
	}
	var mu sync.Mutex
	var nets []netw
	var wg sync.WaitGroup
	sem := make(chan struct{}, 64)
	for g := 0; g+2 < n; g += 3 {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			p, a, b := seedKeys(g), seedKeys(g+1), seedKeys(g+2)
			r := roster(t, 1, p, a, b)
			// Each network dials from its own loopback address, so ports never run out.
			from := func(d *net.Dialer) {
				d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, byte(1+g/3/250%250), byte(g/3%250), 1)}
			}
			got := netw{p, []*client{h.register(p, p, r, from), h.register(a, p, r, from), h.register(b, p, r, from)}}
			// One frame across each network, so its state is as after traffic.
			got.cs[1].sendBinary(frame(typeData, p.ID, make([]byte, 200)))
			got.cs[0].frame()
			mu.Lock()
			nets = append(nets, got)
			mu.Unlock()
		}()
	}
	wg.Wait()
	after := rss()
	conns := 0
	for _, nw := range nets {
		for _, c := range nw.cs {
			c.ws.Close()
			conns++
		}
	}
	return float64(after-before) / float64(conns)
}
