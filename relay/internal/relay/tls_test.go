package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// With LINK_TLS_CERT and LINK_TLS_KEY the relay terminates TLS itself, and the origin of a
// wss URL on the default port has no port.
func TestTLS(t *testing.T) {
	dir := t.TempDir()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.test"},
		DNSNames: []string{"relay.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)

	h := start(t, func(c *Config) { c.TLSCert, c.TLSKey = certFile, keyFile })
	addr := h.addr
	d := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		NetDial:         func(network, _ string) (net.Conn, error) { return net.Dial(network, addr) },
	}
	ws, _, err := d.Dial("wss://relay.test/v1", nil) // Host: relay.test, port 443 implied
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()
	c := &client{t: t, ws: ws}
	hello := c.json()
	c.challenge, _ = b64dec(hello["challenge"].(string))
	p := keys(t, 1)
	h.origin = "relay.test"
	c.send(h.registerMsg(c, p, p.ID.String(), roster(t, 1, p)))
	if m := c.json(); m["type"] != "registered" {
		t.Fatalf("got %v", m)
	}
	c.send(map[string]any{"type": "usage", "id": "tls"})
	var u map[string]any
	_, b, err := c.next(5 * time.Second)
	if err != nil || json.Unmarshal(b, &u) != nil || u["id"] != "tls" {
		t.Fatalf("usage over TLS: %s %v", b, err)
	}
}
