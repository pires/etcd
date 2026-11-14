// Copyright 2026 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package embed

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/server/v3/etcdserver/api/v3client"
)

// embedSource is an in-memory credential source holding one ECDSA leaf.
type embedSource struct{ cert *tls.Certificate }

func (s embedSource) Certificate() (*tls.Certificate, error) { return s.cert, nil }

// embedPin accepts exactly the leaves it was given, in either role.
type embedPin struct{ allowed [][]byte }

func (p embedPin) VerifyPeer(cs tls.ConnectionState, _ bool) error {
	for _, raw := range p.allowed {
		if len(cs.PeerCertificates) > 0 && bytes.Equal(cs.PeerCertificates[0].Raw, raw) {
			return nil
		}
	}
	return errors.New("test verifier: peer refused")
}

func embedCert(t *testing.T, name string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name, "localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// sourceTLS is a credential-source TLSInfo for cert that trusts allowed.
func sourceTLS(t *testing.T, cert *tls.Certificate, allowed ...*tls.Certificate) transport.TLSInfo {
	t.Helper()
	pin := embedPin{}
	for _, c := range allowed {
		pin.allowed = append(pin.allowed, c.Certificate[0])
	}
	info := transport.TLSInfo{ClientCertAuth: true, SkipClientSANVerify: true}
	if err := info.SetCredentialSource(embedSource{cert: cert}, pin); err != nil {
		t.Fatal(err)
	}
	return info
}

// secureSocketURLs are TLS unix-socket URLs unique to this process.
func secureSocketURLs(n int) []url.URL {
	urls := make([]url.URL, n)
	for i := range urls {
		urls[i] = url.URL{Scheme: "unixs", Host: fmt.Sprintf("localhost:%d%06d", os.Getpid(), 900000+i)}
	}
	return urls
}

// TestCredentialSourceConfigValidation: a credential source beside a
// certificate file or auto TLS is refused, as is the gRPC gateway beside a
// client source with no explicit ServerName; source-only configurations,
// including the gateway with a ServerName, validate.
func TestCredentialSourceConfigValidation(t *testing.T) {
	cert := embedCert(t, "member.test")
	for name, edit := range map[string]func(*Config){
		"client cert file": func(c *Config) { c.ClientTLSInfo.CertFile = "cert.pem" },
		"peer trusted CA":  func(c *Config) { c.PeerTLSInfo.TrustedCAFile = "ca.pem" },
		"client auto TLS":  func(c *Config) { c.ClientAutoTLS = true },
		"peer auto TLS":    func(c *Config) { c.PeerAutoTLS = true },
		"gateway, no name": func(c *Config) { c.EnableGRPCGateway = true },
	} {
		cfg := NewConfig()
		cfg.Dir = t.TempDir()
		cfg.EnableGRPCGateway = false
		cfg.ClientTLSInfo = sourceTLS(t, cert, cert)
		cfg.PeerTLSInfo = sourceTLS(t, cert, cert)
		edit(cfg)
		if err := cfg.Validate(); !errors.Is(err, transport.ErrCredentialSource) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	cfg := NewConfig()
	cfg.Dir = t.TempDir()
	cfg.EnableGRPCGateway = false
	cfg.ClientTLSInfo = sourceTLS(t, cert, cert)
	cfg.PeerTLSInfo = sourceTLS(t, cert, cert)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("a source-only configuration: %v", err)
	}
	cfg.EnableGRPCGateway = true
	cfg.ClientTLSInfo.ServerName = "member.test"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the gateway beside a named client source: %v", err)
	}
}

// TestStartEtcdWithCredentialSourcesOnly: one member starts with client and
// peer credential sources and no certificate files. A real client over the
// client source's ClientConfig writes and reads, and a real dial to the peer
// listener with the peer source's ClientConfig is served.
func TestStartEtcdWithCredentialSourcesOnly(t *testing.T) {
	member, client := embedCert(t, "member.test"), embedCert(t, "client.test")
	urls := secureSocketURLs(2)
	cfg := NewConfig()
	cfg.Dir = t.TempDir()
	cfg.EnableGRPCGateway = false
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{urls[0]}, []url.URL{urls[0]}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{urls[1]}, []url.URL{urls[1]}
	cfg.InitialCluster = "default=" + urls[1].String()
	cfg.ClientTLSInfo = sourceTLS(t, member, client)
	cfg.PeerTLSInfo = sourceTLS(t, member, member)
	e, err := StartEtcd(cfg)
	if err != nil {
		t.Fatalf("StartEtcd with credential sources only: %v", err)
	}
	t.Cleanup(e.Close)
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("the member did not become ready")
	}

	clientInfo := sourceTLS(t, client, member)
	clientTLS, err := clientInfo.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	cli, err := clientv3.New(clientv3.Config{Endpoints: []string{urls[0].String()}, TLS: clientTLS, DialTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := cli.Close(); err != nil {
			t.Logf("closing the client: %v", err)
		}
	})
	if _, err := cli.Put(t.Context(), "k", "v"); err != nil {
		t.Fatalf("Put over the credential-source client: %v", err)
	}
	got, err := cli.Get(t.Context(), "k")
	if err != nil || len(got.Kvs) != 1 || string(got.Kvs[0].Value) != "v" {
		t.Fatalf("Get over the credential-source client: %v", err)
	}

	peerInfo := sourceTLS(t, member, member)
	peerTLS, err := peerInfo.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("unix", urls[1].Host, peerTLS)
	if err != nil {
		t.Fatalf("dialling the peer listener: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("GET /version HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("reading the peer reply: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Proto, "HTTP/1") {
		t.Fatalf("the peer listener replied %s", resp.Status)
	}
}

// roleVerifier accepts, per role, exactly the leaves it was given, and records
// what each role saw. server is true when the local side verifies a server.
type roleVerifier struct {
	mu          sync.Mutex
	allowed     map[bool][][]byte
	serverCalls int
	clientNames []string
}

func (v *roleVerifier) VerifyPeer(cs tls.ConnectionState, server bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if server {
		v.serverCalls++
	} else {
		v.clientNames = append(v.clientNames, cs.ServerName)
	}
	for _, raw := range v.allowed[server] {
		if len(cs.PeerCertificates) > 0 && bytes.Equal(cs.PeerCertificates[0].Raw, raw) {
			return nil
		}
	}
	return errors.New("test verifier: peer refused")
}

func (v *roleVerifier) seen() (int, []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.serverCalls, append([]string(nil), v.clientNames...)
}

// switchSource is a member credential source a test can make fail and then
// restore.
type switchSource struct {
	mu    sync.Mutex
	cert  *tls.Certificate
	err   error
	calls int
}

func (s *switchSource) consulted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *switchSource) Certificate() (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.cert, nil
}

func (s *switchSource) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

// gatewayWorld is one running gateway member and the external client that
// reaches it.
type gatewayWorld struct {
	etcd        *Etcd
	source      *switchSource
	client      url.URL
	verifier    *roleVerifier
	externalTLS *tls.Config
}

// gatewayMember starts one member whose client listener is a credential
// source named "member.test", with the gRPC gateway enabled. Its verifier
// admits the member's own leaf and the external client as clients; it
// admits the member's own leaf as a server only when trustSelf.
func gatewayMember(t *testing.T, trustSelf bool) gatewayWorld {
	t.Helper()
	member, external := embedCert(t, "member.test"), embedCert(t, "external.test")
	urls := secureSocketURLs(2)
	verifier := &roleVerifier{allowed: map[bool][][]byte{false: {member.Certificate[0], external.Certificate[0]}}}
	if trustSelf {
		verifier.allowed[true] = [][]byte{member.Certificate[0]}
	}
	cfg := NewConfig()
	cfg.Dir = t.TempDir()
	cfg.EnableGRPCGateway = true
	cfg.ListenClientUrls, cfg.AdvertiseClientUrls = []url.URL{urls[0]}, []url.URL{urls[0]}
	cfg.ListenPeerUrls, cfg.AdvertisePeerUrls = []url.URL{urls[1]}, []url.URL{urls[1]}
	cfg.InitialCluster = "default=" + urls[1].String()
	cfg.ClientTLSInfo = transport.TLSInfo{ClientCertAuth: true, ServerName: "member.test"}
	source := &switchSource{cert: member}
	if err := cfg.ClientTLSInfo.SetCredentialSource(source, verifier); err != nil {
		t.Fatal(err)
	}
	cfg.PeerTLSInfo = sourceTLS(t, member, member)
	e, err := StartEtcd(cfg)
	if err != nil {
		t.Fatalf("StartEtcd with the gateway beside a client source: %v", err)
	}
	t.Cleanup(e.Close)
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(30 * time.Second):
		t.Fatal("the member did not become ready")
	}
	externalInfo := transport.TLSInfo{ServerName: "external.test"}
	if err := externalInfo.SetCredentialSource(embedSource{cert: external}, embedPin{allowed: [][]byte{member.Certificate[0]}}); err != nil {
		t.Fatal(err)
	}
	externalTLS, err := externalInfo.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	return gatewayWorld{etcd: e, source: source, client: urls[0], verifier: verifier, externalTLS: externalTLS}
}

// gatewayPut sends one gateway Put over the client socket and returns the
// HTTP status.
func gatewayPut(t *testing.T, client url.URL, tlsCfg *tls.Config) int {
	t.Helper()
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{
		TLSClientConfig: tlsCfg,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", client.Host)
		},
	}}
	t.Cleanup(httpClient.CloseIdleConnections)
	resp, err := httpClient.Post("https://member.test/v3/kv/put", "application/json",
		strings.NewReader(`{"key":"Z2F0ZXdheQ==","value":"b2s="}`))
	if err != nil {
		t.Fatalf("the gateway request: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("reading the gateway reply: %v", err)
	}
	return resp.StatusCode
}

// TestGRPCGatewaySelfDialsWithTheClientSource: with the gateway enabled
// beside a client credential source, a gateway request succeeds only through
// the self-dial: the member's verifier decides the local server in the
// server direction, and the gateway's own connection presents the explicit
// ServerName "member.test", never a name derived from the socket.
func TestGRPCGatewaySelfDialsWithTheClientSource(t *testing.T) {
	w := gatewayMember(t, true)
	if status := gatewayPut(t, w.client, w.externalTLS); status != http.StatusOK {
		t.Fatalf("the gateway Put returned %d", status)
	}
	serverCalls, names := w.verifier.seen()
	if serverCalls == 0 {
		t.Fatal("the self-dial never ran the verifier in the server direction")
	}
	if !slices.Contains(names, "member.test") {
		t.Fatalf("no client connection presented the explicit ServerName: %q", names)
	}
	for _, name := range names {
		if name != "member.test" && name != "external.test" {
			t.Fatalf("a connection presented a derived name %q", name)
		}
	}
}

// TestGRPCGatewayRefusesAServerItsVerifierRejects: the same member whose
// verifier does not admit its own leaf as a server cannot complete the
// gateway's self-dial, so the gateway request fails while the external
// client's own connection is admitted.
func TestGRPCGatewayRefusesAServerItsVerifierRejects(t *testing.T) {
	w := gatewayMember(t, false)
	if status := gatewayPut(t, w.client, w.externalTLS); status == http.StatusOK {
		t.Fatal("the gateway Put succeeded through a self-dial the verifier refused")
	}
	if serverCalls, _ := w.verifier.seen(); serverCalls == 0 {
		t.Fatal("the refused self-dial never consulted the verifier")
	}
}

// TestGRPCGatewayDialRefusesAFailingClientSource closes the named
// source-failure gap at the exact scope of the self-dial CONFIGURATION:
// over an actual running member, its actual client credential source is
// made to fail and the member's real grpcGatewayDial factory is invoked
// in-package. The factory must yield an error and no connection. The source
// is restored before teardown. This does not claim a full gateway request
// fails, since the external handshake shares the same failing source.
func TestGRPCGatewayDialRefusesAFailingClientSource(t *testing.T) {
	w := gatewayMember(t, true)
	errSourceClosed := errors.New("test source: closed")
	w.source.fail(errSourceClosed)
	t.Cleanup(func() { w.source.fail(nil) })
	dial := w.etcd.grpcGatewayDial(false)
	if dial == nil {
		t.Fatal("the gateway is enabled but no self-dial factory was built")
	}
	conn, err := dial(t.Context())
	if !errors.Is(err, errSourceClosed) || !errors.Is(err, transport.ErrCredentialSource) || conn != nil {
		t.Fatalf("the self-dial over a failing source: %v, connection %v", err, conn)
	}
	w.source.fail(nil)
	restored := w.etcd.grpcGatewayDial(false)
	conn, err = restored(t.Context())
	if err != nil || conn == nil {
		t.Fatalf("the self-dial after the source was restored: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("closing the restored self-dial: %v", err)
	}
}

// TestGRPCGatewaySelfDialHandshakeRefusesAFailingClientSource: the scope is a
// REAL self-dial handshake, not a full gateway HTTP request. Over an actual
// running gateway member, the member's real grpcGatewayDial factory is built
// while the source is healthy, so its TLS configuration is frozen first. The
// actual source is then made to fail, the factory is invoked (grpc.NewClient
// performs no I/O), and a KV Put over the returned connection forces a fresh
// handshake. The handshake consults the failed source, the Put is refused,
// and the key is absent. The source is restored before teardown.
func TestGRPCGatewaySelfDialHandshakeRefusesAFailingClientSource(t *testing.T) {
	w := gatewayMember(t, true)
	dial := w.etcd.grpcGatewayDial(false)
	if dial == nil {
		t.Fatal("the gateway is enabled but no self-dial factory was built")
	}
	errSourceClosed := errors.New("test source: closed")
	w.source.fail(errSourceClosed)
	t.Cleanup(func() { w.source.fail(nil) })
	before := w.source.consulted()
	conn, err := dial(t.Context())
	if err != nil || conn == nil {
		t.Fatalf("the frozen factory refused before any I/O: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Logf("closing the self-dial: %v", err)
		}
	})
	rpc, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	if _, err := pb.NewKVClient(conn).Put(rpc, &pb.PutRequest{Key: []byte("self-dial"), Value: []byte("v")}); err == nil {
		t.Fatal("a Put succeeded over a self-dial whose source failed")
	}
	if w.source.consulted() <= before {
		t.Fatal("the self-dial handshake never consulted the failed source")
	}
	w.source.fail(nil)
	local := v3client.New(w.etcd.Server)
	t.Cleanup(func() {
		if err := local.Close(); err != nil {
			t.Logf("closing the local client: %v", err)
		}
	})
	got, err := local.Get(t.Context(), "self-dial")
	if err != nil || len(got.Kvs) != 0 {
		t.Fatalf("the refused Put left an effect: %v, %d keys", err, len(got.Kvs))
	}
}
