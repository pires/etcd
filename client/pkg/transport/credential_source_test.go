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

package transport

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// memoryCert is a self-signed ECDSA leaf held only in memory.
func memoryCert(t *testing.T, name string, serial int64) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{name},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// memorySource is a credential source whose certificate and failure a test
// switches; calls counts every consultation.
type memorySource struct {
	mu    sync.Mutex
	cert  *tls.Certificate
	err   error
	calls atomic.Int32
}

func (s *memorySource) Certificate() (*tls.Certificate, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cert, s.err
}

func (s *memorySource) set(cert *tls.Certificate, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cert, s.err = cert, err
}

// pinVerifier accepts exactly one peer leaf, per role, and records calls.
type pinVerifier struct {
	mu      sync.Mutex
	allowed map[bool][]byte
	refuse  atomic.Bool
	seen    map[bool]int
	serials map[bool]*big.Int
}

var errPinRefused = errors.New("test verifier: peer refused")

func newPinVerifier() *pinVerifier {
	return &pinVerifier{allowed: map[bool][]byte{}, seen: map[bool]int{}, serials: map[bool]*big.Int{}}
}

func (v *pinVerifier) allow(server bool, cert *tls.Certificate) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.allowed[server] = cert.Certificate[0]
}

func (v *pinVerifier) VerifyPeer(cs tls.ConnectionState, server bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.seen[server]++
	if v.refuse.Load() || len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, v.allowed[server]) {
		return errPinRefused
	}
	v.serials[server] = cs.PeerCertificates[0].SerialNumber
	return nil
}

type endpoint struct {
	source   *memorySource
	verifier *pinVerifier
	info     TLSInfo
}

func newEndpoint(t *testing.T, name string, serial int64) *endpoint {
	t.Helper()
	e := &endpoint{source: &memorySource{cert: memoryCert(t, name, serial)}, verifier: newPinVerifier(),
		info: TLSInfo{ClientCertAuth: true, ServerName: name}}
	if err := e.info.SetCredentialSource(e.source, e.verifier); err != nil {
		t.Fatal(err)
	}
	return e
}

// pair is a server and a client endpoint that each pin the other's leaf.
func pair(t *testing.T) (*endpoint, *endpoint) {
	t.Helper()
	server, client := newEndpoint(t, "server.test", 1), newEndpoint(t, "client.test", 2)
	server.verifier.allow(false, client.source.cert)
	client.verifier.allow(true, server.source.cert)
	return server, client
}

// serve starts a real TLS listener for e and echoes one line per accepted
// connection until the test ends.
func serve(t *testing.T, e *endpoint) string {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l, err := NewTLSListener(raw, &e.info)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() {
		if err := l.Close(); err != nil {
			t.Logf("closing the listener: %v", err)
		}
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				if _, err := io.Copy(conn, conn); err != nil {
					return
				}
			}()
		}
	}()
	return l.Addr().String()
}

// dial connects e as a client and proves the connection carries data.
func dial(t *testing.T, e *endpoint, addr string) (*tls.Conn, error) {
	t.Helper()
	cfg, err := e.info.ClientConfig()
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	if err := echo(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func echo(conn *tls.Conn) error {
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != "ping" {
		return errors.New("echo mismatch")
	}
	return nil
}

// TestCredentialSourceMutualTLSWithNoFiles: a source-only listener and a
// source-only client complete a mutual TLS 1.3 handshake with no certificate
// files anywhere; both sources and both verifiers are consulted.
func TestCredentialSourceMutualTLSWithNoFiles(t *testing.T) {
	server, client := pair(t)
	if server.info.Empty() || client.info.Empty() || !server.info.HasCredentialSource() {
		t.Fatal("a credential-source TLSInfo reports empty")
	}
	conn, err := dial(t, client, serve(t, server))
	if err != nil {
		t.Fatalf("the source-only handshake: %v", err)
	}
	defer conn.Close()
	if v := conn.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Fatalf("negotiated %x, want TLS 1.3", v)
	}
	if server.source.calls.Load() == 0 || client.source.calls.Load() == 0 {
		t.Fatal("a source was never consulted")
	}
	if client.verifier.seen[true] == 0 || server.verifier.seen[false] == 0 {
		t.Fatal("a verifier was never consulted")
	}
}

// TestCredentialSourceSetterRefusals: nil, typed-nil, a second call and every
// conflicting field are refused by the setter.
func TestCredentialSourceSetterRefusals(t *testing.T) {
	src, ver := &memorySource{cert: memoryCert(t, "a", 1)}, newPinVerifier()
	var nilSource *memorySource
	var nilVerifier *pinVerifier
	if err := (&TLSInfo{}).SetCredentialSource(nil, ver); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("nil source: %v", err)
	}
	if err := (&TLSInfo{}).SetCredentialSource(nilSource, ver); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("typed-nil source: %v", err)
	}
	if err := (&TLSInfo{}).SetCredentialSource(src, nilVerifier); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("typed-nil verifier: %v", err)
	}
	once := &TLSInfo{}
	if err := once.SetCredentialSource(src, ver); err != nil {
		t.Fatal(err)
	}
	if err := once.SetCredentialSource(src, ver); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("a second source: %v", err)
	}
	roots := &TLSInfo{}
	roots.SetDynamicTrustRoots(staticPool{})
	for name, info := range map[string]*TLSInfo{
		"cert file":     {CertFile: "cert.pem"},
		"client key":    {ClientKeyFile: "key.pem"},
		"trusted CA":    {TrustedCAFile: "ca.pem"},
		"CRL":           {CRLFile: "crl.pem"},
		"insecure":      {InsecureSkipVerify: true},
		"allowed CNs":   {AllowedCNs: []string{"x"}},
		"allowed host":  {AllowedHostname: "x"},
		"TLS 1.2 min":   {MinVersion: tls.VersionTLS12},
		"TLS 1.2 max":   {MaxVersion: tls.VersionTLS12},
		"dynamic roots": roots,
	} {
		if err := info.SetCredentialSource(src, ver); !errors.Is(err, ErrCredentialSource) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

type staticPool struct{}

func (staticPool) GetCertPool() *x509.CertPool { return x509.NewCertPool() }

// TestCredentialSourceBuildersRefuseLateMixing: a conflicting field set after
// the source, including SetDynamicTrustRoots in the reverse order, is refused
// by BOTH builders; a copy carries the same source and refuses a second one.
func TestCredentialSourceBuildersRefuseLateMixing(t *testing.T) {
	for name, mix := range map[string]func(*TLSInfo){
		"dynamic roots": func(i *TLSInfo) { i.SetDynamicTrustRoots(staticPool{}) },
		"cert file":     func(i *TLSInfo) { i.CertFile = "cert.pem" },
		"trusted CA":    func(i *TLSInfo) { i.TrustedCAFile = "ca.pem" },
		"insecure":      func(i *TLSInfo) { i.InsecureSkipVerify = true },
		"allowed CNs":   func(i *TLSInfo) { i.AllowedCNs = []string{"x"} },
	} {
		e := newEndpoint(t, "a.test", 1)
		mix(&e.info)
		if _, err := e.info.ServerConfig(); !errors.Is(err, ErrCredentialSource) {
			t.Fatalf("%s: ServerConfig %v", name, err)
		}
		if _, err := e.info.ClientConfig(); !errors.Is(err, ErrCredentialSource) {
			t.Fatalf("%s: ClientConfig %v", name, err)
		}
		if err := e.info.ValidateCredentialSource(); !errors.Is(err, ErrCredentialSource) {
			t.Fatalf("%s: ValidateCredentialSource %v", name, err)
		}
	}
	e := newEndpoint(t, "a.test", 1)
	copied := e.info
	if !copied.HasCredentialSource() || copied.Empty() {
		t.Fatal("a copy lost its source")
	}
	if err := copied.SetCredentialSource(e.source, e.verifier); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("a copy accepted a second source: %v", err)
	}
	if got := copied.String(); got != "credential-source, client-cert-auth = true" {
		t.Fatalf("String names %q", got)
	}
}

// TestCredentialSourceFailureRefusesWithNoFallback: a source that fails at
// build time refuses both builders; one that fails after a listener is built
// refuses the handshake on that side; no file is consulted in its place.
func TestCredentialSourceFailureRefusesWithNoFallback(t *testing.T) {
	errClosed := errors.New("test source: closed")
	e := newEndpoint(t, "a.test", 1)
	e.source.set(nil, errClosed)
	if _, err := e.info.ServerConfig(); !errors.Is(err, errClosed) {
		t.Fatalf("ServerConfig over a failing source: %v", err)
	}
	if _, err := e.info.ClientConfig(); !errors.Is(err, errClosed) {
		t.Fatalf("ClientConfig over a failing source: %v", err)
	}
	e.source.set(&tls.Certificate{}, nil)
	if _, err := e.info.ServerConfig(); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("ServerConfig over an empty certificate: %v", err)
	}

	server, client := pair(t)
	addr := serve(t, server)
	server.source.set(nil, errClosed)
	if conn, err := dial(t, client, addr); err == nil {
		conn.Close()
		t.Fatal("a handshake succeeded with a failing server source")
	}
	server2, client2 := pair(t)
	addr2 := serve(t, server2)
	cfg, err := client2.info.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	client2.source.set(nil, errClosed)
	if conn, err := tls.Dial("tcp", addr2, cfg); err == nil {
		if echo(conn) == nil {
			conn.Close()
			t.Fatal("a handshake succeeded with a failing client source")
		}
		conn.Close()
	}
}

// TestCredentialSourceVerifierDecidesBothDirections: a refusing verifier on
// either side refuses the connection.
func TestCredentialSourceVerifierDecidesBothDirections(t *testing.T) {
	server, client := pair(t)
	addr := serve(t, server)
	client.verifier.refuse.Store(true)
	if conn, err := dial(t, client, addr); err == nil {
		conn.Close()
		t.Fatal("the client accepted a server its verifier refused")
	}
	client.verifier.refuse.Store(false)
	server.verifier.refuse.Store(true)
	if conn, err := dial(t, client, addr); err == nil {
		conn.Close()
		t.Fatal("the server accepted a client its verifier refused")
	}
}

// TestCredentialSourceRenewalAndCloseAffectOnlyNewHandshakes: switching the
// server leaf is seen by the next handshake while an established connection
// keeps working; closing the source refuses new handshakes only. A source
// cannot revoke an established stream.
func TestCredentialSourceRenewalAndCloseAffectOnlyNewHandshakes(t *testing.T) {
	server, client := pair(t)
	addr := serve(t, server)
	first, err := dial(t, client, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	renewed := memoryCert(t, "server.test", 3)
	server.source.set(renewed, nil)
	client.verifier.allow(true, renewed)
	second, err := dial(t, client, addr)
	if err != nil {
		t.Fatalf("a handshake after renewal: %v", err)
	}
	defer second.Close()
	if client.verifier.serials[true].Int64() != 3 {
		t.Fatalf("the renewed handshake presented serial %v", client.verifier.serials[true])
	}
	if err := echo(first); err != nil {
		t.Fatalf("the established connection after renewal: %v", err)
	}
	server.source.set(nil, errors.New("test source: closed"))
	if conn, err := dial(t, client, addr); err == nil {
		conn.Close()
		t.Fatal("a handshake succeeded after the source closed")
	}
	if err := echo(second); err != nil {
		t.Fatalf("the established connection after close: %v", err)
	}
}

// TestCredentialSourceBuiltConfigKeepsItsOriginalBinding: a configuration
// built from one TLSInfo keeps consulting the source it was built with.
func TestCredentialSourceBuiltConfigKeepsItsOriginalBinding(t *testing.T) {
	e := newEndpoint(t, "a.test", 1)
	cfg, err := e.info.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	other := newEndpoint(t, "b.test", 9)
	e.info = other.info
	got, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil || got.Leaf.SerialNumber.Int64() != 1 {
		t.Fatalf("the built config followed a reassigned TLSInfo: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS13 || cfg.ClientAuth != tls.RequireAnyClientCert {
		t.Fatalf("the built server config: min %x, client auth %v", cfg.MinVersion, cfg.ClientAuth)
	}
}

// TestCredentialSourceRefusesUnusableCertificates: a typed-nil or non-signer
// private key and an empty leaf are refused by both builders, every time.
func TestCredentialSourceRefusesUnusableCertificates(t *testing.T) {
	good := memoryCert(t, "a.test", 1)
	var nilKey *ecdsa.PrivateKey
	for name, cert := range map[string]*tls.Certificate{
		"typed-nil key":   {Certificate: good.Certificate, PrivateKey: nilKey},
		"non-signer key":  {Certificate: good.Certificate, PrivateKey: "not a key"},
		"no key":          {Certificate: good.Certificate},
		"empty leaf":      {Certificate: [][]byte{{}}, PrivateKey: good.PrivateKey},
		"no chain":        {PrivateKey: good.PrivateKey},
		"nil certificate": nil,
	} {
		e := newEndpoint(t, "a.test", 1)
		e.source.set(cert, nil)
		for range 2 {
			if _, err := e.info.ServerConfig(); !errors.Is(err, ErrCredentialSource) {
				t.Fatalf("%s: ServerConfig %v", name, err)
			}
			if _, err := e.info.ClientConfig(); !errors.Is(err, ErrCredentialSource) {
				t.Fatalf("%s: ClientConfig %v", name, err)
			}
		}
	}
}

// TestCredentialSourceVersionPolicyIsNeverLowered: an explicit minimum above
// TLS 1.3 is kept by both builders, a maximum below the effective minimum is
// refused by both builders and by validation, and an unset minimum is TLS 1.3.
func TestCredentialSourceVersionPolicyIsNeverLowered(t *testing.T) {
	const future = tls.VersionTLS13 + 1
	e := newEndpoint(t, "a.test", 1)
	e.info.MinVersion = future
	server, err := e.info.ServerConfig()
	if err != nil {
		t.Fatal(err)
	}
	client, err := e.info.ClientConfig()
	if err != nil {
		t.Fatal(err)
	}
	if server.MinVersion != future || client.MinVersion != future {
		t.Fatalf("a higher minimum was lowered: server %x, client %x", server.MinVersion, client.MinVersion)
	}

	e.info.MaxVersion = tls.VersionTLS13
	if _, err := e.info.ServerConfig(); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("ServerConfig with max below min: %v", err)
	}
	if _, err := e.info.ClientConfig(); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("ClientConfig with max below min: %v", err)
	}
	if err := e.info.ValidateCredentialSource(); !errors.Is(err, ErrCredentialSource) {
		t.Fatalf("ValidateCredentialSource with max below min: %v", err)
	}

	d := newEndpoint(t, "b.test", 2)
	d.info.MaxVersion = tls.VersionTLS13
	cfg, err := d.info.ServerConfig()
	if err != nil || cfg.MinVersion != tls.VersionTLS13 || cfg.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("the default minimum with max TLS 1.3: %v", err)
	}
}
