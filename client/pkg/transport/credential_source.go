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
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"slices"
)

// ErrCredentialSource refuses a credential source that is missing, mixed with
// another credential or verification mechanism, or unable to supply a
// certificate.
var ErrCredentialSource = errors.New("transport: invalid credential source")

// CredentialSource supplies this endpoint's certificate and private key from
// memory. It is consulted on every handshake, in both the server and client
// roles. Any error, or a certificate with no chain or no private key, refuses
// that handshake: no certificate file is ever read in its place. The source's
// owner decides renewal and closing; once it reports an error, new handshakes
// are refused. Connections that already completed a handshake are not
// re-examined, so a source cannot revoke an established stream.
//
// Implementations must be safe for concurrent use.
type CredentialSource interface {
	Certificate() (*tls.Certificate, error)
}

// PeerVerifier is the whole identity decision for a credential-source
// endpoint. It receives the completed handshake state: server is true when
// the local side is the client verifying a server, and false when the local
// side is a server verifying a client. The standard chain verification is
// not run on these connections, so the verifier owns chain, name and
// revocation checks. Implementations must be safe for concurrent use.
type PeerVerifier interface {
	VerifyPeer(cs tls.ConnectionState, server bool) error
}

// credentialBinding is the immutable pair a TLSInfo was given. Copies of the
// TLSInfo share it, and every built tls.Config captures it at build time.
type credentialBinding struct {
	source   CredentialSource
	verifier PeerVerifier
}

// SetCredentialSource makes info a credential-source endpoint. It may be
// called once, with a non-nil source and verifier, on a TLSInfo that has no
// certificate, key, trusted CA or CRL files, no self-signed certificate, no
// dynamic trust roots, no InsecureSkipVerify, no allowed CN or hostname
// lists, and no TLS version below 1.3. The same rules are checked again by
// every builder, so a conflicting field set after this call is refused when
// a configuration is built, whatever the order of the setters.
func (info *TLSInfo) SetCredentialSource(source CredentialSource, verifier PeerVerifier) error {
	if info == nil || isNilInterface(source) || isNilInterface(verifier) {
		return fmt.Errorf("%w: a nil source or verifier", ErrCredentialSource)
	}
	if info.credentials != nil {
		return fmt.Errorf("%w: a credential source is already set", ErrCredentialSource)
	}
	if err := info.credentialConflicts(); err != nil {
		return err
	}
	info.credentials = &credentialBinding{source: source, verifier: verifier}
	return nil
}

// HasCredentialSource reports whether info was given a credential source.
func (info TLSInfo) HasCredentialSource() bool { return info.credentials != nil }

// ValidateCredentialSource is nil for a TLSInfo without a credential source,
// and otherwise reports any field that conflicts with one.
func (info TLSInfo) ValidateCredentialSource() error {
	if info.credentials == nil {
		return nil
	}
	return info.credentialConflicts()
}

// credentialConflicts reports a field that a credential-source endpoint
// cannot combine with.
func (info TLSInfo) credentialConflicts() error {
	switch {
	case info.CertFile != "" || info.KeyFile != "" || info.ClientCertFile != "" || info.ClientKeyFile != "":
		return fmt.Errorf("%w: certificate or key files are set", ErrCredentialSource)
	case info.TrustedCAFile != "" || info.CRLFile != "":
		return fmt.Errorf("%w: trusted CA or CRL files are set", ErrCredentialSource)
	case info.selfCert || info.parseFunc != nil:
		return fmt.Errorf("%w: a self-signed or file-parsed certificate is set", ErrCredentialSource)
	case info.dynamicTrustRoots != nil:
		return fmt.Errorf("%w: dynamic trust roots are set", ErrCredentialSource)
	case info.InsecureSkipVerify:
		return fmt.Errorf("%w: InsecureSkipVerify is set", ErrCredentialSource)
	case info.AllowedCN != "" || info.AllowedHostname != "" || len(info.AllowedCNs) > 0 || len(info.AllowedHostnames) > 0:
		return fmt.Errorf("%w: allowed CN or hostname lists are set; the verifier owns identity", ErrCredentialSource)
	case info.MinVersion != 0 && info.MinVersion < tls.VersionTLS13:
		return fmt.Errorf("%w: a TLS version below 1.3 is allowed", ErrCredentialSource)
	case info.MaxVersion != 0 && info.MaxVersion < credentialMinVersion(info):
		return fmt.Errorf("%w: the maximum TLS version is below the minimum", ErrCredentialSource)
	}
	return nil
}

// credentialMinVersion is the effective minimum TLS version of a
// credential-source endpoint: TLS 1.3, or the caller's higher minimum. A
// caller's stricter policy is never lowered.
func credentialMinVersion(info TLSInfo) uint16 {
	return max(uint16(tls.VersionTLS13), info.MinVersion)
}

// isNilInterface reports a nil interface or one holding a nil pointer, map,
// slice, function or channel.
func isNilInterface(v any) bool {
	if v == nil {
		return true
	}
	r := reflect.ValueOf(v)
	switch r.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return r.IsNil()
	}
	return false
}

// credentialCertificate is one usable certificate from source, or a refusal.
func credentialCertificate(source CredentialSource) (*tls.Certificate, error) {
	cert, err := source.Certificate()
	if err != nil {
		return nil, errors.Join(ErrCredentialSource, err)
	}
	if cert == nil || len(cert.Certificate) == 0 || len(cert.Certificate[0]) == 0 {
		return nil, fmt.Errorf("%w: the source returned no leaf certificate", ErrCredentialSource)
	}
	if isNilInterface(cert.PrivateKey) {
		return nil, fmt.Errorf("%w: the source returned no private key", ErrCredentialSource)
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok || isNilInterface(signer.Public()) {
		return nil, fmt.Errorf("%w: the source's private key is not a signer", ErrCredentialSource)
	}
	return cert, nil
}

// credentialBaseConfig is the TLS 1.3 configuration both roles share. It
// refuses to build unless the source supplies a certificate now, and its
// callbacks consult only the binding captured here.
func (info TLSInfo) credentialBaseConfig() (*tls.Config, *credentialBinding, error) {
	b := info.credentials
	if b == nil {
		return nil, nil, fmt.Errorf("%w: no credential source", ErrCredentialSource)
	}
	if err := info.credentialConflicts(); err != nil {
		return nil, nil, err
	}
	if _, err := credentialCertificate(b.source); err != nil {
		return nil, nil, err
	}
	source := b.source
	cfg := &tls.Config{
		MinVersion:       credentialMinVersion(info),
		MaxVersion:       info.MaxVersion,
		ServerName:       info.ServerName,
		CurvePreferences: slices.Clone(info.CurvePreferences),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return credentialCertificate(source)
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return credentialCertificate(source)
		},
	}
	return cfg, b, nil
}

// credentialServerConfig is ServerConfig for a credential-source endpoint.
// With ClientCertAuth, every client must present a certificate and the
// verifier decides it; without it, no client certificate is requested.
func (info TLSInfo) credentialServerConfig() (*tls.Config, error) {
	cfg, b, err := info.credentialBaseConfig()
	if err != nil {
		return nil, err
	}
	cfg.ClientAuth = tls.NoClientCert
	if info.ClientCertAuth {
		verifier := b.verifier
		cfg.ClientAuth = tls.RequireAnyClientCert
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("%w: the client presented no certificate", ErrCredentialSource)
			}
			return verifier.VerifyPeer(cs, false)
		}
	}
	cfg.NextProtos = []string{"h2"}
	return cfg, nil
}

// credentialClientConfig is ClientConfig for a credential-source endpoint.
// The standard chain check is replaced, not skipped: the verifier decides
// every server certificate, and a server presenting none is refused.
func (info TLSInfo) credentialClientConfig() (*tls.Config, error) {
	cfg, b, err := info.credentialBaseConfig()
	if err != nil {
		return nil, err
	}
	if info.EmptyCN {
		cert, err := credentialCertificate(b.source)
		if err != nil {
			return nil, err
		}
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, errors.Join(ErrCredentialSource, err)
		}
		if leaf.Subject.CommonName != "" {
			return nil, fmt.Errorf("%w: cert has non empty Common Name (%s)", ErrCredentialSource, leaf.Subject.CommonName)
		}
	}
	verifier := b.verifier
	// The verifier below is the server-certificate check; Go's own chain check
	// is turned off only because it is replaced by this one.
	cfg.InsecureSkipVerify = true
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("%w: the server presented no certificate", ErrCredentialSource)
		}
		return verifier.VerifyPeer(cs, true)
	}
	return cfg, nil
}
