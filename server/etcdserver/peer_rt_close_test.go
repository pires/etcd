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

package etcdserver

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/pkg/v3/idutil"
	"go.etcd.io/etcd/server/v3/auth"
	"go.etcd.io/etcd/server/v3/config"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	"go.etcd.io/etcd/server/v3/etcdserver/api/rafthttp"
	"go.etcd.io/etcd/server/v3/etcdserver/cindex"
	"go.etcd.io/etcd/server/v3/etcdserver/errors"
	"go.etcd.io/etcd/server/v3/features"
	"go.etcd.io/etcd/server/v3/lease"
	"go.etcd.io/etcd/server/v3/mock/mockstorage"
	serverstorage "go.etcd.io/etcd/server/v3/storage"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/schema"
	"go.etcd.io/raft/v3"
)

// peerTestBound bounds the waits below that something this test caused
// happens. It is a failure bound, never what makes a case pass.
const peerTestBound = 10 * time.Second

// observedConn is a peer connection that reports its own Close.
type observedConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *observedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// observedPeerRoundTripper is the round tripper bootstrap builds, keep-alive
// with pooled idle connections and no idle timeout, whose dials are observed:
// every connection it opens is sent on the returned channel.
func observedPeerRoundTripper(t *testing.T) (*http.Transport, <-chan *observedConn) {
	t.Helper()
	rt, err := rafthttp.NewRoundTripper(transport.TLSInfo{}, time.Second)
	require.NoError(t, err)
	tr, ok := rt.(*http.Transport)
	require.True(t, ok, "the peer round tripper is %T, want *http.Transport", rt)
	dials := make(chan *observedConn, 16)
	// The test owns this pool: whatever a case leaves open, including after a
	// failed assertion, is closed when the test ends.
	t.Cleanup(tr.CloseIdleConnections)
	var d net.Dialer
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := d.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		oc := &observedConn{Conn: c, closed: make(chan struct{})}
		dials <- oc
		return oc, nil
	}
	return tr, dials
}

// idlePeerConn sends one request through tr to peerURL, reads and closes the
// response, and returns the connection once tr has put it in its idle pool.
// PutIdleConn is that pool's own report, so the connection is idle, not
// merely answered, when this returns.
func idlePeerConn(t *testing.T, tr *http.Transport, dials <-chan *observedConn, peerURL string) *observedConn {
	t.Helper()
	pooled := make(chan error, 1)
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{
		PutIdleConn: func(err error) { pooled <- err },
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, peerURL, nil)
	require.NoError(t, err)
	resp, err := (&http.Client{Transport: tr}).Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	select {
	case err := <-pooled:
		require.NoError(t, err, "the transport refused the connection to its idle pool")
	case <-time.After(peerTestBound):
		t.Fatal("the transport never put the connection in its idle pool")
	}
	select {
	case c := <-dials:
		return c
	default:
		t.Fatal("the request dialed no observed connection")
		return nil
	}
}

func requireOpen(t *testing.T, c *observedConn, before string) {
	t.Helper()
	select {
	case <-c.closed:
		t.Fatalf("the peer connection was closed before %s; the case below would decide nothing", before)
	default:
	}
}

func requireClosed(t *testing.T, c *observedConn, by string) {
	t.Helper()
	select {
	case <-c.closed:
	default:
		t.Fatalf("%s returned with the peer connection still open", by)
	}
}

func requireNoDial(t *testing.T, dials <-chan *observedConn, by string) {
	t.Helper()
	select {
	case <-dials:
		t.Fatalf("%s dialed a peer", by)
	default:
	}
}

func okPeer(t *testing.T) *httptest.Server {
	t.Helper()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(peer.Close)
	return peer
}

// followerServer is a started server that follows a leader whose peer URL is
// leaderURL, sending its peer requests through tr.
func followerServer(t *testing.T, tr *http.Transport, leaderURL string) *EtcdServer {
	t.Helper()
	lg := zaptest.NewLogger(t)
	be, _ := betesting.NewDefaultTmpBackend(t)
	t.Cleanup(func() { betesting.Close(t, be) })
	cl := newTestCluster(t)
	cl.SetBackend(schema.NewMembershipBackend(lg, be))
	leaderURLs, err := types.NewURLs([]string{leaderURL})
	require.NoError(t, err)
	leader := membership.NewMember("leader", leaderURLs, "test", nil)
	cl.AddMember(leader, true)
	r := newRaftNode(raftNodeConfig{
		lg:          lg,
		Node:        newNodeConfChangeCommitterRecorder(),
		raftStorage: raft.NewMemoryStorage(),
		storage:     mockstorage.NewStorageRecorder(""),
		transport:   newNopTransporter(),
	})
	s := &EtcdServer{
		lgMu:         new(sync.RWMutex),
		lg:           lg,
		Cfg:          config.ServerConfig{Logger: lg, TickMs: 1, ElectionTicks: 10, ServerFeatureGate: features.NewDefaultServerFeatureGate("test", lg)},
		r:            *r,
		cluster:      cl,
		memberID:     types.ID(1),
		peerRt:       tr,
		reqIDGen:     idutil.NewGenerator(0, time.Time{}),
		consistIndex: cindex.NewFakeConsistentIndex(0),
		beHooks:      serverstorage.NewBackendHooks(lg, nil),
		authStore:    auth.NewAuthStore(lg, schema.NewAuthBackend(lg, be), nil, 0),
	}
	s.start()
	// A case that fails before its own Stop still stops the server, before
	// its backend closes. A second Stop returns once the server is done.
	t.Cleanup(s.Stop)
	s.setLead(uint64(leader.ID))
	return s
}

// A server that never started is cleaned up with Cleanup, which closes the
// peer pool it owns.
func TestCleanupClosesIdlePeerConnection(t *testing.T) {
	tr, dials := observedPeerRoundTripper(t)
	conn := idlePeerConn(t, tr, dials, okPeer(t).URL)
	s := &EtcdServer{peerRt: tr}
	requireOpen(t, conn, "Cleanup")
	s.Cleanup()
	requireClosed(t, conn, "Cleanup")
}

// A started server that stops normally has closed its peer pool by the time
// Stop returns.
func TestStopClosesIdlePeerConnection(t *testing.T) {
	tr, dials := observedPeerRoundTripper(t)
	peer := okPeer(t)
	s := followerServer(t, tr, peer.URL)
	conn := idlePeerConn(t, tr, dials, peer.URL)
	requireOpen(t, conn, "Stop")
	s.Stop()
	requireClosed(t, conn, "Stop")
}

// A request forwarded to the leader when the server stops is canceled and
// joined by shutdown before the server reports itself stopped, so its
// connection is closed rather than left to whoever answers last.
//
// Each forward is reached the way a follower reaches it: the server is not the
// leader, and for a promotion the recorder node's raft status has no progress,
// so isLearnerReady answers ErrNotLeader and PromoteMember forwards.
func TestStopJoinsInFlightPeerForwards(t *testing.T) {
	for _, tc := range []struct {
		name    string
		forward func(context.Context, *EtcdServer) error
	}{
		{"lease renewal", func(ctx context.Context, s *EtcdServer) error {
			_, err := s.LeaseRenew(ctx, lease.LeaseID(1))
			return err
		}},
		{"lease time-to-live", func(ctx context.Context, s *EtcdServer) error {
			_, err := s.leaseTimeToLive(ctx, &pb.LeaseTimeToLiveRequest{ID: 1})
			return err
		}},
		{"member promotion", func(ctx context.Context, s *EtcdServer) error {
			_, err := s.PromoteMember(ctx, 2)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr, dials := observedPeerRoundTripper(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			peer := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				// The request body is read whole and closed first: the server
				// watches for the client going away only once the body is
				// consumed, so the handler sees the forward's cancellation.
				_, err := io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
				if closeErr := r.Body.Close(); err == nil {
					err = closeErr
				}
				if err != nil {
					t.Errorf("reading the forwarded request: %v", err)
				}
				once.Do(func() { close(entered) })
				select {
				case <-r.Context().Done():
				case <-release:
				}
			}))
			t.Cleanup(peer.Close)
			// Registered after peer.Close, so it runs first: a case that fails
			// with the handler still blocked releases it, and peer.Close never
			// waits on it.
			t.Cleanup(func() { close(release) })
			s := followerServer(t, tr, peer.URL)

			// The forward runs on a context this case owns. Whatever the case
			// ends with, a failed assertion included, its cleanup cancels the
			// forward and joins it before the peer closes, so a case that fails
			// leaves no forward running and no handler waiting.
			forwardCtx, cancelForward := context.WithCancel(context.Background())
			forwarded := make(chan error, 1)
			returned := make(chan struct{})
			go func() {
				defer close(returned)
				forwarded <- tc.forward(forwardCtx, s)
			}()
			t.Cleanup(func() {
				cancelForward()
				select {
				case <-returned:
				case <-time.After(peerTestBound):
					t.Errorf("the forward did not return after its context was canceled")
				}
			})
			select {
			case <-entered:
			case <-time.After(peerTestBound):
				t.Fatal("the forward never reached the leader")
			}
			var conn *observedConn
			select {
			case conn = <-dials:
			default:
				t.Fatal("the forward reached the leader without an observed connection")
			}
			requireOpen(t, conn, "Stop")
			s.Stop()
			// The closed connection is what proves the forward ended before Stop
			// returned. Its result reaches this test only after the forward's own
			// return, so it is read on a failure bound, as the answer it gave.
			requireClosed(t, conn, "Stop")
			select {
			case err := <-forwarded:
				require.ErrorIs(t, err, errors.ErrStopped)
			case <-time.After(peerTestBound):
				t.Fatal("the forward never returned after Stop")
			}
		})
	}
}

// While a forward waits for a leader, shutdown cancels its context and closes
// stopping, and waitLeader may see either first. An ended context reports
// ErrStopped when shutdown ended it and ErrNoLeader otherwise. stopping stays
// open and the server has no leader here, so only the context ends each wait.
// The stopped context is derived through a timeout, as each forward's is.
func TestWaitLeaderReportsAStoppedContextAsStopped(t *testing.T) {
	s := &EtcdServer{
		Cfg:      config.ServerConfig{TickMs: 1, ElectionTicks: 10},
		cluster:  newTestCluster(t),
		stopping: make(chan struct{}),
	}

	attached, stop := context.WithCancelCause(context.Background())
	stop(errors.ErrStopped)
	stopped, cancelStopped := context.WithTimeout(attached, peerTestBound)
	defer cancelStopped()
	_, err := s.waitLeader(stopped)
	require.ErrorIs(t, err, errors.ErrStopped)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = s.waitLeader(canceled)
	require.ErrorIs(t, err, errors.ErrNoLeader)
}

// A lease renewal, time-to-live query or member promotion that arrives after
// the server stopped is refused before it reaches peerRt, so it cannot reopen
// the pool shutdown closed.
func TestPeerForwardsAfterStopAreRefused(t *testing.T) {
	tr, dials := observedPeerRoundTripper(t)
	s := followerServer(t, tr, okPeer(t).URL)
	s.Stop()

	_, err := s.LeaseRenew(context.Background(), lease.LeaseID(1))
	require.ErrorIs(t, err, errors.ErrStopped)
	requireNoDial(t, dials, "a renewal after Stop")

	_, err = s.leaseTimeToLive(context.Background(), &pb.LeaseTimeToLiveRequest{ID: 1})
	require.ErrorIs(t, err, errors.ErrStopped)
	requireNoDial(t, dials, "a time-to-live query after Stop")

	_, err = s.PromoteMember(context.Background(), 2)
	require.ErrorIs(t, err, errors.ErrStopped)
	requireNoDial(t, dials, "a promotion after Stop")
}

// A NewServer that fails after bootstrap closes the bootstrapped server, and
// with it the peer pool bootstrap handed over.
func TestBootstrappedServerCloseClosesIdlePeerConnection(t *testing.T) {
	tr, dials := observedPeerRoundTripper(t)
	conn := idlePeerConn(t, tr, dials, okPeer(t).URL)
	be, _ := betesting.NewDefaultTmpBackend(t)
	b := &bootstrappedServer{
		prt:     tr,
		storage: &bootstrappedStorage{backend: &bootstrappedBackend{be: be}},
	}
	requireOpen(t, conn, "bootstrappedServer.Close")
	b.Close()
	requireClosed(t, conn, "bootstrappedServer.Close")
}

// A bootstrap that fails hands its peer pool to nobody, so it closes it
// itself. Joining an existing cluster without this member in the initial
// cluster fails before any dial, so the only connection is the one this test
// pooled.
func TestFailedBootstrapClosesIdlePeerConnection(t *testing.T) {
	tr, dials := observedPeerRoundTripper(t)
	peer := okPeer(t)
	conn := idlePeerConn(t, tr, dials, peer.URL)
	lg := zaptest.NewLogger(t)
	peerURLs, err := types.NewURLsMap("other=" + peer.URL)
	require.NoError(t, err)
	cfg := config.ServerConfig{
		Name:                "absent",
		DataDir:             t.TempDir(),
		InitialPeerURLsMap:  peerURLs,
		InitialClusterToken: "test",
		NewCluster:          false,
		Logger:              lg,
		ServerFeatureGate:   features.NewDefaultServerFeatureGate("test", lg),
	}
	require.NoError(t, os.MkdirAll(cfg.MemberDir(), 0o700))
	requireOpen(t, conn, "the failed bootstrap")
	_, err = bootstrapWithPeerRoundTripper(cfg, bootstrapSnapshot(cfg), tr)
	require.ErrorContains(t, err, `couldn't find local name "absent"`)
	requireClosed(t, conn, "the failed bootstrap")
	requireNoDial(t, dials, "the failed bootstrap")
}
