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

package v3rpc

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest"
	"golang.org/x/crypto/bcrypt"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/auth"
	"go.etcd.io/etcd/server/v3/config"
	"go.etcd.io/etcd/server/v3/etcdserver"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	serverversion "go.etcd.io/etcd/server/v3/etcdserver/version"
	"go.etcd.io/etcd/server/v3/features"
)

const (
	// statusWaitTimeout bounds every wait for a signal that the tested
	// behaviour must produce, so a missed signal fails with its own message
	// instead of hanging until the package timeout.
	statusWaitTimeout = 10 * time.Second
	// statusHeldGrace is how long shutdown gets to wrongly complete while an
	// admitted Status is held.
	statusHeldGrace = time.Second
)

// TestMaintenanceStatusAfterStop checks that Status on a server that has
// stopped, while its gRPC server still serves, is refused with the stopped
// error instead of reading the closed backend.
func TestMaintenanceStatusAfterStop(t *testing.T) {
	tests := []struct {
		name   string
		status func(*authMaintenanceServer, context.Context, *pb.StatusRequest) (*pb.StatusResponse, error)
	}{
		{name: "authMaintenanceServer", status: (*authMaintenanceServer).Status},
		{name: "maintenanceServer", status: func(ams *authMaintenanceServer, ctx context.Context, r *pb.StatusRequest) (*pb.StatusResponse, error) {
			return ams.maintenanceServer.Status(ctx, r)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := startStatusTestServer(t)
			ams := NewMaintenanceServer(s, nil).(*authMaintenanceServer)
			requireServerStopped(t, s)

			var err error
			require.NotPanics(t, func() {
				_, err = tt.status(ams, t.Context(), &pb.StatusRequest{})
			})
			require.ErrorIs(t, err, rpctypes.ErrGRPCStopped)
		})
	}
}

// TestMaintenanceStatusHeldInBackendAccess checks that shutdown waits for a
// Status that was admitted and is inside its backend access, and that a Status
// arriving after shutdown began is refused.
func TestMaintenanceStatusHeldInBackendAccess(t *testing.T) {
	s := startStatusTestServer(t)
	ams := NewMaintenanceServer(s, nil).(*authMaintenanceServer)
	vs := &holdingStorageVersion{
		Server:  etcdserver.NewServerVersionAdapter(s),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	ams.maintenanceServer.vs = vs

	requireStopWaitsForHeldStatus(t, s, ams, vs.entered, vs.release, "its backend access")
}

// TestMaintenanceStatusHeldInAuthentication checks that shutdown waits for a
// Status that was admitted and is inside authentication, and that a Status
// arriving after shutdown began is refused.
func TestMaintenanceStatusHeldInAuthentication(t *testing.T) {
	s := startStatusTestServer(t)
	ams := NewMaintenanceServer(s, nil).(*authMaintenanceServer)
	ag := &holdingAuthGetter{
		AuthGetter: s,
		entered:    make(chan struct{}),
		release:    make(chan struct{}),
	}
	ams.AuthAdmin.ag = ag

	requireStopWaitsForHeldStatus(t, s, ams, ag.entered, ag.release, "authentication")
}

// TestMaintenanceStatusWaitingInAuthenticationDoesNotHoldStop checks that a
// Status waiting on its context in authentication, as a simple token waits
// for its index, is refused with the stopped error when shutdown begins and
// does not hold shutdown up.
func TestMaintenanceStatusWaitingInAuthenticationDoesNotHoldStop(t *testing.T) {
	s := startStatusTestServer(t)
	ams := NewMaintenanceServer(s, nil).(*authMaintenanceServer)
	ag := &holdingAuthGetter{
		AuthGetter:    s,
		entered:       make(chan struct{}),
		waitOnContext: true,
	}
	ams.AuthAdmin.ag = ag

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	stopped := make(chan struct{})
	var callStarted, callJoined, stopStarted, stopJoined bool

	// Registered before anything is started, so a failure at any point below
	// releases the waiting call and joins both goroutines.
	t.Cleanup(func() {
		cancel()
		if callStarted && !callJoined {
			awaitValue(t, errc, "the waiting Status to return")
		}
		if stopStarted && !stopJoined {
			awaitSignal(t, stopped, "the server shutdown to complete")
		}
	})

	callStarted = true
	go func() {
		var waitingErr error
		assert.NotPanics(t, func() {
			_, waitingErr = ams.Status(ctx, &pb.StatusRequest{})
		})
		errc <- waitingErr
	}()
	requireSignal(t, ag.entered, "the Status to reach authentication")

	stopStarted = true
	go func() {
		s.HardStop()
		close(stopped)
	}()
	select {
	case <-stopped:
		stopJoined = true
	case <-time.After(statusWaitTimeout):
		t.Fatal("timed out waiting for the server shutdown to complete; a Status waiting in authentication held it up")
	}

	select {
	case waitingErr := <-errc:
		callJoined = true
		require.ErrorIs(t, waitingErr, rpctypes.ErrGRPCStopped)
	case <-time.After(statusWaitTimeout):
		t.Fatal("timed out waiting for the waiting Status to return after the server stopped")
	}
}

type statusResult struct {
	resp *pb.StatusResponse
	err  error
}

// requireStopWaitsForHeldStatus starts a Status that holds inside stage until
// release is closed, begins shutdown, and checks that a new Status is refused,
// that shutdown waits for the held Status, and that the held Status completes
// its backend access once released.
func requireStopWaitsForHeldStatus(t *testing.T, s *etcdserver.EtcdServer, ams *authMaintenanceServer, entered, release chan struct{}, stage string) {
	t.Helper()

	heldc := make(chan statusResult, 1)
	stopped := make(chan struct{})
	var releaseOnce sync.Once
	releaseHeld := func() { releaseOnce.Do(func() { close(release) }) }
	var heldStarted, heldJoined, stopStarted, stopJoined bool

	// Registered before anything is started, so a failure at any point below
	// releases the held Status and joins both goroutines.
	t.Cleanup(func() {
		releaseHeld()
		if heldStarted && !heldJoined {
			awaitValue(t, heldc, "the held Status to return after release")
		}
		if stopStarted && !stopJoined {
			awaitSignal(t, stopped, "the server shutdown to complete")
		}
	})

	heldStarted = true
	go func() {
		var r statusResult
		assert.NotPanics(t, func() {
			r.resp, r.err = ams.Status(context.Background(), &pb.StatusRequest{})
		})
		heldc <- r
	}()
	requireSignal(t, entered, "the Status to reach "+stage)

	stopStarted = true
	go func() {
		s.HardStop()
		close(stopped)
	}()
	requireSignal(t, s.StoppingNotify(), "shutdown to begin")

	var refusedErr error
	require.NotPanicsf(t, func() {
		_, refusedErr = ams.Status(t.Context(), &pb.StatusRequest{})
	}, "a Status that arrives after shutdown began")
	require.ErrorIsf(t, refusedErr, rpctypes.ErrGRPCStopped, "a Status that arrives after shutdown began")

	select {
	case <-stopped:
		stopJoined = true
		t.Fatalf("the server stopped while an admitted Status was held in %s", stage)
	case <-time.After(statusHeldGrace):
	}

	releaseHeld()
	var held statusResult
	select {
	case held = <-heldc:
		heldJoined = true
	case <-time.After(statusWaitTimeout):
		t.Fatal("timed out waiting for the held Status to return after release")
	}
	require.NoError(t, held.err)
	require.NotNil(t, held.resp)

	select {
	case <-stopped:
		stopJoined = true
	case <-time.After(statusWaitTimeout):
		t.Fatal("timed out waiting for the server shutdown to complete after the held Status returned")
	}
}

// holdingStorageVersion holds the first GetStorageVersion call, which reads
// the backend, until release is closed, then performs the read. Later calls
// are not held.
type holdingStorageVersion struct {
	serverversion.Server
	holding atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (v *holdingStorageVersion) GetStorageVersion() *semver.Version {
	if v.holding.CompareAndSwap(false, true) {
		close(v.entered)
		<-v.release
	}
	return v.Server.GetStorageVersion()
}

// holdingAuthGetter reports auth as enabled and holds the first
// AuthInfoFromCtx call. With waitOnContext it waits for the call context and
// fails as an invalid token, as a simple token does when its context ends
// before the token index is applied; otherwise it waits until release is
// closed and authenticates the caller as root. Later calls are not held.
type holdingAuthGetter struct {
	AuthGetter
	holding       atomic.Bool
	entered       chan struct{}
	release       chan struct{}
	waitOnContext bool
}

func (g *holdingAuthGetter) AuthStore() auth.AuthStore {
	return &authEnabledStore{AuthStore: g.AuthGetter.AuthStore()}
}

func (g *holdingAuthGetter) AuthInfoFromCtx(ctx context.Context) (*auth.AuthInfo, error) {
	if g.holding.CompareAndSwap(false, true) {
		close(g.entered)
		if g.waitOnContext {
			<-ctx.Done()
			return nil, auth.ErrInvalidAuthToken
		}
		<-g.release
	}
	return &auth.AuthInfo{Username: "root"}, nil
}

type authEnabledStore struct {
	auth.AuthStore
}

func (s *authEnabledStore) IsAuthEnabled() bool { return true }

// requireSignal waits for c and fails the test when it does not arrive.
func requireSignal(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(statusWaitTimeout):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// awaitSignal waits for c and reports a failure when it does not arrive. It is
// for cleanup, which runs after a failure and must not stop the test goroutine.
func awaitSignal(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(statusWaitTimeout):
		t.Errorf("timed out waiting for %s", what)
	}
}

// awaitValue is awaitSignal for a channel that carries a value.
func awaitValue[T any](t *testing.T, c <-chan T, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(statusWaitTimeout):
		t.Errorf("timed out waiting for %s", what)
	}
}

// requireServerStopped stops s and fails the test when the shutdown does not
// complete.
func requireServerStopped(t *testing.T, s *etcdserver.EtcdServer) {
	t.Helper()
	stopped := make(chan struct{})
	go func() {
		s.HardStop()
		close(stopped)
	}()
	requireSignal(t, stopped, "the server shutdown to complete")
}

// startStatusTestServer starts a single member server without client or peer
// listeners and stops it when the test ends.
func startStatusTestServer(t *testing.T) *etcdserver.EtcdServer {
	t.Helper()
	lg := zaptest.NewLogger(t, zaptest.Level(zapcore.InfoLevel))
	peerURLs := types.MustNewURLs([]string{"http://127.0.0.1:2380"})
	urlsMap, err := types.NewURLsMap("s1=http://127.0.0.1:2380")
	require.NoError(t, err)
	cfg := config.ServerConfig{
		Name:                        "s1",
		ClientURLs:                  types.MustNewURLs([]string{"http://127.0.0.1:2379"}),
		PeerURLs:                    peerURLs,
		DataDir:                     t.TempDir(),
		InitialPeerURLsMap:          urlsMap,
		InitialClusterToken:         "status-lifetime",
		NewCluster:                  true,
		BootstrapTimeout:            10 * time.Millisecond,
		TickMs:                      10,
		ElectionTicks:               10,
		InitialElectionTickAdvance:  true,
		SnapshotCount:               etcdserver.DefaultSnapshotCount,
		SnapshotCatchUpEntries:      etcdserver.DefaultSnapshotCatchUpEntries,
		MaxTxnOps:                   128,
		MaxRequestBytes:             1.5 * 1024 * 1024,
		AuthToken:                   "simple",
		BcryptCost:                  uint(bcrypt.MinCost),
		WarningApplyDuration:        100 * time.Millisecond,
		WarningUnaryRequestDuration: 300 * time.Millisecond,
		MaxLearners:                 membership.DefaultMaxLearners,
		Logger:                      lg,
		ServerFeatureGate:           features.NewDefaultServerFeatureGate("s1", lg),
	}
	s, err := etcdserver.NewServer(cfg)
	require.NoError(t, err)
	s.Start()
	// Registered as soon as the server can be stopped, which is after Start,
	// so every later failure still joins the shutdown.
	t.Cleanup(func() {
		stopped := make(chan struct{})
		go func() {
			s.HardStop()
			close(stopped)
		}()
		awaitSignal(t, stopped, "the test server shutdown to complete")
	})
	requireSignal(t, s.ReadyNotify(), "the test server to become ready")
	return s
}
