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
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	pb "go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/client/pkg/v3/types"
	"go.etcd.io/etcd/server/v3/config"
	"go.etcd.io/etcd/server/v3/etcdserver/api/membership"
	serverversion "go.etcd.io/etcd/server/v3/etcdserver/version"
	"go.etcd.io/etcd/server/v3/storage/backend"
	betesting "go.etcd.io/etcd/server/v3/storage/backend/testing"
	"go.etcd.io/etcd/server/v3/storage/schema"
)

// TestMaintenanceStatusLocalMemberLearner checks the learner state Status
// reports for the local member. A removed local member is the state the server
// serves from after the removal of the local member is applied and before it
// stops.
func TestMaintenanceStatusLocalMemberLearner(t *testing.T) {
	const localID, peerID, clusterID = types.ID(1), types.ID(2), types.ID(0xc1)
	tests := []struct {
		name          string
		local         *membership.Member
		removeLocal   bool
		wantIsLearner bool
	}{
		{
			name:          "local member is a voter",
			local:         &membership.Member{ID: localID},
			wantIsLearner: false,
		},
		{
			name:          "local member is a learner",
			local:         &membership.Member{ID: localID, RaftAttributes: membership.RaftAttributes{IsLearner: true}},
			wantIsLearner: true,
		},
		{
			name:          "local voter is removed",
			local:         &membership.Member{ID: localID},
			removeLocal:   true,
			wantIsLearner: false,
		},
		{
			name:          "local learner is removed",
			local:         &membership.Member{ID: localID, RaftAttributes: membership.RaftAttributes{IsLearner: true}},
			removeLocal:   true,
			wantIsLearner: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lg := zaptest.NewLogger(t)
			be, _ := betesting.NewDefaultTmpBackend(t)
			defer betesting.Close(t, be)

			cl := membership.NewCluster(lg)
			cl.SetID(localID, clusterID)
			cl.SetBackend(schema.NewMembershipBackend(lg, be))
			cl.AddMember(tt.local, membership.ApplyBoth)
			cl.AddMember(&membership.Member{ID: peerID}, membership.ApplyBoth)
			if tt.removeLocal {
				cl.RemoveMember(localID, membership.ApplyBoth)
				require.True(t, cl.IsIDRemoved(localID))
				require.False(t, cl.IsMemberExist(localID))
			}

			rg := &fakeRaftStatusGetter{memberID: localID, leader: peerID}
			ms := &maintenanceServer{
				lg:  lg,
				rg:  rg,
				bg:  &fakeBackendGetter{be: be},
				a:   &fakeAlarmer{},
				hdr: header{clusterID: int64(clusterID), memberID: int64(localID), sg: rg, rev: func() int64 { return 1 }},
				cs:  &localMemberLearner{cl: cl},
				vs:  &fakeServerVersion{},
				cg:  &fakeConfigGetter{},
				ca:  &admitAllCalls{},
			}

			var resp *pb.StatusResponse
			var err error
			require.NotPanics(t, func() {
				resp, err = ms.Status(t.Context(), &pb.StatusRequest{})
			})
			require.NoError(t, err)
			require.Equal(t, uint64(localID), resp.Header.MemberId)
			require.Equal(t, tt.wantIsLearner, resp.IsLearner)
		})
	}
}

// localMemberLearner answers IsLearner from the cluster membership the way
// EtcdServer.IsLearner does.
type localMemberLearner struct {
	cl *membership.RaftCluster
}

func (l *localMemberLearner) IsLearner() bool { return l.cl.IsLocalMemberLearner() }

type fakeRaftStatusGetter struct {
	memberID types.ID
	leader   types.ID
}

func (g *fakeRaftStatusGetter) MemberID() types.ID     { return g.memberID }
func (g *fakeRaftStatusGetter) Leader() types.ID       { return g.leader }
func (g *fakeRaftStatusGetter) CommittedIndex() uint64 { return 1 }
func (g *fakeRaftStatusGetter) AppliedIndex() uint64   { return 1 }
func (g *fakeRaftStatusGetter) Term() uint64           { return 1 }

type fakeBackendGetter struct {
	be backend.Backend
}

func (g *fakeBackendGetter) Backend() backend.Backend { return g.be }

// fakeAlarmer implements only the Alarmer methods Status calls.
type fakeAlarmer struct {
	Alarmer
}

func (a *fakeAlarmer) Alarms() []*pb.AlarmMember { return nil }

// fakeServerVersion implements only the serverversion.Server methods Status
// calls.
type fakeServerVersion struct {
	serverversion.Server
}

func (v *fakeServerVersion) GetStorageVersion() *semver.Version { return nil }

func (v *fakeServerVersion) GetDowngradeInfo() *serverversion.DowngradeInfo { return nil }

type fakeConfigGetter struct{}

func (g *fakeConfigGetter) Config() config.ServerConfig { return config.ServerConfig{} }

// admitAllCalls admits every call, as a running server does.
type admitAllCalls struct{}

func (a *admitAllCalls) AttachCall(ctx context.Context) (context.Context, func(), error) {
	return ctx, func() {}, nil
}
