package mock

import (
	"fmt"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/NordSecurity/nordvpn-linux/core/mesh"
	"github.com/google/uuid"
)

type RegistryMock struct {
	CurrentMachine mesh.Machine
	Peers          mesh.MachinePeers
	LocalPeers     mesh.Machines

	MapErr       error
	ConfigureErr error
	UpdateErr    error
}

func (*RegistryMock) Register(token string, self mesh.Machine) (*mesh.Machine, error) {
	return &mesh.Machine{}, nil
}
func (r *RegistryMock) Update(token string, id uuid.UUID, info mesh.MachineUpdateRequest) error {
	if r.UpdateErr != nil {
		return r.UpdateErr
	}
	r.CurrentMachine.SupportsRouting = info.SupportsRouting
	r.CurrentMachine.Nickname = info.Nickname
	r.CurrentMachine.Endpoints = info.Endpoints
	return nil
}

func (r *RegistryMock) Configure(token string, id uuid.UUID, peerID uuid.UUID, peer mesh.PeerUpdateRequest) error {
	if r.ConfigureErr != nil {
		return r.ConfigureErr
	}

	if len(r.Peers) != 0 {
		for i, v := range r.Peers {
			if v.ID == peerID {
				v.AlwaysAcceptFiles = peer.AlwaysAcceptFiles
				v.DoIAllowRouting = peer.DoIAllowRouting
				v.DoIAllowLocalNetwork = peer.DoIAllowLocalNetwork
				v.DoIAllowFileshare = peer.DoIAllowFileshare
				v.DoIAllowInbound = peer.DoIAllowInbound
				v.Nickname = peer.Nickname
				r.Peers = slices.Replace(r.Peers, i, i+1, v)
			}
			return nil
		}
		return fmt.Errorf("not found")
	}
	return nil
}

func (r *RegistryMock) GetPeerWithIdentifier(id string) *mesh.MachinePeer {
	index := slices.IndexFunc(r.Peers, func(p mesh.MachinePeer) bool {
		return p.ID.String() == id || strings.EqualFold(p.Hostname, id) || p.PublicKey == id || strings.EqualFold(p.Nickname, id)
	})

	if index == -1 {
		return nil
	}

	return &r.Peers[index]
}

func (*RegistryMock) Unregister(token string, self uuid.UUID) error { return nil }

func (r *RegistryMock) Map(token string, self uuid.UUID, _ bool) (*mesh.MachineMap, error) {
	if r.MapErr != nil {
		return nil, r.MapErr
	}
	return &mesh.MachineMap{Machine: r.CurrentMachine, Peers: r.Peers}, nil
}

func (*RegistryMock) Unpair(token string, self uuid.UUID, peer uuid.UUID) error { return nil }

func (*RegistryMock) NotifyNewTransfer(
	token string,
	self uuid.UUID,
	peer uuid.UUID,
	fileName string,
	fileCount int,
	transferID string,
) error {
	return nil
}

type CachingMapperMock struct {
	Value *mesh.MachineMap
	Error error
}

func (m *CachingMapperMock) Map(_ string, _ uuid.UUID, _ bool) (*mesh.MachineMap, error) {
	return m.Value, m.Error
}

type RegistrationCheckerMock struct {
	registrationErr error
}

func (r RegistrationCheckerMock) IsRegistrationInfoCorrect() bool { return r.registrationErr == nil }
func (r RegistrationCheckerMock) Register() error                 { return r.registrationErr }
