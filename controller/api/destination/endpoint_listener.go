package destination

import (
	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	"github.com/linkerd/linkerd2/pkg/addr"
	log "github.com/sirupsen/logrus"
)

func diffUpdateAddresses(oldAddrs, newAddrs []*updateAddress) ([]*updateAddress, []*updateAddress) {
	addSet := make(map[string]*updateAddress)
	removeSet := make(map[string]*updateAddress)

	for _, a := range newAddrs {
		key := addr.ProxyAddressToString(a.address)
		addSet[key] = a
	}

	for _, a := range oldAddrs {
		key := addr.ProxyAddressToString(a.address)
		delete(addSet, key)
		removeSet[key] = a
	}

	for _, a := range newAddrs {
		key := addr.ProxyAddressToString(a.address)
		delete(removeSet, key)
	}

	add := make([]*updateAddress, 0)
	for _, a := range addSet {
		add = append(add, a)
	}

	remove := make([]*updateAddress, 0)
	for _, a := range removeSet {
		remove = append(remove, a)
	}

	return add, remove
}

// implements the endpointUpdateListener interface
type endpointListener struct {
	stream pb.Destination_GetServer
	stopCh chan struct{}
	log    *log.Entry
}

func newEndpointListener(name authority, stream pb.Destination_GetServer) *endpointListener {
	log := log.WithFields(log.Fields{
		"component": "endpoint-listener",
		"authority": name,
	})
	stopCh := make(chan struct{})
	return &endpointListener{stream, stopCh, log}
}

func (l *endpointListener) ClientClose() <-chan struct{} {
	return l.stream.Context().Done()
}

func (l *endpointListener) ServerClose() <-chan struct{} {
	return l.stopCh
}

func (l *endpointListener) Stop() {
	close(l.stopCh)
}

func (l *endpointListener) Add(set []*pb.WeightedAddrSet) {
	if err := l.stream.Send(&pb.Update{Update: &pb.Update_Add{Add: set}}); err != nil {
		l.log.Errorf("Failed to send address update: %s", err)
	}
}

func (l *endpointListener) Remove(set *pb.AddrSet) {
	if err := l.stream.Send(&pb.Update{Update: &pb.Update_Remove{Remove: set}}); err != nil {
		l.log.Errorf("Failed to send address update: %s", err)
	}
}

func (l *endpointListener) NoEndpoints(exists bool) {
	l.log.Debugf("NoEndpoints(%+v)", exists)

	u := &pb.Update{
		Update: &pb.Update_NoEndpoints{
			NoEndpoints: &pb.NoEndpoints{
				Exists: exists,
			},
		},
	}
	if err := l.stream.Send(u); err != nil {
		l.log.Errorf("Failed to send address update: %s", err)
	}
}
