package destination

import (
	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
)

type (
	authority = string
	port      = uint32

	baseResolver interface {
		stop()
	}

	endpointsResolver interface {
		baseResolver
		resolveEndpoints(name authority, listener endpointUpdateListener) error
		//getState() servicePorts
	}

	profileResolver interface {
		baseResolver
		resolveProfiles(name authority, context string, listener profileUpdateListener) error
	}

	endpointUpdateListener interface {
		Add(a *pb.WeightedAddrSet)
		Remove(a *pb.AddrSet)
		ClientClose() <-chan struct{}
		ServerClose() <-chan struct{}
		NoEndpoints(exists bool)
		Stop()
	}
)
