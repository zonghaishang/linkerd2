package destination

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"

	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"

	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	"github.com/linkerd/linkerd2/controller/api/util"
	discoveryPb "github.com/linkerd/linkerd2/controller/gen/controller/discovery"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/addr"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type (
	server struct {
		endpoints endpointsResolver
		profiles  profileResolver

		log *log.Entry
	}

	translator struct {
		enableH2Upgrade                   bool
		controllerNS, identityTrustDomain string
	}
)

// NewServer returns a new instance of the destination server.
//
// The destination server serves service discovery and other information to the
// proxy.  This implementation supports the "k8s" destination scheme and expects
// destination paths to be of the form:
// <service>.<namespace>.svc.cluster.local:<port>
//
// If the port is omitted, 80 is used as a default.  If the namespace is
// omitted, "default" is used as a default.append
//
// Addresses for the given destination are fetched from the Kubernetes Endpoints
// API.
func NewServer(
	addr controllerNS, identityTrustDomain string,
	enableH2Upgrade bool,
	k8sAPI *k8s.API,
	shutdown chan struct{},
) (*grpc.Server, error) {
	endpoints := newEndpointsWatcher(k8sAPI, endpointLabeler)
	profiles := newProfileWatcher(k8sAPI)
	log := log.WithFields(log.Fields{
		"addr":      addr,
		"component": "server",
	})
	srv := server{endpoints, profiles, log}
	go func() {
		<-shutdown
		endpoints.stop()
		profiles.stop()
	}()

	s := prometheus.NewGrpcServer()
	// linkerd2-proxy-api/destination.Destination (proxy-facing)
	pb.RegisterDestinationServer(s, &srv)
	// controller/discovery.Discovery (controller-facing)
	discoveryPb.RegisterDiscoveryServer(s, &srv)
	return s, nil
}

func (s *server) Get(dest *pb.GetDestination, stream pb.Destination_GetServer) error {
	s.log.Debugf("get %s", dest.GetPath())

	err := s.resolver.resolveEndpoints(dest.GetPath(), newEndpointListener(stream))
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid destination: %s", err.Error())
	}

	return nil
}

func (s *server) GetProfile(dest *pb.GetDestination, stream pb.Destination_GetProfileServer) error {
	s.log.Debugf("GetProfile(%+v)", dest)
	host, _, err := getHostAndPort(dest)
	if err != nil {
		return err
	}

	listener := newProfileListener(stream)

	err = s.resolver.streamProfiles(host, dest.GetContextToken(), listener)
	if err != nil {
		s.log.Errorf("Error streaming profile for %s: %v", dest.Path, err)
	}
	return err
}

func (e *endpointsWatcher) Endpoints(ctx context.Context, params *discoveryPb.EndpointsParams) (*discoveryPb.EndpointsResponse, error) {
	s.log.Debugf("serving endpoints request")

	servicePorts := e.getState()

	rsp := discoveryPb.EndpointsResponse{
		ServicePorts: make(map[string]*discoveryPb.ServicePort),
	}

	for serviceID, portMap := range servicePorts {
		discoverySP := discoveryPb.ServicePort{
			PortEndpoints: make(map[uint32]*discoveryPb.PodAddresses),
		}
		for port, sp := range portMap {
			podAddrs := discoveryPb.PodAddresses{
				PodAddresses: []*discoveryPb.PodAddress{},
			}

			for _, ua := range sp.addresses {
				ownerKind, ownerName := s.k8sAPI.GetOwnerKindAndName(ua.pod)
				pod := util.K8sPodToPublicPod(*ua.pod, ownerKind, ownerName)

				podAddrs.PodAddresses = append(
					podAddrs.PodAddresses,
					&discoveryPb.PodAddress{
						Addr: addr.NetToPublic(ua.address),
						Pod:  &pod,
					},
				)
			}

			discoverySP.PortEndpoints[port] = &podAddrs
		}

		s.log.Debugf("ServicePorts[%s]: %+v", serviceID, discoverySP)
		rsp.ServicePorts[serviceID.String()] = &discoverySP
	}

	return &rsp, nil
}

func (s *server) streamResolution(host string, port int, stream pb.Destination_GetServer) error {

}

func getHostAndPort(dest *pb.GetDestination) (string, int, error) {
	if dest.Scheme != "k8s" {
		err := fmt.Errorf("Unsupported scheme %s", dest.Scheme)
		log.Error(err)
		return "", 0, err
	}
	hostPort := strings.Split(dest.Path, ":")
	if len(hostPort) > 2 {
		err := fmt.Errorf("Invalid destination %s", dest.Path)
		log.Error(err)
		return "", 0, err
	}
	host := hostPort[0]
	port := 80
	if len(hostPort) == 2 {
		var err error
		port, err = strconv.Atoi(hostPort[1])
		if err != nil {
			err = fmt.Errorf("Invalid port %s", hostPort[1])
			log.Error(err)
			return "", 0, err
		}
	}
	return host, port, nil
}

func (t *translator) mkWeightedAddr() *pb.WeightedAddr {
	labels, hint, tlsIdentity := l.getAddrMetadata(address.pod)

	return &pb.WeightedAddr{
		Addr:         address.address,
		Weight:       addr.DefaultWeight,
		MetricLabels: labels,
		TlsIdentity:  tlsIdentity,
		ProtocolHint: hint,
	}
}

func (l *endpointListener) getAddrMetadata(pod *corev1.Pod) (map[string]string, *pb.ProtocolHint, *pb.TlsIdentity) {
	controllerNS := pod.Labels[pkgK8s.ControllerNSLabel]
	sa, ns := pkgK8s.GetServiceAccountAndNS(pod)
	ok, on := l.ownerKindAndName(pod)
	labels := pkgK8s.GetPodLabels(ok, on, pod)

	// If the pod is controlled by any Linkerd control plane, then it can be hinted
	// that this destination knows H2 (and handles our orig-proto translation).
	var hint *pb.ProtocolHint
	if l.enableH2Upgrade && controllerNS != "" {
		hint = &pb.ProtocolHint{
			Protocol: &pb.ProtocolHint_H2_{
				H2: &pb.ProtocolHint_H2{},
			},
		}
	}

	// If the pod is controlled by the same Linkerd control plane, then it can
	// participate in identity with peers.
	//
	// TODO this should be relaxed to match a trust domain annotation so that
	// multiple meshes can participate in identity if they share trust roots.
	var identity *pb.TlsIdentity
	if l.identityTrustDomain != "" &&
		controllerNS == l.controllerNS &&
		pod.Annotations[pkgK8s.IdentityModeAnnotation] == pkgK8s.IdentityModeDefault {

		id := fmt.Sprintf("%s.%s.serviceaccount.identity.%s.%s", sa, ns, controllerNS, l.identityTrustDomain)
		identity = &pb.TlsIdentity{
			Strategy: &pb.TlsIdentity_DnsLikeIdentity_{
				DnsLikeIdentity: &pb.TlsIdentity_DnsLikeIdentity{
					Name: id,
				},
			},
		}
	}

	return labels, hint, identity
}
