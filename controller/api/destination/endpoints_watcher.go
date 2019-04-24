package destination

import (
	"fmt"
	"strings"
	"sync"

	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	net "github.com/linkerd/linkerd2-proxy-api/go/net"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/addr"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
)

const (
	kubeSystem = "kube-system"
)

// TODO: prom metrics for all the queues/caches
// https://github.com/linkerd/linkerd2/issues/2204

type (
	targetPort intstr.IntOrString

	// endpointsWatcher watches all endpoints and services in the Kubernetes
	// cluster.  Listeners can subscribe to a particular service and port and
	// endpointsWatcher will publish the address set and all future changes for
	// that service:port.
	endpointsWatcher struct {
		services   corelisters.ServiceLister
		endpoints  corelisters.EndpointsLister
		pods       corelisters.PodLister
		translator endpointTranslator

		publishers   map[serviceID]*servicePublisher
		publishersMu sync.RWMutex

		log *log.Entry
	}

	endpointTranslator interface {
		mkWeightedAddr(s *corev1.Service, p *corev1.Pod, t targetPort) (*pb.WeightedAddr, error)
		mkTcpAddress(p *corev1.Pod, t targetPort) (*net.TcpAddress, error)
	}

	// servicePublisher represents a service along with a port number.  Multiple
	// listeners may be subscribed to a servicePublisher.  servicePublisher maintains the
	// current state of the address set and publishes diffs to all listeners when
	// updates come from either the endpoints API or the service API.
	servicePublisher struct {
		id   serviceID
		pods corelisters.PodLister
		log  *log.Entry

		ports   map[port]portPublisher
		portsMu sync.RWMutex
	}

	portPublisher struct {
		targetPort targetPort
		addresses  []*pb.WeightedAddr
		listener   endpointUpdateListener
	}
)

func newEndpointsWatcher(k8sAPI *k8s.API, translator endpointTranslator) *endpointsWatcher {
	ew := &endpointsWatcher{
		serviceLister:  k8sAPI.Svc().Lister(),
		endpointLister: k8sAPI.Endpoint().Lister(),
		podLister:      k8sAPI.Pod().Lister(),
		translator:     translator,
		log: log.WithFields(log.Fields{
			"component": "endpoints-watcher",
		}),
	}

	k8sAPI.Svc().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ew.addService,
		DeleteFunc: ew.deleteService,
		UpdateFunc: func(_, obj interface{}) { ew.addService(obj) },
	})

	k8sAPI.Endpoint().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ew.addEndpoints,
		DeleteFunc: ew.deleteEndpoints,
		UpdateFunc: func(_, obj interface{}) { ew.addEndpoints(obj) },
	})

	return ew
}

// Close all open streams on shutdown
func (e *endpointsWatcher) stop() {
	e.publishersMu.Lock()
	defer e.publishersMu.Unlock()

	for _, sp := range e.publishers {
		sp.unsubscribeAll()
	}
}

// Subscribe to a service and service port.
// The provided listener will be updated each time the address set for the
// given service port is changed.
func (e *endpointsWatcher) subscribe(service *serviceID, port port, listener endpointUpdateListener) {
	e.log.Infof("Establishing watch on endpoint %s:%d", service, port)

	e.publishersMu.Lock()
	defer e.publishersMu.Unlock()

	// If the service doesn't yet exist, create a stub for it so the listener can
	// be registered.
	sp, ok := e.publishers[*service]
	if !ok {
		sp = e.newServicePublisher(*service)
		e.publishers[*service] = sp
	}

	sp.subscribe(port, listener)
}

func (e *endpointsWatcher) unsubscribe(service *serviceID, port port, listener endpointUpdateListener) {
	e.log.Infof("Stopping watch on endpoint %s:%d", service, port)

	e.publishersMu.Lock()
	defer e.publishersMu.Unlock()

	sp, ok := e.publishers[*service]
	if !ok {
		return
	}
	unsubscribed, numListeners := svcPort.unsubscribe(port, listener)
	if !unsubscribed {
		return
	}
	if numListeners == 0 {
		delete(svc, port)
		if len(svc) == 0 {
			delete(e.publishers, *service)
		}
	}
	return nil
}

func (e *endpointsWatcher) getService(service *serviceID) (*corev1.Service, error) {
	return e.serviceLister.Services(service.namespace).Get(service.name)
}

func (e *endpointsWatcher) addService(obj interface{}) {
	service := obj.(*corev1.Service)
	id := serviceID{
		namespace: service.Namespace,
		name:      service.Name,
	}

	e.publishersMu.RLock()
	defer e.publishersMu.RUnlock()

	svc, ok := e.publishers[id]
	if !ok {
		svc = make(map[uint32]*servicePublisher)
		e.publishers[id] = svc
	}
	for _, sp := range svc {
		sp.updateService(service)
	}
}

func (e *endpointsWatcher) deleteService(obj interface{}) {
	service := obj.(*corev1.Service)
	id := serviceID{
		namespace: service.Namespace,
		name:      service.Name,
	}

	e.publishersMu.RLock()
	defer e.publishersMu.RUnlock()
	for _, sp := range e.publishers[id] {
		sp.deleteService(service)
	}
}

func (e *endpointsWatcher) getEndpoints(service *serviceID) (*corev1.Endpoints, error) {
	return e.endpointLister.Endpoints(service.namespace).Get(service.name)
}

func (e *endpointsWatcher) addEndpoints(obj interface{}) {
	endpoints := obj.(*corev1.Endpoints)
	if endpoints.Namespace == kubeSystem {
		return
	}
	id := serviceID{
		namespace: endpoints.Namespace,
		name:      endpoints.Name,
	}

	e.publishersMu.RLock()
	defer e.publishersMu.RUnlock()
	svc := e.publishers[id]
	for _, sp := range svc {
		sp.updateEndpoints(endpoints)
	}
}

func (e *endpointsWatcher) deleteEndpoints(obj interface{}) {
	endpoints := obj.(*corev1.Endpoints)
	if endpoints.Namespace == kubeSystem {
		return
	}
	id := serviceID{
		namespace: endpoints.Namespace,
		name:      endpoints.Name,
	}

	e.publishersMu.RLock()
	defer e.publishersMu.RUnlock()
	service := e.publishers[id]
	for _, sp := range service {
		sp.deleteEndpoints()
	}
}

/// servicePublisher ///

func (e *endpointsWatcher) newServicePublisher(service serviceID) *servicePublisher {
	return &servicePublisher{
		service:   id,
		podLister: e.podLister,
		log: e.log.WithFields(log.Fields{
			"component": "service-publisher",
			"ns":        id.namespace,
			"svc":       id.name,
		}),
	}
}

func (sp *servicePublisher) updateEndpoints(newEndpoints *corev1.Endpoints) {
	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	sp.updateAddresses(newEndpoints, sp.targetPort)
	sp.endpoints = newEndpoints
}

func (sp *servicePublisher) deleteEndpoints() {
	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	sp.log.Debugf("Deleting %s:%d", sp.service, sp.port)

	for _, listener := range sp.publishers {
		listener.NoEndpoints(false)
	}
	sp.endpoints = nil
	sp.addresses = []*updateAddress{}
}

func (sp *servicePublisher) updateService(newService *corev1.Service) {
	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	newTargetPort := getTargetPort(newService, sp.port)
	if newTargetPort != sp.targetPort {
		sp.updateAddresses(sp.endpoints, newTargetPort)
		sp.targetPort = newTargetPort
	}
}

func (sp *servicePublisher) updateAddresses(endpoints *corev1.Endpoints, port intstr.IntOrString) {
	newAddresses := sp.endpointsToAddresses(endpoints, port)
	if log.GetLevel() >= log.DebugLevel {
		var s []string
		for _, v := range newAddresses {
			s = append(s, fmt.Sprintf("%v", *v))
		}
		sp.log.Debugf("Updating %s:%d to [%v]", sp.service, sp.port, strings.Join(s, ", "))
	}

	if len(newAddresses) == 0 {
		for _, listener := range sp.publishers {
			listener.NoEndpoints(true)
		}
	} else {
		add, remove := diffUpdateAddresses(sp.addresses, newAddresses)
		for _, listener := range sp.publishers {
			listener.Update(add, remove)
		}
	}
	sp.addresses = newAddresses
}

func (sp *servicePublisher) subscribe(port port, listener endpointUpdateListener) {
	sp.log.Debugf("Subscribing %s:%d exists=%t", sp.service, sp.port, exists)

	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	sp.publishers = append(sp.publishers, listener)
	if !exists {
		listener.NoEndpoints(false)
	} else if len(sp.addresses) == 0 {
		listener.NoEndpoints(true)
	} else {
		listener.Update(sp.addresses, nil)
	}
}

// unsubscribe returns true iff the listener was found and removed.
// it also returns the number of listeners remaining after unsubscribing.
func (sp *servicePublisher) unsubscribe(port port, listener endpointUpdateListener) (bool, int) {
	sp.log.Debugf("Unsubscribing %s:%d", sp.service, sp.port)

	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	for i, p := range sp.publishers {
		if item == listener {
			// delete the item from the slice
			sp.publishers[i] = sp.publishers[len(sp.publishers)-1]
			sp.publishers[len(sp.publishers)-1] = nil
			sp.publishers = sp.publishers[:len(sp.publishers)-1]
			return true, len(sp.publishers)
		}
	}
	return false, len(sp.publishers)
}

func (sp *servicePublisher) unsubscribeAll() {
	sp.log.Debugf("Unsubscribing %s:%d", sp.service, sp.port)

	sp.publishersMu.Lock()
	defer sp.publishersMu.Unlock()

	for _, listener := range sp.publishers {
		listener.Stop()
	}
}

func (sp *servicePublisher) endpointsToAddresses(endpoints *corev1.Endpoints, targetPort intstr.IntOrString) []*updateAddress {
	addrs := make([]*updateAddress, 0)

	for _, subset := range endpoints.Subsets {
		var portNum uint32
		switch targetPort.Type {
		case intstr.String:
			for _, port := range subset.Ports {
				if port.Name == targetPort.StrVal {
					portNum = uint32(port.Port)
					break
				}
			}
		case intstr.Int:
			portNum = uint32(targetPort.IntVal)
		}
		if portNum == 0 {
			sp.log.Errorf("Port %v not found", targetPort)
			return addrs
		}

		for _, address := range subset.Addresses {
			target := address.TargetRef
			if target == nil {
				sp.log.Errorf("Target not found for endpoint %v", address)
				continue
			}

			idStr := fmt.Sprintf("%s %s.%s", address.IP, target.Name, target.Namespace)

			ip, err := addr.ParseProxyIPV4(address.IP)
			if err != nil {
				sp.log.Errorf("[%s] not a valid IPV4 address", idStr)
				continue
			}

			pod, err := sp.podLister.Pods(target.Namespace).Get(target.Name)
			if err != nil {
				sp.log.Errorf("[%s] failed to lookup pod: %s", idStr, err)
				continue
			}

			addrs = append(addrs, &updateAddress{
				address: &net.TcpAddress{Ip: ip, Port: portNum},
				pod:     pod,
			})
		}
	}
	return addrs
}

// getTargetPort returns the port specified as an argument if no service is
// present. If the service is present and it has a port spec matching the
// specified port and a target port configured, it returns the name of the
// service's port (not the name of the target pod port), so that it can be
// looked up in the the endpoints API response, which uses service port names.
func getTargetPort(service *corev1.Service, port uint32) targetPort {
	// Use the specified port as the target port by default
	targetPort := intstr.FromInt(int(port))

	if service == nil {
		return targetPort
	}

	// If a port spec exists with a port matching the specified port and a target
	// port configured, use that port spec's name as the target port
	for _, portSpec := range service.Spec.Ports {
		if portSpec.Port == int32(port) && portSpec.TargetPort != intstr.FromInt(0) {
			return intstr.FromString(portSpec.Name)
		}
	}

	return targetPort
}
