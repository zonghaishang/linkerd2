package destination

import (
	"errors"
	"regexp"
	"strconv"
	"testing"
)

var k8sSvcNameRE = regexp.MustCompile("^(?i)([^.]+)\\.([^.]+)\\.svc\\.cluster\\.local\\.?(?::(\\d+))?$")

type serviceID struct {
	namespace string
	name      string
}

func parseK8sServiceFromAuthority(name authority) (serviceID, port, error) {
	parts := k8sSvcNameRE.FindStringSubmatch(name)

	if len(parts) != 3 && len(parts) != 4 {
		return serviceID{}, 0, errors.New("invalid kubernetes service name")
	}

	port := port(80)
	if len(parts) == 4 {
		p, err := strconv.Atoi(parts[3])
		if err != nil {
			panic("k8s service name regex only matches numeric ports")
		}
		port = port(p)
	}

	id := serviceId{
		name:      parts[1],
		namespace: parts[2],
	}
	return id, port, nil
}

func testParseK8sServiceFromAuthority(t *testing.T) {
	id, port, err := parseK8sServiceFromAuthority("foo.bar.svc.cluster.local")
	if err != nil || id.name != "foo" || id.namespace != "bar" || port != 80 {
		t.Error("could not parse foo.bar.svc.cluster.local")
	}

	id, port, err = parseK8sServiceFromAuthority("foo.bar.svc.cluster.local.")
	if err != nil || id.name != "foo" || id.namespace != "bar" || port != 80 {
		t.Error("could not parse foo.bar.svc.cluster.local.")
	}

	id, port, err = parseK8sServiceFromAuthority("foo.bar.svc.cluster.local:8080")
	if err != nil || id.name != "foo" || id.namespace != "bar" || port != 8080 {
		t.Error("could not parse foo.bar.svc.cluster.local:8080")
	}

	id, port, err = parseK8sServiceFromAuthority("foo.bar.svc.cluster.local.:8080")
	if err != nil || id.name != "foo" || id.namespace != "bar" || port != 8080 {
		t.Error("could not parse foo.bar.svc.cluster.local.:8080")
	}

	id, port, err = parseK8sServiceFromAuthority("bar.svc.cluster.local")
	if err == nil {
		t.Error("should not have parsed bar.svc.cluster.local")
	}

	id, port, err = parseK8sServiceFromAuthority("bar.svc.cluster.local:8080")
	if err == nil {
		t.Error("should not have parsed bar.svc.cluster.local:8080")
	}

	id, port, err = parseK8sServiceFromAuthority("linkerd.io")
	if err == nil {
		t.Error("should not have parsed linkerd.io")
	}
}
