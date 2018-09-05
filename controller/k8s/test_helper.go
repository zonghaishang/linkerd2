package k8s

import (
	spfake "github.com/linkerd/linkerd2/pkg/client/clientset/versioned/fake"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/kubernetes/scheme"
)

func toRuntimeObject(config string) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode([]byte(config), nil, nil)
	return obj, err
}

func NewFakeAPI(configs ...string) (*API, error) {
	objs := []runtime.Object{}
	spObjs := []runtime.Object{}
	for _, config := range configs {
		obj, err := toRuntimeObject(config)
		if err != nil {
			return nil, err
		}
		if config == k8s.ServiceProfile {
			spObjs = append(spObjs, obj)
		} else {
			objs = append(objs, obj)
		}
	}

	clientSet := fake.NewSimpleClientset(objs...)
	spClientSet := spfake.NewSimpleClientset(spObjs...)
	return NewAPI(
		clientSet,
		spClientSet,
		CM,
		Deploy,
		Endpoint,
		NS,
		Pod,
		RC,
		RS,
		Svc,
	), nil
}
