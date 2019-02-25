package k8s

import (
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/prometheus"
	"k8s.io/client-go/kubernetes"

	// Load all the auth plugins for the cloud providers.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// NewClientSet returns a Kubernetes client for the given configuration.
func NewClientSet(kubeConfig string) (*kubernetes.Clientset, error) {
	config, err := k8s.GetConfig(kubeConfig, "")
	if err != nil {
		return nil, err
	}

	wt := config.WrapTransport
	config.WrapTransport = prometheus.ClientWithTelemetry("k8s", wt)
	return kubernetes.NewForConfig(config)
}
