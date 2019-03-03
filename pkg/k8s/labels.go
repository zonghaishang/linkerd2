/*
Kubernetes labels and annotations used in Linkerd's control plane and data plane
Kubernetes configs.
*/

package k8s

import (
	"fmt"

	"github.com/linkerd/linkerd2/pkg/version"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

const (
	/*
	 * Labels
	 */

	// ControllerComponentLabel identifies this object as a component of Linkerd's
	// control plane (e.g. web, controller).
	ControllerComponentLabel = "linkerd.io/control-plane-component"

	// ControllerNSLabel is injected into mesh-enabled apps, identifying the
	// namespace of the Linkerd control plane.
	ControllerNSLabel = "linkerd.io/control-plane-ns"

	// ProxyDeploymentLabel is injected into mesh-enabled apps, identifying the
	// deployment that this proxy belongs to.
	ProxyDeploymentLabel = "linkerd.io/proxy-deployment"

	// ProxyReplicationControllerLabel is injected into mesh-enabled apps,
	// identifying the ReplicationController that this proxy belongs to.
	ProxyReplicationControllerLabel = "linkerd.io/proxy-replicationcontroller"

	// ProxyReplicaSetLabel is injected into mesh-enabled apps, identifying the
	// ReplicaSet that this proxy belongs to.
	ProxyReplicaSetLabel = "linkerd.io/proxy-replicaset"

	// ProxyJobLabel is injected into mesh-enabled apps, identifying the Job that
	// this proxy belongs to.
	ProxyJobLabel = "linkerd.io/proxy-job"

	// ProxyDaemonSetLabel is injected into mesh-enabled apps, identifying the
	// DaemonSet that this proxy belongs to.
	ProxyDaemonSetLabel = "linkerd.io/proxy-daemonset"

	// ProxyStatefulSetLabel is injected into mesh-enabled apps, identifying the
	// StatefulSet that this proxy belongs to.
	ProxyStatefulSetLabel = "linkerd.io/proxy-statefulset"

	/*
	 * Annotations
	 */

	// CreatedByAnnotation indicates the source of the injected data plane
	// (e.g. linkerd/cli v2.0.0).
	CreatedByAnnotation = "linkerd.io/created-by"

	// IdentityIssuerExpiryAnnotation indicates the time at which this set of identity
	// issuer credentials will cease to be valid.
	IdentityIssuerExpiryAnnotation = "linkerd.io/identity-issuer-expiry"

	// ProxyVersionAnnotation indicates the version of the injected data plane
	// (e.g. v0.1.3).
	ProxyVersionAnnotation = "linkerd.io/proxy-version"

	// ProxyInjectAnnotation controls whether or not a pod should be injected
	// when set on a pod spec. When set on a namespace spec, it applies to all
	// pods in the namespace. Supported values are "enabled" or "disabled"
	ProxyInjectAnnotation = "linkerd.io/inject"

	// ProxyInjectEnabled is assigned to the ProxyInjectAnnotation annotation to
	// enable injection for a pod or namespace.
	ProxyInjectEnabled = "enabled"

	// ProxyInjectDisabled is assigned to the ProxyInjectAnnotation annotation to
	// disable injection for a pod or namespace.
	ProxyInjectDisabled = "disabled"

	// IdentityModeAnnotation controls how a pod participates
	// in service identity.
	IdentityModeAnnotation = "linkerd.io/identity-mode"

	// IdentityModeDefault is assigned to IdentityModeAnnotation to
	// use the control plane's default identity scheme.
	IdentityModeDefault = "default"

	// IdentityModeDisabled is assigned to IdentityModeAnnotation to
	// disable the proxy from participating in automatic identity.
	IdentityModeDisabled = "disabled"

	// IdentityModeOptional is assigned to IdentityModeAnnotation to
	// optionally configure the proxy to participate in automatic identity.
	//
	// Deprecated.
	IdentityModeOptional = "optional"

	/*
	 * Component Names
	 */

	// InitContainerName is the name assigned to the injected init container.
	InitContainerName = "linkerd-init"

	// ProxyContainerName is the name assigned to the injected proxy container.
	ProxyContainerName = "linkerd-proxy"

	IdentityEndEntityVolumeName = "linkerd-identity-end-entity"

	// ProxyInjectorWebookConfig is the name of the mutating webhook
	// configuration resource of the proxy-injector webhook.
	ProxyInjectorWebhookConfig = "linkerd-proxy-injector-webhook-config"

	// MountPathBase is the base directory of the mount path
	MountPathBase = "/var/run/linkerd"
)

// InjectedLabels contains the list of label keys subjected to be injected by Linkerd into resource definitions
var InjectedLabels = []string{ControllerNSLabel, ProxyDeploymentLabel, ProxyReplicationControllerLabel,
	ProxyReplicaSetLabel, ProxyJobLabel, ProxyDaemonSetLabel, ProxyStatefulSetLabel}

var (
	// MountPathGlobalConfig is the path at which the global config file is mounted
	// in the control plane.
	MountPathGlobalConfig = MountPathBase + "/config/global"

	// MountPathProxyConfig is the path at which the proxy injection config file is
	// mounted in the control plane.
	MountPathProxyConfig = MountPathBase + "/config/proxy"
)

// CreatedByAnnotationValue returns the value associated with
// CreatedByAnnotation.
func CreatedByAnnotationValue() string {
	return fmt.Sprintf("linkerd/cli %s", version.Version)
}

// GetServiceAccountAndNS returns the pod's serviceaccount and namespace.
func GetServiceAccountAndNS(pod *corev1.Pod) (sa string, ns string) {
	sa = pod.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}

	ns = pod.GetNamespace()
	if ns == "" {
		ns = "default"
	}

	return
}

// GetPodLabels returns the set of prometheus owner labels for a given pod
func GetPodLabels(ownerKind, ownerName string, pod *corev1.Pod) map[string]string {
	labels := map[string]string{"pod": pod.Name}

	l5dLabel := KindToL5DLabel(ownerKind)
	labels[l5dLabel] = ownerName

	sa, _ := GetServiceAccountAndNS(pod)
	labels["serviceaccount"] = sa

	if controllerNS := pod.Labels[ControllerNSLabel]; controllerNS != "" {
		labels["control_plane_ns"] = controllerNS
	}

	if pth := pod.Labels[appsv1.DefaultDeploymentUniqueLabelKey]; pth != "" {
		labels["pod_template_hash"] = pth
	}

	return labels
}

// IsMeshed returns whether a given Pod is in a given controller's service mesh.
func IsMeshed(pod *corev1.Pod, controllerNS string) bool {
	return pod.Labels[ControllerNSLabel] == controllerNS
}
