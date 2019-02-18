package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	jsonpatch "github.com/evanphx/json-patch"

	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/injector"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/spf13/cobra"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

const (
	// LocalhostDNSNameOverride allows override of the controlPlaneDNS. This
	// must be in absolute form for the proxy to special-case it.
	LocalhostDNSNameOverride = "localhost."
	// ControlPlanePodName default control plane pod name.
	ControlPlanePodName = "linkerd-controller"
	// PodNamespaceEnvVarName is the name of the variable used to pass the pod's namespace.
	PodNamespaceEnvVarName = "LINKERD2_PROXY_POD_NAMESPACE"

	// for inject reports

	hostNetworkDesc    = "pods do not use host networking"
	sidecarDesc        = "pods do not have a 3rd party proxy or initContainer already injected"
	injectDisabledDesc = "pods are not annotated to disable injection"
	unsupportedDesc    = "at least one resource injected"
	udpDesc            = "pod specs do not include UDP ports"
)

type injectOptions struct {
	*proxyConfigOptions
}

type resourceTransformerInject struct{}

// InjectYAML processes resource definitions and outputs them after injection in out
func InjectYAML(in io.Reader, out io.Writer, report io.Writer, globalConfig *pb.GlobalConfig, proxyConfig *pb.ProxyConfig) error {
	return ProcessYAML(in, out, report, globalConfig, proxyConfig, resourceTransformerInject{})
}

func runInjectCmd(inputs []io.Reader, errWriter, outWriter io.Writer, globalConfig *pb.GlobalConfig, proxyConfig *pb.ProxyConfig) int {
	return transformInput(inputs, errWriter, outWriter, globalConfig, proxyConfig, resourceTransformerInject{})
}

// objMeta provides a generic struct to parse the names of Kubernetes objects
type objMeta struct {
	metaV1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
}

func newInjectOptions() *injectOptions {
	return &injectOptions{
		proxyConfigOptions: newProxyConfigOptions(),
	}
}

func newCmdInject() *cobra.Command {
	options := newInjectOptions()

	cmd := &cobra.Command{
		Use:   "inject [flags] CONFIG-FILE",
		Short: "Add the Linkerd proxy to a Kubernetes config",
		Long: `Add the Linkerd proxy to a Kubernetes config.

You can inject resources contained in a single file, inside a folder and its
sub-folders, or coming from stdin.`,
		Example: `  # Inject all the deployments in the default namespace.
  kubectl get deploy -o yaml | linkerd inject - | kubectl apply -f -

  # Download a resource and inject it through stdin.
  curl http://url.to/yml | linkerd inject - | kubectl apply -f -

  # Inject all the resources inside a folder and its sub-folders.
  linkerd inject <folder> | kubectl apply -f -`,
		RunE: func(cmd *cobra.Command, args []string) error {

			if len(args) < 1 {
				return fmt.Errorf("please specify a kubernetes resource file")
			}

			if err := options.validate(); err != nil {
				return err
			}

			in, err := read(args[0])
			if err != nil {
				return err
			}

			// TODO: Fetch GlobalConfig and ProxyConfig from the ConfigMap/API
			globalConfig, proxyConfig := injectOptionsToConfigs(options)

			exitCode := uninjectAndInject(in, stderr, stdout, globalConfig, proxyConfig)
			os.Exit(exitCode)
			return nil
		},
	}

	addProxyConfigFlags(cmd, options.proxyConfigOptions)

	return cmd
}

func uninjectAndInject(inputs []io.Reader, errWriter, outWriter io.Writer, globalConfig *pb.GlobalConfig, proxyConfig *pb.ProxyConfig) int {
	var out bytes.Buffer
	if exitCode := runUninjectSilentCmd(inputs, errWriter, &out, nil, nil); exitCode != 0 {
		return exitCode
	}
	return runInjectCmd([]io.Reader{&out}, errWriter, outWriter, globalConfig, proxyConfig)
}

func (resourceTransformerInject) transform(bytes []byte, globalConfig *pb.GlobalConfig, proxyConfig *pb.ProxyConfig) ([]byte, []injector.InjectReport, error) {
	//fmt.Printf("transform bytes: %v\n", string(bytes))
	conf := &injector.ResourceConfig{
		K8sLabels: map[string]string{},
	}
	// Unmarshal the object enough to read the Kind field
	if err := yaml.Unmarshal(bytes, &conf.Meta); err != nil {
		return nil, nil, err
	}
	patchJSON, reports, err := conf.Transform(bytes, globalConfig, proxyConfig)
	if err != nil {
		return nil, nil, err
	}
	patch, err := jsonpatch.DecodePatch(patchJSON)
	if err != nil {
		return nil, nil, err
	}
	origJSON, err := yaml.YAMLToJSON(bytes)
	if err != nil {
		return nil, nil, err
	}
	injectedJSON, err := patch.Apply(origJSON)
	if err != nil {
		return nil, nil, err
	}
	injectedYAML, err := yaml.JSONToYAML(injectedJSON)
	if err != nil {
		return nil, nil, err
	}
	return injectedYAML, reports, nil
}

func (resourceTransformerInject) generateReport(injectReports []injector.InjectReport, output io.Writer) {
	injected := []injector.InjectReport{}
	hostNetwork := []string{}
	sidecar := []string{}
	udp := []string{}
	injectDisabled := []string{}
	warningsPrinted := verbose

	for _, r := range injectReports {
		if !r.HostNetwork && !r.Sidecar && !r.UnsupportedResource && !r.InjectDisabled {
			injected = append(injected, r)
		}

		if r.HostNetwork {
			hostNetwork = append(hostNetwork, r.ResName())
			warningsPrinted = true
		}

		if r.Sidecar {
			sidecar = append(sidecar, r.ResName())
			warningsPrinted = true
		}

		if r.Udp {
			udp = append(udp, r.ResName())
			warningsPrinted = true
		}

		if r.InjectDisabled {
			injectDisabled = append(injectDisabled, r.ResName())
			warningsPrinted = true
		}
	}

	//
	// Warnings
	//

	// leading newline to separate from yaml output on stdout
	output.Write([]byte("\n"))

	if len(hostNetwork) > 0 {
		output.Write([]byte(fmt.Sprintf("%s \"hostNetwork: true\" detected in %s\n", warnStatus, strings.Join(hostNetwork, ", "))))
	} else if verbose {
		output.Write([]byte(fmt.Sprintf("%s %s\n", okStatus, hostNetworkDesc)))
	}

	if len(sidecar) > 0 {
		output.Write([]byte(fmt.Sprintf("%s known 3rd party sidecar detected in %s\n", warnStatus, strings.Join(sidecar, ", "))))
	} else if verbose {
		output.Write([]byte(fmt.Sprintf("%s %s\n", okStatus, sidecarDesc)))
	}

	if len(injectDisabled) > 0 {
		output.Write([]byte(fmt.Sprintf("%s \"%s: %s\" annotation set on %s\n",
			warnStatus, k8s.ProxyInjectAnnotation, k8s.ProxyInjectDisabled, strings.Join(injectDisabled, ", "))))
	} else if verbose {
		output.Write([]byte(fmt.Sprintf("%s %s\n", okStatus, injectDisabledDesc)))
	}

	if len(injected) == 0 {
		output.Write([]byte(fmt.Sprintf("%s no supported objects found\n", warnStatus)))
		warningsPrinted = true
	} else if verbose {
		output.Write([]byte(fmt.Sprintf("%s %s\n", okStatus, unsupportedDesc)))
	}

	if len(udp) > 0 {
		verb := "uses"
		if len(udp) > 1 {
			verb = "use"
		}
		output.Write([]byte(fmt.Sprintf("%s %s %s \"protocol: UDP\"\n", warnStatus, strings.Join(udp, ", "), verb)))
	} else if verbose {
		output.Write([]byte(fmt.Sprintf("%s %s\n", okStatus, udpDesc)))
	}

	//
	// Summary
	//
	if warningsPrinted {
		output.Write([]byte("\n"))
	}

	for _, r := range injectReports {
		if !r.HostNetwork && !r.Sidecar && !r.UnsupportedResource && !r.InjectDisabled {
			output.Write([]byte(fmt.Sprintf("%s \"%s\" injected\n", r.Kind, r.Name)))
		} else {
			if r.Kind != "" {
				output.Write([]byte(fmt.Sprintf("%s \"%s\" skipped\n", r.Kind, r.Name)))
			} else {
				output.Write([]byte(fmt.Sprintf("document missing \"kind\" field, skipped\n")))
			}
		}
	}

	// trailing newline to separate from kubectl output if piping
	output.Write([]byte("\n"))
}

func injectOptionsToConfigs(options *injectOptions) (*pb.GlobalConfig, *pb.ProxyConfig) {
	globalConfig := &pb.GlobalConfig{
		LinkerdNamespace: controlPlaneNamespace,
		CniEnabled:       options.noInitContainer,
		IdentityContext:  nil,
	}
	var ignoreInboundPorts []*pb.Port
	for _, port := range options.ignoreInboundPorts {
		ignoreInboundPorts = append(ignoreInboundPorts, &pb.Port{Port: uint32(port)})
	}
	var ignoreOutboundPorts []*pb.Port
	for _, port := range options.ignoreOutboundPorts {
		ignoreOutboundPorts = append(ignoreOutboundPorts, &pb.Port{Port: uint32(port)})
	}
	proxyConfig := &pb.ProxyConfig{
		ProxyImage:              &pb.Image{ImageName: options.proxyImage, PullPolicy: options.imagePullPolicy, Registry: options.dockerRegistry},
		ProxyInitImage:          &pb.Image{ImageName: options.initImage, PullPolicy: options.imagePullPolicy, Registry: options.dockerRegistry},
		ApiPort:                 &pb.Port{Port: uint32(options.destinationAPIPort)},
		ControlPort:             &pb.Port{Port: uint32(options.proxyControlPort)},
		IgnoreInboundPorts:      ignoreInboundPorts,
		IgnoreOutboundPorts:     ignoreOutboundPorts,
		InboundPort:             &pb.Port{Port: uint32(options.inboundPort)},
		MetricsPort:             &pb.Port{Port: uint32(options.proxyMetricsPort)},
		OutboundPort:            &pb.Port{Port: uint32(options.outboundPort)},
		Resource:                &pb.ResourceRequirements{RequestCpu: options.proxyCPURequest, RequestMemory: options.proxyMemoryRequest},
		ProxyUid:                options.proxyUID,
		LogLevel:                &pb.LogLevel{Level: options.proxyLogLevel},
		DisableExternalProfiles: options.disableExternalProfiles,
	}
	return globalConfig, proxyConfig
}
