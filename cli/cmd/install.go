package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/ptypes"
	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/helm/pkg/chartutil"
	"k8s.io/helm/pkg/proto/hapi/chart"
	"k8s.io/helm/pkg/renderutil"
	"k8s.io/helm/pkg/timeconv"
	"sigs.k8s.io/yaml"

	"github.com/linkerd/linkerd2/cli/static"
	pb "github.com/linkerd/linkerd2/controller/gen/config"
	"github.com/linkerd/linkerd2/pkg/config"
	"github.com/linkerd/linkerd2/pkg/k8s"
	"github.com/linkerd/linkerd2/pkg/tls"
	"github.com/linkerd/linkerd2/pkg/version"
)

type (
	installConfig struct {
		Namespace                string
		ControllerImage          string
		WebImage                 string
		PrometheusImage          string
		PrometheusVolumeName     string
		GrafanaImage             string
		GrafanaVolumeName        string
		ControllerReplicas       uint
		ImagePullPolicy          string
		UUID                     string
		CliVersion               string
		ControllerLogLevel       string
		ControllerComponentLabel string
		CreatedByAnnotation      string
		ProxyContainerName       string
		ProxyAutoInjectEnabled   bool
		ProxyInjectAnnotation    string
		ProxyInjectDisabled      string
		SingleNamespace          bool
		EnableHA                 bool
		ControllerUID            int64
		EnableH2Upgrade          bool
		NoInitContainer          bool
		GlobalConfig             string
		ProxyConfig              string

		EnableTLS bool
		Identity  *installIdentityConfig
	}

	installIdentityConfig struct {
		TrustDomain     string
		TrustAnchorsPEM string

		Issuer *issuerConfig
	}

	issuerConfig struct {
		ClockSkewAllowance string
		IssuanceLifetime   string

		KeyPEM, CrtPEM string

		CrtExpiry time.Time

		CrtExpiryAnnotation string
	}

	// installOptions holds values for command line flags that apply to the install
	// command. All fields in this struct should have corresponding flags added in
	// the newCmdInstall func later in this file. It also embeds proxyConfigOptions
	// in order to hold values for command line flags that apply to both inject and
	// install.
	installOptions struct {
		controllerReplicas uint
		controllerLogLevel string
		proxyAutoInject    bool
		singleNamespace    bool
		highAvailability   bool
		controllerUID      int64
		disableH2Upgrade   bool
		identityOptions    installIdentityOptions
		proxyConfigOptions
	}

	installIdentityOptions struct {
		trustDomain        string
		issuanceLifetime   time.Duration
		clockSkewAllowance time.Duration
	}

	clusterState struct {
		configs configs
		issuer  struct{ keyPEM, crtPEM string }
	}
)

const (
	prometheusProxyOutboundCapacity   = 10000
	defaultControllerReplicas         = 1
	defaultHAControllerReplicas       = 3
	defaultIdentityTrustDomain        = "cluster.local"
	defaultIdentityIssuanceLifetime   = 2 * time.Minute
	defaultIdentityClockSkewAllowance = 2 * time.Minute

	nsTemplateName             = "templates/namespace.yaml"
	identityTemplateName       = "templates/identity.yaml"
	controllerTemplateName     = "templates/controller.yaml"
	webTemplateName            = "templates/web.yaml"
	prometheusTemplateName     = "templates/prometheus.yaml"
	grafanaTemplateName        = "templates/grafana.yaml"
	serviceprofileTemplateName = "templates/serviceprofile.yaml"
	proxyInjectorTemplateName  = "templates/proxy_injector.yaml"
)

func newInstallOptions() *installOptions {
	return &installOptions{
		controllerReplicas: defaultControllerReplicas,
		controllerLogLevel: "info",
		proxyAutoInject:    false,
		singleNamespace:    false,
		highAvailability:   false,
		controllerUID:      2103,
		disableH2Upgrade:   false,

		proxyConfigOptions: proxyConfigOptions{
			linkerdVersion:          version.Version,
			proxyImage:              defaultDockerRegistry + "/proxy",
			initImage:               defaultDockerRegistry + "/proxy-init",
			dockerRegistry:          defaultDockerRegistry,
			imagePullPolicy:         "IfNotPresent",
			inboundPort:             4143,
			outboundPort:            4140,
			ignoreInboundPorts:      nil,
			ignoreOutboundPorts:     nil,
			proxyUID:                2102,
			proxyLogLevel:           "warn,linkerd2_proxy=info",
			proxyControlPort:        4190,
			proxyMetricsPort:        4191,
			proxyCPURequest:         "",
			proxyMemoryRequest:      "",
			proxyCPULimit:           "",
			proxyMemoryLimit:        "",
			disableExternalProfiles: false,
			noInitContainer:         false,
		},

		identityOptions: installIdentityOptions{
			trustDomain:        defaultIdentityTrustDomain,
			issuanceLifetime:   defaultIdentityIssuanceLifetime,
			clockSkewAllowance: defaultIdentityClockSkewAllowance,
		},
	}
}

func newCmdInstall() *cobra.Command {
	options := newInstallOptions()

	cmd := &cobra.Command{
		Use:   "install [flags]",
		Short: "Output Kubernetes configs to install Linkerd",
		Long:  "Output Kubernetes configs to install Linkerd.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cluster, err := fetchClusterState()
			if err != nil {
				return err
			}

			config, err := validateAndBuildConfig(cluster, options)
			if err != nil {
				return err
			}

			return render(*config, os.Stdout, options)
		},
	}

	addProxyConfigFlags(cmd, &options.proxyConfigOptions)
	cmd.PersistentFlags().UintVar(&options.controllerReplicas, "controller-replicas", options.controllerReplicas, "Replicas of the controller to deploy")
	cmd.PersistentFlags().StringVar(&options.controllerLogLevel, "controller-log-level", options.controllerLogLevel, "Log level for the controller and web components")
	cmd.PersistentFlags().BoolVar(&options.proxyAutoInject, "proxy-auto-inject", options.proxyAutoInject, "Enable proxy sidecar auto-injection via a webhook (default false)")
	cmd.PersistentFlags().BoolVar(&options.singleNamespace, "single-namespace", options.singleNamespace, "Experimental: Configure the control plane to only operate in the installed namespace (default false)")
	cmd.PersistentFlags().BoolVar(&options.highAvailability, "ha", options.highAvailability, "Experimental: Enable HA deployment config for the control plane (default false)")
	cmd.PersistentFlags().Int64Var(&options.controllerUID, "controller-uid", options.controllerUID, "Run the control plane components under this user ID")
	cmd.PersistentFlags().BoolVar(&options.disableH2Upgrade, "disable-h2-upgrade", options.disableH2Upgrade, "Prevents the controller from instructing proxies to perform transparent HTTP/2 upgrading (default false)")
	return cmd
}

func fetchClusterState() (state clusterState, err error) {
	api, err := k8s.NewAPI(kubeconfigPath, kubeContext)
	if err != nil {
		return
	}

	k, err := kubernetes.NewForConfig(api.Config)
	if err != nil {
		return
	}

	configMaps := k.CoreV1().ConfigMaps(controlPlaneNamespace)
	if g, p, err := config.Fetch(configMaps); err == nil {
		state.configs.global = g
		state.configs.proxy = p
	}

	// If we can't fetch the issuer secrets, then we assume they don't exist...
	secrets := k.CoreV1().Secrets(controlPlaneNamespace)
	if s, e := secrets.Get("linkerd-identity-issuer", metav1.GetOptions{}); e == nil {
		state.issuer.crtPEM = string(s.Data["crt.pem"])
		state.issuer.keyPEM = string(s.Data["key.pem"])
	}

	return
}

func validateAndBuildConfig(state clusterState, options *installOptions) (*installConfig, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}

	if options.highAvailability && options.controllerReplicas == defaultControllerReplicas {
		options.controllerReplicas = defaultHAControllerReplicas
	}

	if options.highAvailability && options.proxyCPURequest == "" {
		options.proxyCPURequest = "10m"
	}

	if options.highAvailability && options.proxyMemoryRequest == "" {
		options.proxyMemoryRequest = "20Mi"
	}

	if state.configs.global == nil {
		state.configs.global = &pb.Global{}
	}

	// TODO accept roots as configuration
	var identity *installIdentityConfig
	if options.enableTLS() {
		idctx := state.configs.global.GetIdentityContext()
		if idctx != nil && state.issuer.crtPEM != "" && state.issuer.keyPEM != "" {
			crt, err := tls.DecodePEMCrt(state.issuer.crtPEM)
			if err != nil {
				return nil, err
			}

			var csa time.Duration
			if d := idctx.GetClockSkewAllowance(); d != nil {
				csa, err = ptypes.Duration(d)
				if err != nil {
					return nil, err
				}
			} else {
				csa = options.identityOptions.clockSkewAllowance
			}

			var il time.Duration
			if d := idctx.GetIssuanceLifetime(); d != nil {
				il, err = ptypes.Duration(d)
				if err != nil {
					return nil, err
				}
			} else {
				il = options.identityOptions.issuanceLifetime
			}

			identity = &installIdentityConfig{
				TrustDomain:     idctx.GetTrustDomain(),
				TrustAnchorsPEM: idctx.GetTrustAnchorsPem(),
				Issuer: &issuerConfig{
					ClockSkewAllowance:  csa.String(),
					IssuanceLifetime:    il.String(),
					CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,

					KeyPEM:    state.issuer.keyPEM,
					CrtPEM:    state.issuer.crtPEM,
					CrtExpiry: crt.Certificate.NotAfter,
				},
			}
		} else {
			trustDomain := options.identityOptions.trustDomain
			root, err := tls.GenerateRootCAWithDefaults(fmt.Sprintf("identity.%s", trustDomain))
			if err != nil {
				return nil, fmt.Errorf("Failed to create root certificate for identity: %s", err)
			}

			identity = &installIdentityConfig{
				TrustDomain:     trustDomain,
				TrustAnchorsPEM: root.Cred.Crt.EncodeCertificatePEM(),
				Issuer: &issuerConfig{
					ClockSkewAllowance:  options.identityOptions.clockSkewAllowance.String(),
					IssuanceLifetime:    options.identityOptions.issuanceLifetime.String(),
					CrtExpiryAnnotation: k8s.IdentityIssuerExpiryAnnotation,

					KeyPEM:    root.Cred.EncodePrivateKeyPEM(),
					CrtPEM:    root.Cred.Crt.EncodeCertificatePEM(),
					CrtExpiry: root.Cred.Crt.Certificate.NotAfter,
				},
			}
		}
	}

	jsonMarshaler := jsonpb.Marshaler{EmitDefaults: true}
	globalConfig, err := jsonMarshaler.MarshalToString(globalConfig(options, identity))
	if err != nil {
		return nil, err
	}

	proxyConfig, err := jsonMarshaler.MarshalToString(proxyConfig(options))
	if err != nil {
		return nil, err
	}

	return &installConfig{
		Namespace:                controlPlaneNamespace,
		ControllerImage:          fmt.Sprintf("%s/controller:%s", options.dockerRegistry, options.linkerdVersion),
		WebImage:                 fmt.Sprintf("%s/web:%s", options.dockerRegistry, options.linkerdVersion),
		PrometheusImage:          "prom/prometheus:v2.7.1",
		PrometheusVolumeName:     "data",
		GrafanaImage:             fmt.Sprintf("%s/grafana:%s", options.dockerRegistry, options.linkerdVersion),
		GrafanaVolumeName:        "data",
		ControllerReplicas:       options.controllerReplicas,
		ImagePullPolicy:          options.imagePullPolicy,
		UUID:                     uuid.NewV4().String(),
		CliVersion:               k8s.CreatedByAnnotationValue(),
		ControllerLogLevel:       options.controllerLogLevel,
		ControllerComponentLabel: k8s.ControllerComponentLabel,
		ControllerUID:            options.controllerUID,
		CreatedByAnnotation:      k8s.CreatedByAnnotation,
		EnableTLS:                options.enableTLS(),
		ProxyContainerName:       k8s.ProxyContainerName,
		ProxyAutoInjectEnabled:   options.proxyAutoInject,
		ProxyInjectAnnotation:    k8s.ProxyInjectAnnotation,
		ProxyInjectDisabled:      k8s.ProxyInjectDisabled,
		SingleNamespace:          options.singleNamespace,
		EnableHA:                 options.highAvailability,
		EnableH2Upgrade:          !options.disableH2Upgrade,
		NoInitContainer:          options.noInitContainer,
		GlobalConfig:             globalConfig,
		ProxyConfig:              proxyConfig,
		Identity:                 identity,
	}, nil
}

func render(config installConfig, w io.Writer, options *installOptions) error {
	// Render raw values and create chart config
	rawValues, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	chrtConfig := &chart.Config{Raw: string(rawValues), Values: map[string]*chart.Value{}}

	files := []*chartutil.BufferedFile{
		{Name: chartutil.ChartfileName},
		{Name: nsTemplateName},
		{Name: identityTemplateName},
		{Name: controllerTemplateName},
		{Name: serviceprofileTemplateName},
		{Name: webTemplateName},
		{Name: prometheusTemplateName},
		{Name: grafanaTemplateName},
		{Name: proxyInjectorTemplateName},
	}

	// Read templates into bytes
	for _, f := range files {
		data, err := readIntoBytes(f.Name)
		if err != nil {
			return err
		}
		f.Data = data
	}

	// Create chart and render templates
	chrt, err := chartutil.LoadFiles(files)
	if err != nil {
		return err
	}

	renderOpts := renderutil.Options{
		ReleaseOptions: chartutil.ReleaseOptions{
			Name:      "linkerd",
			IsInstall: true,
			IsUpgrade: false,
			Time:      timeconv.Now(),
			Namespace: controlPlaneNamespace,
		},
		KubeVersion: "",
	}

	renderedTemplates, err := renderutil.Render(chrt, chrtConfig, renderOpts)
	if err != nil {
		return err
	}

	// Merge templates and inject
	var buf bytes.Buffer
	for _, tmpl := range files {
		t := path.Join(renderOpts.ReleaseOptions.Name, tmpl.Name)
		if _, err := buf.WriteString(renderedTemplates[t]); err != nil {
			return err
		}
	}

	injectOptions := newInjectOptions()

	injectOptions.proxyConfigOptions = options.proxyConfigOptions

	// Skip outbound port 443 to enable Kubernetes API access without the proxy.
	// Once Kubernetes supports sidecar containers, this may be removed, as that
	// will guarantee the proxy is running prior to control-plane startup.
	injectOptions.ignoreOutboundPorts = append(injectOptions.ignoreOutboundPorts, 443)

	// TODO: Fetch GlobalConfig and ProxyConfig from the ConfigMap/API
	// c, err := fetchConfigsFromK8s()
	// if err != nil {
	// 	return err
	// }
	injectConfig := newConfig()
	injectConfig.overrideFromOptions(injectOptions)

	// Override does NOT set an identity context if none exists, since it can't be
	// enabled at inject-time if it's not enabled at install-time.
	if config.Identity != nil {
		id := config.Identity
		il, err := time.ParseDuration(id.Issuer.IssuanceLifetime)
		if err != nil {
			il = defaultIdentityIssuanceLifetime
		}

		csa, err := time.ParseDuration(id.Issuer.ClockSkewAllowance)
		if err != nil {
			csa = defaultIdentityClockSkewAllowance
		}

		injectConfig.global.IdentityContext = &pb.IdentityContext{
			TrustDomain:        id.TrustDomain,
			TrustAnchorsPem:    id.TrustAnchorsPEM,
			IssuanceLifetime:   ptypes.DurationProto(il),
			ClockSkewAllowance: ptypes.DurationProto(csa),
		}
	}

	return processYAML(&buf, w, ioutil.Discard, resourceTransformerInject{
		configs: injectConfig,
		proxyOutboundCapacity: map[string]uint{
			config.PrometheusImage: prometheusProxyOutboundCapacity,
		},
	})
}

func (options *installOptions) validate() error {
	if _, err := log.ParseLevel(options.controllerLogLevel); err != nil {
		return fmt.Errorf("--controller-log-level must be one of: panic, fatal, error, warn, info, debug")
	}

	if options.proxyAutoInject && options.singleNamespace {
		return fmt.Errorf("The --proxy-auto-inject and --single-namespace flags cannot both be specified together")
	}

	return options.proxyConfigOptions.validate()
}

func readIntoBytes(filename string) ([]byte, error) {
	file, err := static.Templates.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := new(bytes.Buffer)
	buf.ReadFrom(file)

	return buf.Bytes(), nil
}

func globalConfig(options *installOptions, id *installIdentityConfig) *pb.Global {
	var identityContext *pb.IdentityContext
	if id != nil {
		il, err := time.ParseDuration(id.Issuer.IssuanceLifetime)
		if err != nil {
			il = defaultIdentityIssuanceLifetime
		}

		csa, err := time.ParseDuration(id.Issuer.ClockSkewAllowance)
		if err != nil {
			csa = defaultIdentityClockSkewAllowance
		}

		identityContext = &pb.IdentityContext{
			TrustDomain:        id.TrustDomain,
			TrustAnchorsPem:    id.TrustAnchorsPEM,
			IssuanceLifetime:   ptypes.DurationProto(il),
			ClockSkewAllowance: ptypes.DurationProto(csa),
		}
	}

	return &pb.Global{
		LinkerdNamespace: controlPlaneNamespace,
		CniEnabled:       options.noInitContainer,
		Version:          options.linkerdVersion,
		IdentityContext:  identityContext,
	}
}

func proxyConfig(options *installOptions) *pb.Proxy {
	ignoreInboundPorts := []*pb.Port{}
	for _, port := range options.ignoreInboundPorts {
		ignoreInboundPorts = append(ignoreInboundPorts, &pb.Port{Port: uint32(port)})
	}

	ignoreOutboundPorts := []*pb.Port{}
	for _, port := range options.ignoreOutboundPorts {
		ignoreOutboundPorts = append(ignoreOutboundPorts, &pb.Port{Port: uint32(port)})
	}

	return &pb.Proxy{
		ProxyImage: &pb.Image{
			ImageName:  registryOverride(options.proxyImage, options.dockerRegistry),
			PullPolicy: options.imagePullPolicy,
		},
		ProxyInitImage: &pb.Image{
			ImageName:  registryOverride(options.initImage, options.dockerRegistry),
			PullPolicy: options.imagePullPolicy,
		},
		DestinationApiPort: &pb.Port{Port: 8086},
		ControlPort: &pb.Port{
			Port: uint32(options.proxyControlPort),
		},
		IgnoreInboundPorts:  ignoreInboundPorts,
		IgnoreOutboundPorts: ignoreOutboundPorts,
		InboundPort: &pb.Port{
			Port: uint32(options.inboundPort),
		},
		MetricsPort: &pb.Port{
			Port: uint32(options.proxyMetricsPort),
		},
		OutboundPort: &pb.Port{
			Port: uint32(options.outboundPort),
		},
		Resource: &pb.ResourceRequirements{
			RequestCpu:    options.proxyCPURequest,
			RequestMemory: options.proxyMemoryRequest,
			LimitCpu:      options.proxyCPULimit,
			LimitMemory:   options.proxyMemoryLimit,
		},
		ProxyUid: options.proxyUID,
		LogLevel: &pb.LogLevel{
			Level: options.proxyLogLevel,
		},
		DisableExternalProfiles: options.disableExternalProfiles,
	}
}
