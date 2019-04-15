package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/flags"
	pkgK8s "github.com/linkerd/linkerd2/pkg/k8s"
	pkgTls "github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
	kauthzApi "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8s "k8s.io/client-go/kubernetes"
	"k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	"k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8088", "address to serve on")
	metricsAddr := flag.String("metrics-addr", ":9998", "address to serve scrapable metrics on")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	controllerNamespace := flag.String("controller-namespace", "linkerd", "namespace in which Linkerd is installed")
	flags.ConfigureAndParse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	config, err := pkgK8s.GetConfig(*kubeConfigPath, "")
	if err != nil {
		log.Fatalf("Failed to parse kubeconfig: %s", err)
	}

	// API client for interacting with the aggregation layer
	aggClientset, err := clientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create aggregator clientset: %s", err)
	}

	// Generate root serving CA on startup
	rootCA, err := pkgTls.GenerateRootCAWithDefaults("tap")
	if err != nil {
		log.Fatalf("failed to create root CA: %s", err)
	}

	// API client for reading config maps
	clientset, err := k8s.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create k8s clientset: %s", err)
	}

	// Get the aggregation client CA from a configmap
	authConfig, err := clientset.CoreV1().ConfigMaps("kube-system").Get("extension-apiserver-authentication", metav1.GetOptions{})
	if err != nil {
		log.Fatalf("Failed to get auth config map: %s", err)
	}
	log.Errorf("Loaded config map: %+v", authConfig.Data)

	clientCaPem := authConfig.Data["requestheader-client-ca-file"]
	allowedClientNames := parseList(authConfig.Data["requestheader-allowed-names"])

	// Root serving CA trust anchor
	trustAnchor := []byte(rootCA.Cred.EncodeCertificatePEM())

	// Serving TLS config
	tc, err := tlsConfig(rootCA, "linkerd-tap", "linkerd", clientCaPem, allowedClientNames)

	server := &http.Server{
		Addr:      *addr,
		TLSConfig: tc,
		Handler:   http.HandlerFunc(serve(clientset)),
	}

	// Start serving
	go func() {
		log.Println("starting http server on", *addr)
		err := server.ListenAndServeTLS("", "")
		if err != nil {
			log.Errorf("Server stopped: %s", err)
		} else {
			log.Error("Server stopped")
		}
	}()

	go admin.StartServer(*metricsAddr)

	// Update or create API service registration
	registration, err := aggClientset.ApiregistrationV1().APIServices().Get("v1alpha1.tap.linkerd.io", metav1.GetOptions{})
	if err != nil {
		log.Errorf("Unable to get registraiton: %s", err)
	}

	if registration != nil {
		log.Error("Updating registration...")
		registration.Spec = v1.APIServiceSpec{
			Service: &v1.ServiceReference{
				Name:      "linkerd-tap",
				Namespace: "linkerd",
			},
			Group:                "tap.linkerd.io",
			GroupPriorityMinimum: 1000,
			Version:              "v1alpha1",
			VersionPriority:      100,
			CABundle:             trustAnchor,
		}
		registration, err = aggClientset.ApiregistrationV1().APIServices().Update(registration)
		if err != nil {
			log.Errorf("Failed to update registration: %s", err)
		} else {
			log.Errorf("Successfullly updated registration: %+v", *registration)
		}
	} else {
		log.Error("Creating registration...")
		registration := &v1.APIService{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "v1alpha1.tap.linkerd.io",
				Namespace: *controllerNamespace,
			},
			Spec: v1.APIServiceSpec{
				Service: &v1.ServiceReference{
					Name:      "linkerd-tap",
					Namespace: "linkerd",
				},
				Group:                "tap.linkerd.io",
				GroupPriorityMinimum: 1000,
				Version:              "v1alpha1",
				VersionPriority:      100,
				CABundle:             trustAnchor,
			},
		}
		_, err = aggClientset.ApiregistrationV1().APIServices().Create(registration)
		if err != nil {
			log.Errorf("Failed to create api service: %s", err)
		} else {
			log.Errorf("Successfully created api service: %+v", *registration)
		}
	}

	<-stop

	log.Println("shutting down http server on", *addr)
	server.Shutdown(context.Background())
}

func serve(api k8s.Interface) func(res http.ResponseWriter, req *http.Request) {
	return func(res http.ResponseWriter, req *http.Request) {
		log.Errorf("Tap request: %s", req.URL)
		log.Errorf("Got headers: %v", req.Header)
		// Verify that the client sent a certificate.  If a client cert was
		// sent, we can assume it has already been validated (as we specified
		// in the TLSConfig).
		if len(req.TLS.PeerCertificates) > 0 {
			log.Errorf("Request has client cert: %s", req.TLS.PeerCertificates[0].Subject.CommonName)
			// TODO: validate the common name against the allowed names from the configmap
		} else {
			log.Error("Request has no client cert")
		}

		// The aggreagtion layer gives us the authenticated user name in headers.
		user := req.Header.Get("X-Remote-User")
		group := req.Header.Get("X-Remote-Group")

		log.Errorf("Doing authz check for %s of %s", user, group)

		// RBAC check that the authenticated user can tap
		r := &kauthzApi.SubjectAccessReview{
			Spec: kauthzApi.SubjectAccessReviewSpec{
				Groups: []string{group},
				User:   user,
				ResourceAttributes: &kauthzApi.ResourceAttributes{
					Resource:    "pods",
					Subresource: "tap",
					Verb:        "get",
				},
			},
		}
		rvw, err := api.AuthorizationV1().SubjectAccessReviews().Create(r)
		if err != nil {
			log.Errorf("Error creating access review: %s", err)
		} else {
			log.Error("Access review created successfully...")
		}
		if rvw.Status.Allowed {
			fmt.Fprintf(res, "User %s is permitted to tap", user)
		} else {
			fmt.Fprintf(res, "User %s is not permitted to tap because: %s", user, rvw.Status.Reason)
		}
	}
}

func tlsConfig(rootCA *pkgTls.CA, name, controllerNamespace string, clientCaPem string, allowedClientNames []string) (*tls.Config, error) {
	// must use the service short name in this TLS identity as the k8s api server
	// looks for the webhook at <svc_name>.<namespace>.svc, without the cluster
	// domain.
	dnsName := fmt.Sprintf("%s.%s.svc", name, controllerNamespace)

	cred, err := rootCA.GenerateEndEntityCred(dnsName)
	if err != nil {
		return nil, err
	}

	certPEM := cred.EncodePEM()
	keyPEM := cred.EncodePrivateKeyPEM()
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}

	log.Errorf("Using client ca: %s", clientCaPem)

	clientCaPool := x509.NewCertPool()
	ok := clientCaPool.AppendCertsFromPEM([]byte(clientCaPem))
	if !ok {
		return nil, fmt.Errorf("Failed to add client ca to cert pool")
	}

	log.Errorf("client ca pool has %d subjects", len(clientCaPool.Subjects()))

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    clientCaPool,
	}, nil
}

func parseList(input string) []string {
	input = strings.TrimPrefix(input, "[")
	input = strings.TrimSuffix(input, "]")
	output := strings.Split(input, ",")
	for i, o := range output {
		o = strings.TrimPrefix(o, "\"")
		o = strings.TrimSuffix(o, "\"")
		output[i] = o
	}
	return output
}
