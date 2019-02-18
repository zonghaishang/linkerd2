package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/flags"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/x509util"

	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":8083", "address to serve on")
	adminAddr := flag.String("admin-addr", ":9996", "address of HTTP admin server")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	controllerNS := flag.String("controller-namespace", "linkerd", "namespace in which Linkerd is installed")
	trustDomain := flag.String("trust-domain", "cluster.local", "trust domain for identities")
	trustAnchors := flag.String("trust anchors", "", "path to trust anchors")
	signingKey := flag.String("signing-key", "", "path to signing key")
	signingCrt := flag.String("signing-crt", "", "path to signing certificate")
	signingIntermediates := flag.String("signing-intermediates", "", "path to signing key")
	signingLifetime := flag.Duration("signing-valid-for", 24*time.Hour, "Signature validityl ifetime")
	flags.ConfigureAndParse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	dom, err := identity.NewTrustDomain(*controllerNS, *trustDomain)
	if err != nil {
		log.Fatalf("Invalid trust domain: %s", err.Error())
	}

	issuer, err := x509util.LoadIdentityFromDisk(*signingCrt, *signingKey)
	if err != nil {
		log.Fatalf("Failed to load signing identity from key=%s and crt=%s: %s",
			*signingCrt, *signingKey, err)
	}

	k8s, err := k8s.NewClientSet(*kubeConfigPath)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %s: %s", *kubeConfigPath, err)
	}
	srv := grpc.NewServer()
	identity.Register(srv, k8s.Authentication(), dom, issuer, *signingLifetime)

	go admin.StartServer(*adminAddr)

	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %s", *addr, err)
	}
	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()

	<-stop
	log.Infof("shutting down gRPC server on %s", *addr)
	srv.GracefulStop()
}

func parseCrt(crtb []byte) (*x509.Certificate, []byte, error) {
	block, crtb := pem.Decode(crtb)
	if block == nil {
		return nil, nil, errors.New("Failed to decode PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	return c, crtb, err
}

func parseCrtPool(crtb []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for len(crtb) > 0 {
		crt, b, err := parseCrt(crtb)
		if err != nil {
			return nil, err
		}
		crtb = b
		if crt == nil {
			continue
		}
		pool.AddCert(crt)
	}

	return pool, nil
}
