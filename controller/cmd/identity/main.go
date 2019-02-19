package main

import (
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/admin"
	"github.com/linkerd/linkerd2/pkg/flags"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/pkg/x509"

	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", ":8083", "address to serve on")
	adminAddr := flag.String("admin-addr", ":9996", "address of HTTP admin server")
	kubeConfigPath := flag.String("kubeconfig", "", "path to kube config")
	controllerNS := flag.String("controller-namespace", "linkerd",
		"namespace in which Linkerd is installed")
	trustDomain := flag.String("trust-domain", "cluster.local", "trust domain for identities")
	trustAnchorsPath := flag.String("trust anchors",
		"/var/run/linkerd/identity/trust-anchors",
		"path to file or directory containing trust anchors")
	issuerCredsPath := flag.String("issuer-credentials",
		"/var/run/linkerd/identity/issuer-credentials",
		"path to directoring containing issuer credentials")
	issuanceLifetime := flag.Duration("issuance-lifetime", 24*time.Hour,
		"The amount of time for which a signed certificate is valid")
	flags.ConfigureAndParse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	dom, err := identity.NewTrustDomain(*controllerNS, *trustDomain)
	if err != nil {
		log.Fatalf("Invalid trust domain: %s", err.Error())
	}

	// TODO watch trustAnchorsPath for changes
	trustAnchors, err := x509util.ReadCertPool(*trustAnchorsPath)
	if err != nil {
		log.Fatalf("Failed to read trust anchors from %s: %s", *trustAnchorsPath, err)
	}

	// TODO watch issuerCredsPath for changes
	issuerCreds, err := loadSigningCreds(*issuerCredsPath)
	if err != nil {
		log.Fatalf("Failed to read issuer credentials from %s: %s", *issuerCredsPath, err)
	}

	if _, err := issuerCreds.Verify(trustAnchors); err != nil {
		log.Fatalf("Failed to verify issuer credentials with trust anchors: %s", err)
	}

	k8s, err := k8s.NewClientSet(*kubeConfigPath)
	if err != nil {
		log.Fatalf("Failed to load kubeconfig: %s: %s", *kubeConfigPath, err)
	}
	svc := identity.NewService(k8s.Authentication(), dom, issuerIdentity, *issuanceLifetime)

	go admin.StartServer(*adminAddr)
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %s", *addr, err)
	}

	srv := grpc.NewServer()
	svc.Register(srv)
	go func() {
		log.Infof("starting gRPC server on %s", *addr)
		srv.Serve(lis)
	}()
	<-stop
	log.Infof("shutting down gRPC server on %s", *addr)
	srv.GracefulStop()
}

func parsePemCrt(crtb []byte) (*x509.Certificate, []byte, error) {
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

func parsePemCrtPool(crtb []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	for len(crtb) > 0 {
		crt, b, err := parsePemCrt(crtb)
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

func readPemCrtPool(path string) (*x509.CertPool, error) {
	s, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var crtb []byte

	if s.IsDir() {
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, f := range dir {
			p := filepath.Join(path, f.Name())
			b, err := ioutil.ReadFile(p)
			if err != nil {
				return nil, err
			}
			crtb = append(crtb, b...)
			crtb = append(crtb, '\n')
		}
	} else {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		crtb = b
	}

	return parsePemCrtPool(crtb)
}
