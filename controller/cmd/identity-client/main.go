package main

import (
	"crypto/rand"
	"crypto/x509"
	"flag"
	"os"
	"os/signal"
	"syscall"


	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"github.com/linkerd/linkerd2/controller/identity"
	"github.com/linkerd/linkerd2/controller/k8s"
	"github.com/linkerd/linkerd2/pkg/flags"
	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
)

func main() {
	tokenPath := flag.String("token", "", "path to serviceaccount token")
	name := flag.String("name", "", "identity name")
	dir := flag.String("dir", "", "directory under which credentials are written")
	// TODO flag.String("audience", "linkerd.io/identity", "Token audience")
	flags.ConfigureAndParse()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	key, err := tls.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a key: %s", err)
	}

	csr := x509.CertificateRequest{DNSNames: []string{*name}}
	csrb, err := x509.CreateCertificateRequest(rand.Reader, &csr, key)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}

	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err.Error())
	}
	client := pb.NewIdentityClient(conn)


	svc := identity.NewService(k8s.Authentication(), dom, ca)

	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"

	for {
		select {
		case <-stop:
			log.Info("Shutting down...")
		}
	}
}
