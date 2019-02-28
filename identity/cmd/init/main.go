package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"github.com/linkerd/linkerd2/pkg/flags"
	"github.com/linkerd/linkerd2/pkg/tls"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

func main() {
	addr := flag.String("addr", "localhost:8083", "address of identity service")
	trustAnchorsPath := flag.String("trust-anchors", "", "path to PEM-encoded trust anchors")
	tokenPath := flag.String("token", "", "path to serviceaccount token")
	name := flag.String("name", "", "identity name")
	dir := flag.String("dir", "", "directory under which credentials are written")
	flags.ConfigureAndParse()

	if *tokenPath == "" {
		log.Fatalf("-token must be specified")
	}

	// Read the trust root cert pool from a PEM file.
	if *trustAnchorsPath == "" {
		log.Fatalf("-strust-anchors must be specified")
	}
	rootsb, err := ioutil.ReadFile(*trustAnchorsPath)
	if err != nil {
		log.Fatalf("Failed to read trust anchors: %s: %s", *trustAnchorsPath, err)
	}
	roots, err := tls.DecodePEMCertPool(string(rootsb))
	if err != nil {
		log.Fatalf("Failed to read trust anchors: %s: %s", *trustAnchorsPath, err)
	}

	if *dir == "" {
		log.Fatalf("-dir must be specified")
	}
	dirStat, err := os.Stat(*dir)
	if err != nil {
		log.Fatalf("Cannot access directory: %s", err)
	}
	if !dirStat.IsDir() {
		log.Fatalf("Not a directory: %s", *dir)
	}
	if dirStat.Mode().Perm() == 0700 {
		log.Fatalf("Must have permissions 0700: %s; got %s", *dir, dirStat.Mode().Perm())
	}
	keyPath := filepath.Join(*dir, "key")
	csrPath := filepath.Join(*dir, "csr")
	crtPath := filepath.Join(*dir, "crt.pem")

	// Generate a private key and store it read-only (i.e. mostly for debugging).
	key, err := tls.GenerateKey()
	if err != nil {
		log.Fatalf("Failed to generate a key: %s", err)
	}
	if err = ioutil.WriteFile(keyPath, tls.EncodePrivateKeyP8(key), 0400); err != nil {
		log.Errorf("Failed to write Key: %s", err)
	}

	if *name == "" {
		log.Fatalf("-name must be specified")
	}
	csr := x509.CertificateRequest{DNSNames: []string{*name}}
	csrb, err := x509.CreateCertificateRequest(rand.Reader, &csr, key)
	if err != nil {
		log.Fatalf("Failed to create CSR: %s", err)
	}
	if err = ioutil.WriteFile(csrPath, csrb, 0400); err != nil {
		log.Errorf("Failed to write CSR: %s", err)
	}

	conn, err := grpc.Dial(*addr, grpc.WithInsecure())
	if err != nil {
		log.Fatal(err.Error())
	}
	client := pb.NewIdentityClient(conn)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	certifyReq := pb.CertifyRequest{
		Identity:                  *name,
		CertificateSigningRequest: csrb,
	}

	for {
		token, err := ioutil.ReadFile(*tokenPath)
		if err != nil {
			log.Fatalf("Failed to read token: %s", err)
		}

		certifyReq.Token = token
		rsp, err := client.Certify(context.Background(), &certifyReq)

		var refreshIn time.Duration
		if err != nil {
			log.Errorf("Failed to obtain certificate: %s", err)
			refreshIn = 1 * time.Minute
		} else {
			crtb := rsp.GetLeafCertificate()
			if len(crtb) == 0 {
				log.Fatal("Missing certificate in response")
			}
			crt, err := x509.ParseCertificate(crtb)
			if err != nil {
				log.Fatalf("Failed to parse certificate: %s", err)
			}

			intermediates := x509.NewCertPool()
			for _, b := range rsp.GetIntermediateCertificates() {
				c, err := x509.ParseCertificate(b)
				if err != nil {
					log.Fatal(err.Error())
				}
				intermediates.AddCert(c)
			}

			_, err = crt.Verify(x509.VerifyOptions{
				Roots:         roots,
				Intermediates: intermediates,
			})
			if err != nil {
				log.Fatal(err.Error())
			}

			if time.Now().After(crt.NotAfter) || time.Now().Before(crt.NotBefore) {
				log.Fatal("Received expired certificate")
			}

			if err := ioutil.WriteFile(crtPath, crtb, 0600); err != nil {
				log.Errorf("Failed to write CRT: %s", err)
			}

			// Refresh in 80% of the time expiry time, with a max of 1 day
			expiresIn := time.Until(crt.NotAfter)
			refreshIn = (expiresIn / time.Second) * (800 * time.Millisecond)
			if refreshIn > 24*time.Hour {
				refreshIn = 24 * time.Hour
			}

			s := sha256.Sum256(crt.Raw)
			sum := strings.ToLower(hex.EncodeToString(s[:]))
			log.Infof("id=%s; fp=%s; expiry=%s; refresh=%s", *name, sum, expiresIn, refreshIn)
		}

		select {
		case <-time.NewTimer(refreshIn).C:
			continue
		case <-stop:
			log.Info("Shutting down...")
		}
	}
}
