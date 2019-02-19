package identity

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	steputil "github.com/smallstep/cli/crypto/pemutil"
	"github.com/smallstep/cli/crypto/x509util"

	"github.com/smallstep/cli/pkg/x509"
)

type Issuer struct {
	crt        *x509.Certificate
	key        interface{}
	trustChain []*x509.Certificate
	lifetime   time.Duration
}

// Load Issuer credentials from the given directory
func IssuerFromDir(dir string, lifetime time.Duration) (*Issuer, error) {
	s, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !s.IsDir() {
		return nil, fmt.Errorf("Not a directory: %s", dir)
	}

	trustPath := filepath.Join(dir, "trust-chain.pem")
	crtPath := filepath.Join(dir, "crt")
	keyPath := filepath.Join(dir, "key")

	var trustChain []*x509.Certificate
	// Optionally read the trust-chain if it exists.
	if _, err := os.Stat(trustPath); err == nil {
		trustChain, err = ReadPemCrts(trustPath)
		if err != nil {
			return nil, err
		}
	}

	// Reads PEM or DER
	crt, err := steputil.ReadStepCertificate(crtPath)
	if err != nil {
		return nil, err
	}

	keyb, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	// Parses various formats of private key...
	key, err := steputil.ParseKey(keyb)
	if err != nil {
		return nil, err
	}

	return &Issuer{crt, key, trustChain, lifetime}, nil
}

func (i *Issuer) Verify(anchors []*x509.Certificate) ([][]*x509.Certificate, error) {
	as := x509.NewCertPool()
	for _, c := range anchors {
		as.AddCert(c)
	}

	is := x509.NewCertPool()
	for _, c := range i.trustChain {
		is.AddCert(c)
	}

	return i.crt.Verify(x509.VerifyOptions{Roots: as, Intermediates: is})
}

func (i *Issuer) Issue(csr *x509.CertificateRequest) (crtb []byte, validUntil time.Time, err error) {
	profile, err := x509util.NewLeafProfileWithCSR(csr, i.crt, i.key,
		x509util.WithNotBeforeAfterDuration(time.Time{}, time.Time{}, i.lifetime))
	if err != nil {
		return
	}

	validUntil = time.Now().Add(i.lifetime)
	crtb, err = profile.CreateCertificate()
	return
}

func (i *Issuer) ExportTrustChain() (chain []*x509.Certificate) {
	chain = append(chain, i.crt)
	for _, c := range i.trustChain {
		chain = append(chain, c)
	}

	return
}
