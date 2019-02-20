package identity

import (
	"crypto/x509"
	"time"

	"github.com/linkerd/linkerd2/pkg/tls"
)

type Issuer struct {
	ca       *tls.CA
	lifetime time.Duration
}

// NewIssuer creates a new issuer using the provided CA
func NewIssuer(ca *tls.CA, lifetime time.Duration) (*Issuer, error) {
	return &Issuer{ca, lifetime}, nil
}

func (iss *Issuer) Verify(anchors []*x509.Certificate) ([][]*x509.Certificate, error) {
	as := x509.NewCertPool()
	for _, c := range anchors {
		as.AddCert(c)
	}

	is := x509.NewCertPool()
	for _, c := range iss.ca.Crt.TrustChain {
		is.AddCert(c)
	}

	vo := x509.VerifyOptions{Roots: as, Intermediates: is}
	return iss.ca.Crt.Certificate.Verify(vo)
}

func (iss *Issuer) Issue(csr *x509.CertificateRequest) (tls.Crt, error) {
	return iss.ca.SignEndEntity(csr)
}
