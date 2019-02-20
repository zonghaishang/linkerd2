package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"time"
)

// CA provides a certificate authority for TLS-enabled installs.
// Issuing certificates concurrently is not supported.
type CA struct {
	// validity is the duration for which issued certificates are valid. This
	// is approximately cert.NotAfter - cert.NotBefore with some additional
	// allowance for clock skew.
	//
	// Currently this is used for the CA's validity too, but nothing should
	// assume that the CA's validity period is the same as issued certificates'
	// validity.
	validity time.Duration

	// clockSkewAllocance is the maximum supported clock skew. Everything that
	// processes the certificates must have a system clock that is off by no
	// more than this allowance in either direction.
	clockSkewAllocance time.Duration

	// PrivateKey of the CA.
	PrivateKey *ecdsa.PrivateKey

	// Crt is the certificate and trust chain.
	Crt Crt

	// nextSerialNumber is the serial number of the next certificate to issue.
	// Serial numbers must not be reused.
	//
	// It is assumed there is only one instance of CA and it is assumed that a
	// given CA object isn't requested to issue certificates concurrently.
	//
	// For now we do not attempt to meet CABForum requirements (e.g. regarding
	// randomness).
	nextSerialNumber uint64
}

// Crt is a certificate and trust chain.
type Crt struct {
	Certificate *x509.Certificate
	TrustChain  []*x509.Certificate
}

type EndEntity struct {
	PrivateKey *ecdsa.PrivateKey
	Crt
}

func newCA() *CA {
	return &CA{
		// Initially all certificates will be valid for one year. TODO: Shorten the
		// validity duration of CA and end-entity certificates downward.
		validity: (24 * 365) * time.Hour,

		// Allow an hour of clock skew. TODO: decrease the default value of this
		// and make it tunable. TODO: Reconsider how this interacts with the
		// similar logic in the webpki verifier; since both are trying to account
		// for clock skew, there is somewhat of an over-correction.
		clockSkewAllocance: 1 * time.Hour,

		nextSerialNumber: 1,
	}
}

// WithClockSkewAllowance sets the maximum allowable time for a node's clock to skew.
func (ca *CA) WithClockSkewAllowance(v time.Duration) *CA {
	ca.validity = v
	return ca
}

// WithValidity sets the lifetime for ceritificates issued by this CA.
func (ca *CA) WithValidity(v time.Duration) *CA {
	ca.validity = v
	return ca
}

func ReadCA(keyPath, crtPath string) (ca *CA, err error) {
	ca = newCA()

	ca.PrivateKey, err = ReadKeyPEM(keyPath)
	if err != nil {
		return
	}

	ca.Crt, err = ReadCrtPEM(crtPath)
	return
}

// GenerateRootCA is the only way to create a CA.
func GenerateRootCA(name string) (ca *CA, err error) {
	ca = newCA()

	ca.PrivateKey, err = generateKeyPair()
	if err != nil {
		return
	}

	t := ca.createTemplate(&ca.PrivateKey.PublicKey)
	t.Subject = pkix.Name{CommonName: name}
	t.IsCA = true
	t.MaxPathLen = -1
	t.BasicConstraintsValid = true
	t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	der, err := x509.CreateCertificate(rand.Reader, &t, &t, ca.PrivateKey.Public(), ca.PrivateKey)
	if err != nil {
		return
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}

	ca.Crt.Certificate = crt
	return
}

// GenerateIntermediary creates a new certificate that is valid for the
// given DNS name, generating a new keypair for it.
func (ca *CA) GenerateIntermediary(name string, maxPathLen int) (*CA, error) {
	privateKey, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	t := ca.createTemplate(&privateKey.PublicKey)
	t.Subject = pkix.Name{CommonName: name}
	t.IsCA = true
	t.MaxPathLen = maxPathLen
	t.BasicConstraintsValid = true
	t.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	crtb, err := x509.CreateCertificate(rand.Reader, &t, ca.Crt.Certificate, privateKey.Public(), ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(crtb)
	if err != nil {
		return nil, err
	}

	ica := newCA()
	ica.validity = ca.validity
	ica.clockSkewAllocance = ca.clockSkewAllocance
	ica.PrivateKey = privateKey
	ica.Crt.Certificate = crt
	ica.Crt.TrustChain = append(ca.Crt.TrustChain, ca.Crt.Certificate)
	return ica, nil
}

// GenerateEndEntity creates a new certificate that is valid for the
// given DNS name, generating a new keypair for it.
func (ca *CA) GenerateEndEntity(dnsName string) (*EndEntity, error) {
	pk, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	crt, err := ca.SignEndEntity(&x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: dnsName},
		DNSNames:  []string{dnsName},
		PublicKey: pk.PublicKey,
	})
	return &EndEntity{PrivateKey: pk, Crt: crt}, err
}

// SignEndEntity creates a new certificate that is valid for the
// given DNS name, generating a new keypair for it.
func (ca *CA) SignEndEntity(csr *x509.CertificateRequest) (Crt, error) {
	pubkey, ok := csr.PublicKey.(ecdsa.PublicKey)
	if !ok {
		return Crt{}, fmt.Errorf("CSR must contain an ECDSA public key: %+v", csr.PublicKey)
	}

	t := ca.createTemplate(&pubkey)
	t.Issuer = ca.Crt.Certificate.Subject
	t.Subject = csr.Subject
	t.Extensions = csr.Extensions
	t.ExtraExtensions = csr.ExtraExtensions
	t.DNSNames = csr.DNSNames
	t.EmailAddresses = csr.EmailAddresses
	t.IPAddresses = csr.IPAddresses
	t.URIs = csr.URIs

	crtb, err := x509.CreateCertificate(rand.Reader, &t, ca.Crt.Certificate, &pubkey, ca.PrivateKey)
	if err != nil {
		return Crt{}, fmt.Errorf("Failed to create certificate: %s", err)
	}

	crt, err := x509.ParseCertificate(crtb)
	if err != nil {
		return Crt{}, fmt.Errorf("Failed to parse certificate: %s", err)
	}

	chain := append(ca.Crt.TrustChain, ca.Crt.Certificate)
	return Crt{Certificate: crt, TrustChain: chain}, nil
}

// createTemplate returns a certificate t for a non-CA certificate with
// no subject name, no subjectAltNames. The t can then be modified into
// a (root) CA t or an end-entity t by the caller.
func (ca *CA) createTemplate(publicKey *ecdsa.PublicKey) x509.Certificate {
	// ECDSA is used instead of RSA because ECDSA key generation is
	// straightforward and fast whereas RSA key generation is extremely slow
	// and error-prone.
	//
	// CA certificates are signed with the same algorithm as end-entity
	// certificates because they are relatively short-lived, because using one
	// algorithm minimizes exposure to implementation flaws, and to speed up
	// signature verification time.
	//
	// SHA-256 is used because any larger digest would be truncated to 256 bits
	// anyway since a P-256 scalar is only 256 bits long.
	const SignatureAlgorithm = x509.ECDSAWithSHA256

	serialNumber := big.NewInt(int64(ca.nextSerialNumber))
	ca.nextSerialNumber++

	notBefore := time.Now()

	return x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: SignatureAlgorithm,
		NotBefore:          notBefore.Add(-ca.clockSkewAllocance),
		NotAfter:           notBefore.Add(ca.validity).Add(ca.clockSkewAllocance),
		PublicKey:          publicKey,
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}
}

func generateKeyPair() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (crt *Crt) EncodePEM() []byte {
	w := bytes.Buffer{}
	n := len(crt.TrustChain)

	// Serialize certificates from leaf to root.
	_ = pem.Encode(&w, &pem.Block{Type: "CERTIFICATE", Bytes: crt.Certificate.Raw})
	for i := n - 1; i >= 0; i-- {
		_ = pem.Encode(&w, &pem.Block{Type: "CERTIFICATE", Bytes: crt.TrustChain[i].Raw})
	}

	return w.Bytes()
}

func (crt *Crt) EncodeTrustChainDER() [][]byte {
	// Serialize certificates from leaf to root.
	chain := make([][]byte, len(crt.TrustChain))
	for i, c := range crt.TrustChain {
		chain[len(crt.TrustChain)-i-1] = c.Raw
	}
	return chain
}

func (ee *EndEntity) PemEncodePrivateKey() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ee.PrivateKey)
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// ReadCertificatePEm reads a PEM-encoded certificates from the given path.
func ReadCertificatePEM(path string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	crt, _, err := decodeCertificatePEM(b)
	return crt, err
}

// ReadCertificatePEM reads a PEM-encoded certificates from the given path.
func ReadTrustAnchorsPEM(path string) ([]*x509.Certificate, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return DecodeTrustAnchorsPEM(b)
}

// ReadCrtPEM reads PEM-encoded certificates from the named file
func ReadCrtPEM(path string) (Crt, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return Crt{}, err
	}
	return DecodeCrtPEM(b)
}

func ReadKeyPEM(path string) (*ecdsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeKeyPEM(b)
}

func DecodeKeyPEM(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("Not PEM-encoded")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("Expected 'EC PRIVATE KEY'; found: '%s'", block.Type)
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func decodeCertificatePEM(crtb []byte) (*x509.Certificate, []byte, error) {
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

// DecodeCrtPEM decodes PEM-encoded certificates from leaf to root.
func DecodeCrtPEM(buf []byte) (crt Crt, err error) {
	certs, err := decodeCertificatesPEM(buf)
	if err != nil {
		return
	}

	crt.Certificate = certs[0]
	certs = certs[1:]

	// The chain is read from Leaf to Root, but we store it from Root to Leaf.
	crt.TrustChain = make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		crt.TrustChain[len(certs)-i-1] = c
	}
	return
}

// DecodeTrustAnchorsPEM decodes PEM-encoded certificates.
func DecodeTrustAnchorsPEM(buf []byte) ([]*x509.Certificate, error) {
	return decodeCertificatesPEM(buf)
}

func decodeCertificatesPEM(buf []byte) (certs []*x509.Certificate, err error) {
	for len(buf) > 0 {
		var c *x509.Certificate
		c, buf, err = decodeCertificatePEM(buf)
		if err != nil {
			return
		}
		if c == nil {
			continue // not a CERTIFICATE, skip
		}
		certs = append(certs, c)
	}
	return
}
