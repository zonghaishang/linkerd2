package identity

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/cloudflare/cfssl/log"
	"github.com/golang/protobuf/ptypes"
	"github.com/linkerd/linkerd2/pkg/tls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
)

type (
	// Service implements the gRPC service in terms of a Validator and Issuer.
	Service struct {
		v Validator
		i tls.Issuer
	}

	// Validator implementors accept a bearer token, validates it, and returns a
	// DNS-form identity.
	Validator interface {
		Validate([]byte) (string, error)
	}
)

// NewService creates a new identity service.
func NewService(v Validator, i tls.Issuer) Service {
	return Service{v, i}
}

// Register registers an identity service implementation in the provided gRPC
// server.
func (s *Service) Register(g *grpc.Server) {
	pb.RegisterIdentityServer(g, s)
}

// Certify validates identity and signs certificates.
func (s *Service) Certify(ctx context.Context, req *pb.CertifyRequest) (*pb.CertifyResponse, error) {
	// Extract the relevant info form the request.
	reqIdentity, tok, csr, err := checkRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err = checkCSR(csr, reqIdentity); err != nil {
		log.Debug()
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	// Authenticate the provided token against the Kubernetes API.
	log.Debugf("Validating token for %s", reqIdentity)
	tokIdentity, err := s.v.Validate(tok)
	if err != nil {
		msg := fmt.Sprintf("Failed to validate token: %s", err)
		log.Error(msg)
		return nil, status.Error(codes.Internal, msg)
	}

	// Ensure the requested identity matches the token's identity.
	if reqIdentity != tokIdentity {
		msg := fmt.Sprintf("Requested identity did not match provided token: requested=%s; found=%s",
			reqIdentity, tokIdentity)
		log.Debug(msg)
		return nil, status.Error(codes.FailedPrecondition, msg)
	}

	// Create a certificate
	crt, err := s.i.IssueEndEntityCrt(csr)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	crts := crt.ExtractRaw()
	if len(crts) == 0 {
		panic("We seem to have lost the certificate while signing it?")
	}

	// Bundle issuer crt with certificate so the trust path to the root can be verified.
	log.Infof("certifying %s until %s", tokIdentity, crt.Certificate.NotAfter)
	validUntil, err := ptypes.TimestampProto(crt.Certificate.NotAfter)
	if err != nil {
		log.Errorf("Invalid expiry time: %s", err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	rsp := &pb.CertifyResponse{
		LeafCertificate:          crts[0],
		IntermediateCertificates: crts[1:],

		ValidUntil: validUntil,
	}
	return rsp, nil
}

func checkRequest(req *pb.CertifyRequest) (string, []byte, *x509.CertificateRequest, error) {
	reqIdentity := req.GetIdentity()
	if reqIdentity == "" {
		return "", nil, nil, errors.New("missing identity")
	}

	tok := req.GetToken()
	if len(tok) == 0 {
		return "", nil, nil, errors.New("missing token")
	}

	der := req.GetCertificateSigningRequest()
	if len(der) == 0 {
		return "", nil, nil,
			errors.New("missing certificate signing request")
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", nil, nil, err
	}

	return reqIdentity, tok, csr, nil
}

func checkCSR(csr *x509.CertificateRequest, identity string) error {
	if len(csr.DNSNames) != 1 {
		return errors.New("CSR must have exactly one DNSName")
	}
	if csr.DNSNames[0] != identity {
		return fmt.Errorf("CSR name does not match requested identity: csr=%s; req=%s", csr.DNSNames[0], identity)
	}

	if csr.Subject.CommonName != "" {
		return errors.New("CommonName must be empty")
	}
	if len(csr.EmailAddresses) > 0 {
		return errors.New("Cannot validate email addresses")
	}
	if len(csr.IPAddresses) > 0 {
		return errors.New("Cannot validate IP addresses")
	}
	if len(csr.URIs) > 0 {
		return errors.New("Cannot validate URIs")
	}

	return nil
}
