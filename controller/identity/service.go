package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/golang/protobuf/ptypes"
	log "github.com/sirupsen/logrus"
	"github.com/smallstep/cli/crypto/x509util"
	"github.com/smallstep/cli/pkg/x509"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	kauthnApi "k8s.io/api/authentication/v1"
	kauthn "k8s.io/client-go/kubernetes/typed/authentication/v1"

	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
)

// Service certifies identities over gRPC.
type Service struct {
	authn  kauthn.AuthenticationV1Interface
	domain *TrustDomain
	issuer *Issuer
}

// NewService creates a new identity service.
func NewService(
	authn kauthn.AuthenticationV1Interface,
	domain *TrustDomain,
	issuer *Issuer,
) *Service {
	return &Service{authn, domain, issuer}
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
	log.Debugf("requesting token review to certify %s", reqIdentity)
	rvw, err := s.authenticateToken(tok)
	if err != nil {
		return nil, err // status set/logged within authenticateToken
	}

	// Determine the identity associated with the token's userinfo.
	tokIdentity, err := getIdentity(rvw.User.Username, s.domain)
	if err != nil {
		msg := fmt.Sprintf("TokenReview returned unexpected user: %s: %s", rvw.User.Username, err)
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
	leaf, validUntil, err := s.issuer.Issue(csr)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	log.Infof("certifying %s until %s", tokIdentity, validUntil.String())

	// Bundle issuer crt with certificate so the trust path to the root can be verified.
	v, err := ptypes.TimestampProto(validUntil)
	if err != nil {
		log.Error("Invalid expiry time: %s", err)
		return nil, status.Error(codes.Internal, err.Error())
	}
	var chain [][]byte
	for _, c := range s.issuer.ExportTrustChain() {
		chain = append(chain, c.Raw)
	}
	rsp := &pb.CertifyResponse{
		LeafCertificate:          leaf,
		IntermediateCertificates: chain,
		ValidUntil:               v,
	}
	return rsp, nil
}

func (s *Service) authenticateToken(tok []byte) (*kauthnApi.TokenReviewStatus, error) {
	// TODO: Set/check `audience`
	tr := kauthnApi.TokenReview{Spec: kauthnApi.TokenReviewSpec{Token: string(tok)}}
	rvw, err := s.authn.TokenReviews().Create(&tr)
	if err != nil {
		log.Error("TokenReview failed: %s", err)
		return nil, status.Error(codes.Internal, "TokenReview failed")
	}

	if rvw.Status.Error != "" {
		log.Warn("TokenReview failed: %s", rvw.Status.Error)
		msg := fmt.Sprintf("TokenReview failed: %s", rvw.Status.Error)
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	if !rvw.Status.Authenticated {
		log.Info("TokenReview authentication failed: %s", rvw.Status)
		return nil, status.Error(codes.FailedPrecondition, "token could not be authenticated")
	}

	return &rvw.Status, nil
}

func checkRequest(req *pb.CertifyRequest) (reqIdentity string, tok []byte, csr *x509.CertificateRequest, err error) {
	reqIdentity = req.GetIdentity()
	if reqIdentity == "" {
		err = errors.New("missing identity")
		return
	}

	tok = req.GetToken()
	if len(tok) == 0 {
		err = errors.New("missing token")
		return
	}

	csrb := req.GetCertificateSigningRequest()
	if len(csrb) == 0 {
		err = errors.New("missing certificate signing request")
		return
	}

	csr, err = x509util.LoadCSRFromBytes(csrb)
	return
}

func getIdentity(uname string, d *TrustDomain) (string, error) {
	uns := strings.Split(uname, ":")
	if len(uns) != 4 ||
		uns[0] != "system" || uns[1] != "serviceaccount" ||
		!isLabel(uns[2]) || !isLabel(uns[3]) {
		return "", errors.New("must be in form system:serviceaccount:NS:SA")
	}

	return d.ServiceAccountIdentity(uns[3], uns[2])
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
