package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

type svc struct {
	authn    kauthn.AuthenticationV1Interface
	domain   *TrustDomain
	issuer   *x509util.Identity
	lifetime time.Duration
}

// Register registers an identity service implementation in the provided gRPC
// server.
func Register(
	s *grpc.Server,
	authn kauthn.AuthenticationV1Interface,
	domain *TrustDomain,
	issuer *x509util.Identity,
	lifetime time.Duration,
) {
	pb.RegisterIdentityServer(s, &svc{authn, domain, issuer, lifetime})
}

func (s *svc) Certify(ctx context.Context, req *pb.CertifyRequest) (*pb.CertifyResponse, error) {
	reqIdentity, tok, csr, err := checkRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err = checkCSR(csr, reqIdentity); err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}

	log.Debugf("requesting token review to certify %s", reqIdentity)
	tr := kauthnApi.TokenReview{Spec: kauthnApi.TokenReviewSpec{Token: string(tok)}}
	rvw, err := s.authn.TokenReviews().Create(&tr)
	if err != nil {
		return nil, status.Error(codes.Internal, "TokenReview failed")
	}
	if rvw.Status.Error != "" {
		msg := fmt.Sprintf("TokenReview failed: %s", rvw.Status.Error)
		return nil, status.Error(codes.InvalidArgument, msg)
	}
	if !rvw.Status.Authenticated {
		return nil, status.Error(codes.FailedPrecondition, "token could not be authenticated")
	}

	validName, err := s.getIdentity(rvw.Status.User.Username)
	if err != nil {
		msg := fmt.Sprintf("TokenReview returned unexpected user: %s: %s", rvw.Status.User.Username, err)
		return nil, status.Error(codes.Internal, msg)
	}

	if reqIdentity != validName {
		msg := fmt.Sprintf("Requested identity did not match provided token: requested=%s; found=%s",
			reqIdentity, validName)
		return nil, status.Error(codes.FailedPrecondition, msg)
	}

	profile, err := x509util.NewLeafProfileWithCSR(csr, s.issuer.Crt, s.issuer.Key,
		x509util.WithNotBeforeAfterDuration(time.Time{}, time.Time{}, s.lifetime))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	validUntil := time.Now().Add(s.lifetime)
	log.Infof("certifying %s until %s", validName, validUntil.String())
	crtb, err := profile.CreateCertificate()
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	// Bundle issuer crt with certificate so the trust path to the root can be verified.
	v, err := ptypes.TimestampProto(validUntil)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	rsp := &pb.CertifyResponse{
		LeafCertificate:          crtb,
		IntermediateCertificates: [][]byte{s.issuer.Crt.Raw},
		ValidUntil:               v,
	}
	return rsp, nil
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

func (s *svc) getIdentity(uname string) (string, error) {
	uns := strings.Split(uname, ":")
	if len(uns) != 4 ||
		uns[0] != "system" || uns[1] != "serviceaccount" ||
		!isLabel(uns[2]) || !isLabel(uns[3]) {
		return "", errors.New("must be in form system:serviceaccount:NS:SA")
	}
	return s.domain.ServiceAccountIdentity(uns[3], uns[2])
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
