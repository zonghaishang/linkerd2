package destination

import (
	"errors"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	pbHttp "github.com/linkerd/linkerd2-proxy-api/go/http_types"
	sp "github.com/linkerd/linkerd2/pkg/apis/serviceprofile/v1alpha1"
)

type profileUpdateListener interface {
	Update(profile *sp.ServiceProfile)
	ClientClose() <-chan struct{}
	ServerClose() <-chan struct{}
	Stop()
}

// implements the profileUpdateListener interface
type profileListener struct {
	stream pb.Destination_GetProfileServer
	stopCh chan struct{}
}

func newProfileListener(stream pb.Destination_GetProfileServer) *profileListener {
	return &profileListener{
		stream: stream,
		stopCh: make(chan struct{}),
	}
}

func (l *profileListener) ClientClose() <-chan struct{} {
	return l.stream.Context().Done()
}

func (l *profileListener) ServerClose() <-chan struct{} {
	return l.stopCh
}

func (l *profileListener) Stop() {
	close(l.stopCh)
}

func (l *profileListener) Update(profile *sp.ServiceProfile) {
	routes := make([]*pb.Route, 0)
	if profile != nil {
		for _, route := range profile.Spec.Routes {
			pbRoute, err := toRoute(route)
			if err != nil {
				log.Error(err)
				return
			}
			routes = append(routes, pbRoute)
		}
	}
	l.stream.Send(&pb.DestinationProfile{Routes: routes})
}

func toRoute(route *sp.RouteSpec) (*pb.Route, error) {
	cond, err := toRequestMatch(route.Condition)
	if err != nil {
		return nil, err
	}
	rcs := make([]*pb.ResponseClass, 0)
	for _, rc := range route.Responses {
		pbRc, err := toResponseClass(rc)
		if err != nil {
			return nil, err
		}
		rcs = append(rcs, pbRc)
	}
	return &pb.Route{
		Condition:       cond,
		ResponseClasses: rcs,
	}, nil
}

func toResponseClass(rc *sp.ResponseClass) (*pb.ResponseClass, error) {
	cond, err := toResponseMatch(rc.Condition)
	if err != nil {
		return nil, err
	}
	return &pb.ResponseClass{
		Condition: cond,
		IsFailure: !rc.IsSuccess,
	}, nil
}

func toResponseMatch(rspMatch *sp.ResponseMatch) (*pb.ResponseMatch, error) {
	err := validateResponseMatch(rspMatch)
	if err != nil {
		return nil, err
	}
	if rspMatch.All != nil {
		all := make([]*pb.ResponseMatch, 0)
		for _, m := range rspMatch.All {
			pbM, err := toResponseMatch(m)
			if err != nil {
				return nil, err
			}
			all = append(all, pbM)
		}
		return &pb.ResponseMatch{
			Match: &pb.ResponseMatch_All{
				All: &pb.ResponseMatch_Seq{
					Matches: all,
				},
			},
		}, nil
	}

	if rspMatch.Any != nil {
		any := make([]*pb.ResponseMatch, 0)
		for _, m := range rspMatch.Any {
			pbM, err := toResponseMatch(m)
			if err != nil {
				return nil, err
			}
			any = append(any, pbM)
		}
		return &pb.ResponseMatch{
			Match: &pb.ResponseMatch_Any{
				Any: &pb.ResponseMatch_Seq{
					Matches: any,
				},
			},
		}, nil
	}

	if rspMatch.Status != nil {
		return &pb.ResponseMatch{
			Match: &pb.ResponseMatch_Status{
				Status: &pb.HttpStatusRange{
					Max: rspMatch.Status.Max,
					Min: rspMatch.Status.Min,
				},
			},
		}, nil
	}

	if rspMatch.Not != nil {
		not, err := toResponseMatch(rspMatch.Not)
		if err != nil {
			return nil, err
		}
		return &pb.ResponseMatch{
			Match: &pb.ResponseMatch_Not{
				Not: not,
			},
		}, nil
	}

	return nil, errors.New("A response match must have a field set")
}

func toRequestMatch(reqMatch *sp.RequestMatch) (*pb.RequestMatch, error) {
	err := validateRequestMatch(reqMatch)
	if err != nil {
		return nil, err
	}
	if reqMatch.All != nil {
		all := make([]*pb.RequestMatch, 0)
		for _, m := range reqMatch.All {
			pbM, err := toRequestMatch(m)
			if err != nil {
				return nil, err
			}
			all = append(all, pbM)
		}
		return &pb.RequestMatch{
			Match: &pb.RequestMatch_All{
				All: &pb.RequestMatch_Seq{
					Matches: all,
				},
			},
		}, nil
	}

	if reqMatch.Any != nil {
		any := make([]*pb.RequestMatch, 0)
		for _, m := range reqMatch.Any {
			pbM, err := toRequestMatch(m)
			if err != nil {
				return nil, err
			}
			any = append(any, pbM)
		}
		return &pb.RequestMatch{
			Match: &pb.RequestMatch_Any{
				Any: &pb.RequestMatch_Seq{
					Matches: any,
				},
			},
		}, nil
	}

	if reqMatch.Method != "" {
		return &pb.RequestMatch{
			Match: &pb.RequestMatch_Method{
				Method: toHTTPMethod(reqMatch.Method),
			},
		}, nil
	}

	if reqMatch.Not != nil {
		not, err := toRequestMatch(reqMatch.Not)
		if err != nil {
			return nil, err
		}
		return &pb.RequestMatch{
			Match: &pb.RequestMatch_Not{
				Not: not,
			},
		}, nil
	}

	if reqMatch.Path != "" {
		return &pb.RequestMatch{
			Match: &pb.RequestMatch_Path{
				Path: &pb.PathMatch{
					Regex: reqMatch.Path,
				},
			},
		}, nil
	}

	return nil, errors.New("A request match must have a field set")
}

func validateRequestMatch(reqMatch *sp.RequestMatch) error {
	tooManyKindsErr := errors.New("A request match may not have more two fields set")
	matchKindSet := false
	if reqMatch.All != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if reqMatch.Any != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if reqMatch.Method != "" {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if reqMatch.Not != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if reqMatch.Path != "" {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}

	if !matchKindSet {
		return errors.New("A request match must have a field set")
	}

	return nil
}

func validateResponseMatch(rspMatch *sp.ResponseMatch) error {
	tooManyKindsErr := errors.New("A response match may not have more two fields set")
	invalidRangeErr := errors.New("Range maximum cannot be smaller than minimum")
	matchKindSet := false
	if rspMatch.All != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if rspMatch.Any != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}
	if rspMatch.Status != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		if rspMatch.Status.Max < rspMatch.Status.Min {
			return invalidRangeErr
		}
		matchKindSet = true
	}
	if rspMatch.Not != nil {
		if matchKindSet {
			return tooManyKindsErr
		}
		matchKindSet = true
	}

	if !matchKindSet {
		return errors.New("A response match must have a field set")
	}

	return nil
}

func toHTTPMethod(method string) *pbHttp.HttpMethod {
	method = strings.ToUpper(method)
	var registeredMethod pbHttp.HttpMethod_Registered = -1
	if method == http.MethodConnect {
		registeredMethod = pbHttp.HttpMethod_CONNECT
	}
	if method == http.MethodDelete {
		registeredMethod = pbHttp.HttpMethod_DELETE
	}
	if method == http.MethodGet {
		registeredMethod = pbHttp.HttpMethod_GET
	}
	if method == http.MethodHead {
		registeredMethod = pbHttp.HttpMethod_HEAD
	}
	if method == http.MethodOptions {
		registeredMethod = pbHttp.HttpMethod_OPTIONS
	}
	if method == http.MethodPatch {
		registeredMethod = pbHttp.HttpMethod_PATCH
	}
	if method == http.MethodPost {
		registeredMethod = pbHttp.HttpMethod_POST
	}
	if method == http.MethodPut {
		registeredMethod = pbHttp.HttpMethod_PUT
	}
	if registeredMethod == -1 {
		return &pbHttp.HttpMethod{
			Type: &pbHttp.HttpMethod_Unregistered{
				Unregistered: method,
			},
		}
	}
	return &pbHttp.HttpMethod{
		Type: &pbHttp.HttpMethod_Registered_{
			Registered: registeredMethod,
		},
	}
}
