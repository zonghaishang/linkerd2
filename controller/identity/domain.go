package identity

import (
	"errors"
	"fmt"
	"strings"
)

// TrustDomain is a namespace for identities.
type TrustDomain struct {
	controlNamespace, domain string
}

// NewTrustDomain creates a new identity namespace.
func NewTrustDomain(controlNamespace, domain string) (*TrustDomain, error) {
	if !isLabel(controlNamespace) {
		return nil, fmt.Errorf("Control namespace must be a label: '%s'", controlNamespace)
	}
	if domain == "" {
		return nil, errors.New("Domain must not be empty")
	}

	return &TrustDomain{controlNamespace, domain}, nil
}

// ServiceAccountIdentity formats the identity for a K8s ServiceAccount.
func (d *TrustDomain) ServiceAccountIdentity(sa, ns string) (string, error) {
	if !isLabel(sa) {
		return "", fmt.Errorf("Service account must be a label: '%s'", sa)
	}
	if !isLabel(ns) {
		return "", fmt.Errorf("Namespace account must be a label: '%s'", ns)
	}

	id := fmt.Sprintf("%s.%s.serviceaccount.identity.%s.%s", sa, ns, d.controlNamespace, d.domain)
	return id, nil
}

func isLabel(p string) bool {
	return p != "" && !strings.Contains(p, ".")
}
