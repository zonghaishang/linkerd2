package identity

import (
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/smallstep/cli/pkg/x509"
)

func parsePemCrt(crtb []byte) (*x509.Certificate, []byte, error) {
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

func parsePemCrts(crtb []byte) (crts []*x509.Certificate, err error) {
	for len(crtb) > 0 {
		var (
			crt *x509.Certificate
			b   []byte
		)
		crt, b, err = parsePemCrt(crtb)
		if err != nil {
			return
		}
		crtb = b
		if crt != nil {
			crts = append(crts, crt)
		}
	}
	return
}

// ReadPemCrts reads PEM-encoded certificates from the given path or file.
func ReadPemCrts(path string) ([]*x509.Certificate, error) {
	s, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var crtb []byte

	if s.IsDir() {
		dir, err := ioutil.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, f := range dir {
			p := filepath.Join(path, f.Name())
			b, err := ioutil.ReadFile(p)
			if err != nil {
				return nil, err
			}
			crtb = append(crtb, b...)
			crtb = append(crtb, '\n')
		}
	} else {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		crtb = b
	}

	return parsePemCrts(crtb)
}
