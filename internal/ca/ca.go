// Package ca mints a local certificate authority and short-lived leaf
// certificates. The proxy presents a leaf for each destination host so a
// trusting client can be observed. Clients that pin certificates reject
// these leaves; that rejection is recorded as invisible traffic.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certName = "ca.crt"
	keyName  = "ca.key"
)

// Authority is a self-signed CA stored on disk as PEM files.
type Authority struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
	KeyPEM  []byte
	Dir     string
}

// Generate creates a new CA directory. The key is mode 0600.
func Generate(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Egress Ledger Local CA", Organization: []string{"Egress Ledger"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, certName), certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, keyName), keyPEM, 0o600); err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM, Dir: dir}, nil
}

// Load reads a CA written by Generate.
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certName))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyName))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("ca: no certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	kblock, _ := pem.Decode(keyPEM)
	if kblock == nil {
		return nil, errors.New("ca: no key PEM")
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, err
	}
	return &Authority{Cert: cert, Key: key, CertPEM: certPEM, KeyPEM: keyPEM, Dir: dir}, nil
}

// Leaf returns a TLS certificate for host, signed by the CA.
func (a *Authority) Leaf(host string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(0, 0, 7),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.Cert, &key.PublicKey, a.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	return n, nil
}
