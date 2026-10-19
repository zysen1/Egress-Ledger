package ca

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

func TestGenerateLeafVerifies(t *testing.T) {
	dir := t.TempDir()
	a, err := Generate(dir)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := loaded.Leaf("uploads.example-vendor.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.Certificate) == 0 {
		t.Fatal("empty leaf")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.Cert)
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "uploads.example-vendor.test"}); err != nil {
		t.Fatal(err)
	}
	other := x509.NewCertPool()
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: other, DNSName: "uploads.example-vendor.test"}); err == nil {
		t.Fatal("leaf verified against an empty pool")
	}
	// The leaf is usable as a server certificate.
	_ = tls.Certificate(leaf)
}
