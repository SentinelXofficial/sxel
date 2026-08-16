package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func genKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	return k
}

func pemEncode(t *testing.T, typ string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func signCert(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentKey)
	if err != nil {
		t.Fatalf("sign cert: %v", err)
	}
	return der
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "sxel-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der := signCert(t, tmpl, tmpl, key, &key.PublicKey)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	return cert, key
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, isClient bool) ([]byte, []byte) {
	t.Helper()
	key := genKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if isClient {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der := signCert(t, tmpl, ca, caKey, &key.PublicKey)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pemEncode(t, "CERTIFICATE", der), pemEncode(t, "EC PRIVATE KEY", keyDER)
}

func mtlsServer(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()
	srvCertPEM, srvKeyPEM := testLeaf(t, ca, caKey, "127.0.0.1", false)
	srvCert, err := tls.X509KeyPair(srvCertPEM, srvKeyPEM)
	if err != nil {
		t.Fatalf("server keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemEncode(t, "CERTIFICATE", ca.Raw)) {
		t.Fatal("append ca")
	}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "mtls-ok")
	}))
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	ts.StartTLS()
	return ts
}

func TestNewHTTPClientMTLS(t *testing.T) {
	ca, caKey := testCA(t)
	srv := mtlsServer(t, ca, caKey)
	defer srv.Close()

	certPEM, keyPEM := testLeaf(t, ca, caKey, "sxel-test-client", true)

	dir := t.TempDir()
	certPath := filepath.Join(dir, "client.pem")
	keyPath := filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &Config{Timeout: 5, ClientCert: certPath, ClientKey: keyPath}
	body, status, err := DoGET(NewHTTPClient(cfg), cfg, srv.URL)
	if err != nil {
		t.Fatalf("mTLS request failed: %v", err)
	}
	if status != http.StatusOK || body != "mtls-ok" {
		t.Errorf("got status=%d body=%q", status, body)
	}
}

func TestNewHTTPClientNoCertRejected(t *testing.T) {
	ca, caKey := testCA(t)
	srv := mtlsServer(t, ca, caKey)
	defer srv.Close()

	cfg := &Config{Timeout: 5}
	_, _, err := DoGET(NewHTTPClient(cfg), cfg, srv.URL)
	if err == nil {
		t.Fatal("expected error without client cert, got nil")
	}
}

func TestNewHTTPClientBadKeyPairSilentlyIgnored(t *testing.T) {
	cfg := &Config{Timeout: 5, ClientCert: "/nonexistent/cert.pem", ClientKey: "/nonexistent/key.pem"}
	tc := TLSClientConfigFor(cfg)
	if len(tc.Certificates) != 0 {
		t.Errorf("expected no certificates for invalid pair, got %d", len(tc.Certificates))
	}
}
