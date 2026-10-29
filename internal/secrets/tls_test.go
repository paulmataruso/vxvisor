package secrets

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCAAndServerCert(t *testing.T) {
	dir := t.TempDir()
	cp, kp := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	ca, err := LoadOrCreateCA(cp, kp, "test CA")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(kp); st.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v, want 0600", st.Mode().Perm())
	}
	ca2, err := LoadOrCreateCA(cp, kp, "test CA")
	if err != nil || !ca2.Cert.Equal(ca.Cert) {
		t.Fatal("CA was not reloaded from disk")
	}
	sc, sk := filepath.Join(dir, "srv.crt"), filepath.Join(dir, "srv.key")
	pair, err := ca.LoadOrIssue(sc, sk, []string{"192.0.2.10", "engine.example"})
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(pair.Certificate[0])
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	for _, h := range []string{"192.0.2.10", "engine.example"} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: h}); err != nil {
			t.Fatalf("server cert does not verify for %s: %v", h, err)
		}
	}
	// Same names: reused. A new name: reissued.
	again, _ := ca.LoadOrIssue(sc, sk, []string{"192.0.2.10"})
	if string(again.Certificate[0]) != string(pair.Certificate[0]) {
		t.Fatal("cert reissued although it already covers the names")
	}
	re, _ := ca.LoadOrIssue(sc, sk, []string{"192.0.2.11"})
	if string(re.Certificate[0]) == string(pair.Certificate[0]) {
		t.Fatal("cert not reissued for a new address")
	}
}
