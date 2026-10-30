package secrets

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"slices"
	"time"
)

// A per-install certificate authority and the server certificates it issues,
// for TLS listeners that clients must be able to pin (the oVirt-compatible
// backup API: Veeam downloads the CA from the engine's pki-resource URL, as it
// would from a real oVirt engine). Keys are generated locally, stored 0600 and
// never leave the host; nothing is fetched or published.

// CA is a loaded certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
	PEM  []byte // the CA certificate, PEM encoded (safe to publish)
}

const rsaBits = 3072

// LoadOrCreateCA loads the CA at certPath/keyPath, creating a fresh one (10
// years) on first use.
func LoadOrCreateCA(certPath, keyPath, commonName string) (*CA, error) {
	if ca, err := loadCA(certPath, keyPath); err == nil {
		return ca, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"VXVisor"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		SubjectKeyId:          skid(&key.PublicKey),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	if err := writePair(certPath, keyPath, der, key); err != nil {
		return nil, err
	}
	return loadCA(certPath, keyPath)
}

func loadCA(certPath, keyPath string) (*CA, error) {
	cb, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, fmt.Errorf("CA %s: %w", certPath, err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	signer, ok := pair.PrivateKey.(crypto.Signer)
	if !ok || !cert.IsCA {
		return nil, fmt.Errorf("CA %s is not a usable CA", certPath)
	}
	return &CA{Cert: cert, Key: signer, PEM: cb}, nil
}

// LoadOrIssue returns the server certificate at certPath/keyPath, issuing a
// new one when it is missing, was issued by another CA, doesn't cover every
// name in hosts (IPs or DNS names), or expires within 30 days.
func (ca *CA) LoadOrIssue(certPath, keyPath string, hosts []string) (tls.Certificate, error) {
	if pair, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil &&
			leaf.CheckSignatureFrom(ca.Cert) == nil && covers(leaf, hosts) &&
			time.Until(leaf.NotAfter) > 30*24*time.Hour {
			pair.Certificate = append(pair.Certificate, ca.Cert.Raw)
			return pair, nil
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	cn := "vxvisor"
	if len(hosts) > 0 {
		cn = hosts[0]
	}
	tmpl := &x509.Certificate{
		SerialNumber:   serial(),
		Subject:        pkix.Name{CommonName: cn, Organization: []string{"VXVisor"}},
		NotBefore:      now.Add(-time.Hour),
		NotAfter:       now.AddDate(0, 0, 825),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   skid(&key.PublicKey),
		AuthorityKeyId: ca.Cert.SubjectKeyId,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writePair(certPath, keyPath, der, key); err != nil {
		return tls.Certificate{}, err
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	pair.Certificate = append(pair.Certificate, ca.Cert.Raw)
	return pair, nil
}

func covers(leaf *x509.Certificate, hosts []string) bool {
	for _, h := range hosts {
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			if !slices.ContainsFunc(leaf.IPAddresses, ip.Equal) {
				return false
			}
		} else if !slices.Contains(leaf.DNSNames, h) {
			return false
		}
	}
	return true
}

func writePair(certPath, keyPath string, der []byte, key *rsa.PrivateKey) error {
	kb := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(keyPath, kb, 0o600); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

func skid(pub *rsa.PublicKey) []byte {
	h := sha256.Sum256(x509.MarshalPKCS1PublicKey(pub))
	return h[:20]
}
