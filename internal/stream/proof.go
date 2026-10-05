// The agent's identity: the certificate ISOGrid issued for the cluster and
// its key. At connection the API sends a nonce, and the agent proves it holds
// the key by signing that nonce (ECDSA P-256 over SHA-256, DER, base64), the
// exact form the API verifies.
package stream

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// LoadKey reads an ECDSA private key in PEM form, PKCS#8 (what ISOGrid issues)
// or SEC 1.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseKey(raw)
}

// ParseKey parses what LoadKey reads.
func ParseKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	switch block.Type {
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected an ECDSA key, got %T", parsed)
		}
		return key, nil
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
}

// LoadCertificate reads the PEM certificate and returns both its text, which
// travels in the hello, and the parsed certificate.
func LoadCertificate(path string) (string, *x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil, err
	}
	cert, err := ParseCertificate(raw)
	if err != nil {
		return "", nil, err
	}
	return string(raw), cert, nil
}

// ParseCertificate parses what LoadCertificate reads.
func ParseCertificate(raw []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// Sign produces the proof for a challenge nonce.
func Sign(key *ecdsa.PrivateKey, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// Verify is the counterpart of Sign, for tests and tooling.
func Verify(pub *ecdsa.PublicKey, message []byte, signatureB64 string) bool {
	der, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.VerifyASN1(pub, digest[:], der)
}
