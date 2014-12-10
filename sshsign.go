package sshsign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type Signer interface {
	Sign(data []byte) ([]byte, error)
}

type Verifier interface {
	Verify(data []byte, sig []byte) error
}

type PrivateKey struct {
	*rsa.PrivateKey
}

// Sign calculates the signature over data using the sha256 hash algorithm
func (k *PrivateKey) Sign(data []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	return rsa.SignPKCS1v15(rand.Reader, k.PrivateKey, crypto.SHA256, h.Sum(nil))
}

type PublicKey struct {
	*rsa.PublicKey
}

// Verify verifies the signature over data using the sha256 hash algorithm
func (k *PublicKey) Verify(data []byte, sig []byte) error {
	h := sha256.New()
	h.Write(data)
	return rsa.VerifyPKCS1v15(k.PublicKey, crypto.SHA256, h.Sum(nil), sig)
}

func NewSigner(r, p io.Reader) (Signer, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no key found")
	}
	content := block.Bytes

	if p != nil {
		passphrase, err := ioutil.ReadAll(p)
		if err != nil {
			return nil, err
		}
		content, err = x509.DecryptPEMBlock(block, passphrase)
		if err != nil {
			return nil, err
		}
	}

	var k interface{}
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err = x509.ParsePKCS1PrivateKey(content)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(fmt.Sprintf("unsupported key type %q", block.Type))
	}

	var pk *PrivateKey
	switch t := k.(type) {
	case *rsa.PrivateKey:
		pk = &PrivateKey{t}
	default:
		return nil, errors.New(fmt.Sprintf("unsupported key type %T", pk))
	}

	return pk, nil
}

func NewVerifier(r io.Reader) (Verifier, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no key found")
	}

	var k interface{}
	switch block.Type {
	case "PUBLIC KEY":
		k, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New(fmt.Sprintf("unsupported key type %q - use \"ssh-keygen -e -m PKCS8\" to convert the key", block.Type))
	}

	var pk *PublicKey
	switch t := k.(type) {
	case *rsa.PublicKey:
		pk = &PublicKey{t}
	default:
		return nil, errors.New(fmt.Sprintf("unsupported key type %T", pk))
	}

	return pk, nil
}
