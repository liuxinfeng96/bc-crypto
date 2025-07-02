package asym

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	bcx509 "github.com/liuxinfeng96/bc-crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
	smx509 "github.com/tjfoc/gmsm/x509"
)

func GenerateKey(algorithm AlgorithmCurve) (crypto.PrivateKey, error) {

	switch algorithm {
	case EC_Secp256k1:
		return ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	case EC_NISTP224:
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case EC_NISTP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC_NISTP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case EC_NISTP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case EC_SM2:
		return sm2.GenerateKey(rand.Reader)
	case RSA512:
		return rsa.GenerateKey(rand.Reader, 512)
	case RSA1024:
		return rsa.GenerateKey(rand.Reader, 1024)
	case RSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case RSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	default:
		return nil, errors.New("the public key algorithm curve is unknown")
	}
}

func ParsePrivateKeyFromDER(der []byte) (crypto.PrivateKey, error) {

	if key, err := bcx509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := bcx509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := smx509.ParsePKCS8UnecryptedPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("fail to parse the private key, the key type is unknown")
}

func ParsePublicKeyFromDER(der []byte) (crypto.PublicKey, error) {

	if key, err := bcx509.ParsePKIXPublicKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("fail to parse the public key, the key type is unknown")
}

func ParsePrivateKey(p []byte) (crypto.PrivateKey, error) {

	var (
		privateKey crypto.PrivateKey
		err        error
	)

	block, rest := pem.Decode(p)
	if block == nil {
		privateKey, err = ParsePrivateKeyFromDER(rest)
	} else {
		privateKey, err = ParsePrivateKeyFromDER(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParsePublicKey(p []byte) (crypto.PublicKey, error) {
	var (
		publicKey crypto.PublicKey
		err       error
	)

	block, rest := pem.Decode(p)
	if block == nil {
		publicKey, err = ParsePublicKeyFromDER(rest)
	} else {
		publicKey, err = ParsePublicKeyFromDER(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func MarshalPrivateKey(key crypto.PrivateKey) ([]byte, error) {
	der, err := bcx509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}

	skBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	skBuf := new(bytes.Buffer)
	if err = pem.Encode(skBuf, skBlock); err != nil {
		return nil, err
	}

	return skBuf.Bytes(), nil
}

func MarshalPublicKey(pub crypto.PublicKey) ([]byte, error) {
	der, err := bcx509.MarshalPKIXPublicKey(pub)
	pkBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	pkBuf := new(bytes.Buffer)
	if err = pem.Encode(pkBuf, pkBlock); err != nil {
		return nil, err
	}

	return pkBuf.Bytes(), nil
}
