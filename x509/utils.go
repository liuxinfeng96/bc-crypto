package x509

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
	local "github.com/liuxinfeng96/bc-crypto"
	bcecdsa "github.com/liuxinfeng96/bc-crypto/ecdsa"
	"github.com/tjfoc/gmsm/sm2"
	smx509 "github.com/tjfoc/gmsm/x509"
)

func ParsePrivateKeyFromDER(der []byte) (crypto.PrivateKey, error) {

	if key, err := ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}

	if key, err := smx509.ParsePKCS8UnecryptedPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("fail to parse the private key, the key type is unknown")
}

func ParsePublicKeyFromDER(der []byte) (crypto.PublicKey, error) {

	if key, err := ParsePKIXPublicKey(der); err == nil {
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

type AlgorithmCurve uint32

const (
	EC_Secp256k1 AlgorithmCurve = iota + 1
	EC_NISTP224
	EC_NISTP256
	EC_NISTP384
	EC_NISTP521
	EC_SM2

	RSA512
	RSA1024
	RSA2048
	RSA3072
)

var AlgorithmCurveMap = map[string]AlgorithmCurve{
	"EC_Secp256k1": EC_Secp256k1,
	"EC_NISTP224":  EC_NISTP224,
	"EC_NISTP256":  EC_NISTP256,
	"EC_NISTP384":  EC_NISTP384,
	"EC_NISTP521":  EC_NISTP521,
	"EC_SM2":       EC_SM2,
	"RSA512":       RSA512,
	"RSA1024":      RSA1024,
	"RSA2048":      RSA2048,
	"RSA3072":      RSA3072,
}

func (a AlgorithmCurve) String() string {
	switch a {
	case EC_Secp256k1:
		return "EC_Secp256k1"
	case EC_NISTP224:
		return "EC_NISTP224"
	case EC_NISTP256:
		return "EC_NISTP256"
	case EC_NISTP384:
		return "EC_NISTP384"
	case EC_NISTP521:
		return "EC_NISTP521"
	case EC_SM2:
		return "EC_SM2"
	case RSA512:
		return "RSA512"
	case RSA1024:
		return "RSA1024"
	case RSA2048:
		return "RSA2048"
	case RSA3072:
		return "RSA3072"
	default:
		return "unknown"
	}
}

func GenerateKey(algorithm AlgorithmCurve) (crypto.PrivateKey, error) {

	switch algorithm {
	case EC_Secp256k1:
		return bcecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	case EC_NISTP224:
		return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case EC_NISTP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case EC_NISTP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case EC_NISTP521:
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case EC_SM2:
		return bcecdsa.GenerateKey(sm2.P256Sm2(), rand.Reader)
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

func MarshalPrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	switch key := key.(type) {
	case *bcecdsa.PrivateKey:

		skDer, err := MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}

		skBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: skDer,
		}

		skBuf := new(bytes.Buffer)
		if err = pem.Encode(skBuf, skBlock); err != nil {
			return nil, err
		}

		return skBuf.Bytes(), nil

	case *rsa.PrivateKey:

		skDer, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}

		skBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: skDer,
		}

		skBuf := new(bytes.Buffer)
		if err = pem.Encode(skBuf, skBlock); err != nil {
			return nil, err
		}

		return skBuf.Bytes(), nil

	case *ecdsa.PrivateKey:

		skDer, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}

		skBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: skDer,
		}

		skBuf := new(bytes.Buffer)
		if err = pem.Encode(skBuf, skBlock); err != nil {
			return nil, err
		}

		return skBuf.Bytes(), nil

	default:
		return nil, errors.New("unknown private key type")
	}
}

func MarshalPublicKeyToPEM(pub crypto.PublicKey) ([]byte, error) {
	switch pub := pub.(type) {
	case *bcecdsa.PublicKey:

		pkDer, err := MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}

		pkBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkDer,
		}

		pkBuf := new(bytes.Buffer)
		if err = pem.Encode(pkBuf, pkBlock); err != nil {
			return nil, err
		}

		return pkBuf.Bytes(), nil

	case *rsa.PublicKey:

		pkDer := x509.MarshalPKCS1PublicKey(pub)

		pkBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkDer,
		}

		pkBuf := new(bytes.Buffer)
		if err := pem.Encode(pkBuf, pkBlock); err != nil {
			return nil, err
		}

		return pkBuf.Bytes(), nil

	case *ecdsa.PublicKey:

		pkDer, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, err
		}

		pkBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkDer,
		}

		pkBuf := new(bytes.Buffer)
		if err = pem.Encode(pkBuf, pkBlock); err != nil {
			return nil, err
		}

		return pkBuf.Bytes(), nil

	default:
		return nil, errors.New("unknown public key type")
	}
}

func ParseCertificateFromPEM(certBytes []byte) (*Certificate, error) {
	var (
		cert *Certificate
		err  error
	)

	block, rest := pem.Decode(certBytes)
	if block == nil {
		cert, err = ParseCertificate(rest)
	} else {
		cert, err = ParseCertificate(block.Bytes)
	}

	if err != nil {
		return nil, err
	}

	return cert, nil
}

func ComputeSKI(pub interface{}) ([]byte, error) {

	var publicKeyBytes []byte
	var err error

	if publicKeyBytes, _, err = marshalPublicKey(pub); err != nil {
		return nil, err
	}

	hashFunc, _, err := signingParamsForPublicKey(pub, UnknownSignatureAlgorithm)
	if err != nil {
		return nil, err
	}

	hash := hashFunc.New()

	hash.Write(publicKeyBytes)

	pubHash := hash.Sum(nil)

	return pubHash[:], nil
}

func GetSignatureAlgorithm(key crypto.PrivateKey) (SignatureAlgorithm, error) {
	skey, ok := key.(crypto.Signer)
	if !ok {
		return 0, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	var signatureAlgorithm SignatureAlgorithm
	switch skey.Public().(type) {
	case *ecdsa.PublicKey:
		signatureAlgorithm = ECDSAWithSHA256
	case *bcecdsa.PublicKey:
		pk := skey.Public().(*bcecdsa.PublicKey)
		switch pk.Curve {
		case sm2.P256Sm2():
			signatureAlgorithm = SM2WithSM3
		default:
			signatureAlgorithm = ECDSAWithSHA256
		}
	case *rsa.PublicKey:
		signatureAlgorithm = SHA256WithRSA
	default:
		return 0, errors.New("x509: certificate private key type is unknowm")
	}

	return signatureAlgorithm, nil
}

func ParseCertificateRequestFromPEM(csrBytes []byte) (*CertificateRequest, error) {
	var (
		csr *CertificateRequest
		err error
	)
	block, rest := pem.Decode(csrBytes)
	if block == nil {
		csr, err = ParseCertificateRequest(rest)
	} else {
		csr, err = ParseCertificateRequest(block.Bytes)
	}
	if err != nil {
		return nil, err
	}
	return csr, nil
}

func GetKeyUsageAndExtKeyUsage(isCa bool) (KeyUsage, []ExtKeyUsage) {
	var (
		keyUsage    KeyUsage
		extKeyUsage []ExtKeyUsage
	)
	if isCa {
		keyUsage = KeyUsageCRLSign | KeyUsageCertSign
	} else {
		keyUsage = KeyUsageKeyEncipherment | KeyUsageDataEncipherment | KeyUsageKeyAgreement |
			KeyUsageDigitalSignature | KeyUsageContentCommitment
		extKeyUsage = []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth}
	}
	return keyUsage, extKeyUsage
}

func GetHashTypeBySignatureAlgo(signatureAlgo SignatureAlgorithm) (local.Hash, error) {

	for i := 0; i < len(signatureAlgorithmDetails); i++ {
		if signatureAlgo == signatureAlgorithmDetails[i].algo {
			return signatureAlgorithmDetails[i].hash, nil
		}
	}

	return local.Hash(0), errors.New("unknown signature algorithm")
}

func GetHashTypeBySignatureAlgoString(signatureAlgoStr string) (local.Hash, error) {

	for i := 0; i < len(signatureAlgorithmDetails); i++ {
		if signatureAlgoStr == signatureAlgorithmDetails[i].name {
			return signatureAlgorithmDetails[i].hash, nil
		}
	}

	return local.Hash(0), errors.New("unknown signature algorithm")
}
