package x509

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	bcecdsa "github.com/liuxinfeng96/bc-crypto/ecdsa"
	"github.com/tjfoc/gmsm/sm2"
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

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func ComputeSKI(pub interface{}) ([]byte, error) {
	encodedPub, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()

	hash.Write(subPKI.SubjectPublicKey.Bytes)

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
