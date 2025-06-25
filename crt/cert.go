package crt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"

	bcecdsa "github.com/liuxinfeng96/bc-crypto/ecdsa"
	bcx509 "github.com/liuxinfeng96/bc-crypto/x509"
	"github.com/tjfoc/gmsm/sm2"
)

type CsrReq struct {
	Country            string
	Locality           string
	Province           string
	OrganizationalUnit string
	Organization       string
	CommonName         string
	Sans               []string
	PrivateKeyBytes    []byte
}

type CertificateReq struct {
	IsCA        bool
	ValidTime   time.Duration
	CsrBytes    []byte
	CaCertBytes []byte
	CaKeyBytes  []byte
}

func CreateCSR(req *CsrReq) ([]byte, error) {

	sk, err := bcx509.ParsePrivateKey(req.PrivateKeyBytes)
	if err != nil {
		return nil, err
	}

	signatureAlgorithm, err := getSignatureAlgorithm(sk)
	if err != nil {
		return nil, err
	}

	dnsName, ips := dealSANS(req.Sans)

	templateX509 := &bcx509.CertificateRequest{
		SignatureAlgorithm: signatureAlgorithm,
		Subject: pkix.Name{
			Country:            []string{req.Country},
			Locality:           []string{req.Locality},
			Province:           []string{req.Province},
			OrganizationalUnit: []string{req.OrganizationalUnit},
			Organization:       []string{req.Organization},
			CommonName:         req.CommonName,
		},
		DNSNames:    dnsName,
		IPAddresses: ips,
	}

	data, err := bcx509.CreateCertificateRequest(rand.Reader, templateX509, sk)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func CreateCertificate(req *CertificateReq) ([]byte, error) {

	csr, err := bcx509.ParseCertificateRequest(req.CsrBytes)
	if err != nil {
		return nil, err
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, err
	}

	basicConstraintsValid := false

	if req.IsCA {
		basicConstraintsValid = true
	}

	keyUsage, extKeyUsage := getKeyUsageAndExtKeyUsage(req.IsCA)

	notBefore := time.Now().UTC()

	sn, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, err
	}

	caKey, err := bcx509.ParsePrivateKey(req.CaKeyBytes)
	if err != nil {
		return nil, err
	}

	signatureAlgorithm, err := getSignatureAlgorithm(caKey)
	if err != nil {
		return nil, err
	}

	template := &bcx509.Certificate{
		SerialNumber:          sn,
		NotBefore:             notBefore,
		NotAfter:              notBefore.Add(req.ValidTime).UTC(),
		BasicConstraintsValid: basicConstraintsValid,
		MaxPathLen:            -1,
		IsCA:                  req.IsCA,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              csr.DNSNames,
		Subject:               csr.Subject,
		Extensions:            csr.Extensions,
		ExtraExtensions:       csr.ExtraExtensions,
		SignatureAlgorithm:    signatureAlgorithm,
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
	}

	template.SubjectKeyId, err = bcx509.ComputeSKI(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	caCert, err := bcx509.ParseCertificateFromPEM(req.CaCertBytes)
	if err != nil {
		return nil, err
	}

	template.Issuer = caCert.Subject

	if caCert.SubjectKeyId != nil {
		template.AuthorityKeyId = caCert.SubjectKeyId
	} else {
		template.AuthorityKeyId, err = bcx509.ComputeSKI(caCert.PublicKey)
		if err != nil {
			return nil, err
		}
	}

	certDER, err := bcx509.CreateCertificate(rand.Reader, template, caCert,
		csr.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return certPEM, nil
}

func getSignatureAlgorithm(key crypto.PrivateKey) (bcx509.SignatureAlgorithm, error) {
	skey, ok := key.(crypto.Signer)
	if !ok {
		return 0, errors.New("x509: certificate private key does not implement crypto.Signer")
	}

	var signatureAlgorithm bcx509.SignatureAlgorithm
	switch skey.Public().(type) {
	case *ecdsa.PublicKey:
		signatureAlgorithm = bcx509.ECDSAWithSHA256
	case *bcecdsa.PublicKey:
		pk := skey.Public().(*bcecdsa.PublicKey)
		switch pk.Curve {
		case sm2.P256Sm2():
			signatureAlgorithm = bcx509.SM2WithSM3
		default:
			signatureAlgorithm = bcx509.ECDSAWithSHA256
		}
	case *rsa.PublicKey:
		signatureAlgorithm = bcx509.SHA256WithRSA
	case *sm2.PublicKey:
		signatureAlgorithm = bcx509.SM2WithSM3
	default:
		return 0, errors.New("x509: certificate private key type is unknowm")
	}

	return signatureAlgorithm, nil
}

func dealSANS(sans []string) ([]string, []net.IP) {

	var dnsName []string
	var ipAddrs []net.IP

	for _, san := range sans {
		ip := net.ParseIP(san)
		if ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsName = append(dnsName, san)
		}
	}

	return dnsName, ipAddrs
}

func getKeyUsageAndExtKeyUsage(isCa bool) (bcx509.KeyUsage, []bcx509.ExtKeyUsage) {
	var (
		keyUsage    bcx509.KeyUsage
		extKeyUsage []bcx509.ExtKeyUsage
	)
	if isCa {
		keyUsage = bcx509.KeyUsageCRLSign | bcx509.KeyUsageCertSign
	} else {
		keyUsage = bcx509.KeyUsageKeyEncipherment | bcx509.KeyUsageDataEncipherment | bcx509.KeyUsageKeyAgreement |
			bcx509.KeyUsageDigitalSignature | bcx509.KeyUsageContentCommitment
		extKeyUsage = []bcx509.ExtKeyUsage{bcx509.ExtKeyUsageClientAuth, bcx509.ExtKeyUsageServerAuth}
	}
	return keyUsage, extKeyUsage
}
