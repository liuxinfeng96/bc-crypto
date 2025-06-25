package crt

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/test-go/testify/require"
)

func TestCreateCSR(t *testing.T) {

	keyStr := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR1RBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUJITTlWQVlJdEJIa3dkd0lCQVFRZ0cxamJsMGE2dHVuR2FNZXMKK1d5dk1Td1JleHB2SS9qYTRPaEo5NjYvaDVPZ0NnWUlLb0VjejFVQmdpMmhSQU5DQUFUdjZmRVZ4MXIwQ29zZAoweDU4UGxsWnd2QUt0L1liSVFJTTA2eWx5TW9EUUhQTjAxZ0tBZmNRTUNyd1J0YnZIWnFDaWtPVzlOb2Y4UlJOCndSOHB0ZGF1Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"

	signKeyPem, err := base64.StdEncoding.DecodeString(keyStr)
	require.Nil(t, err)

	println(string(signKeyPem))
	// 申请CSR
	csrBytes, err := CreateCSR(&CsrReq{
		Country:            "CN",
		Locality:           "ShanDong",
		Province:           "QingDao",
		OrganizationalUnit: "client",
		Organization:       "lcago.cer.org",
		CommonName:         "202507201" + ".sign",
		PrivateKeyBytes:    signKeyPem,
	})
	require.Nil(t, err)

	println(string(csrBytes))
}

func TestCreateCert(t *testing.T) {
	keyStr := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR1RBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUJITTlWQVlJdEJIa3dkd0lCQVFRZ0cxamJsMGE2dHVuR2FNZXMKK1d5dk1Td1JleHB2SS9qYTRPaEo5NjYvaDVPZ0NnWUlLb0VjejFVQmdpMmhSQU5DQUFUdjZmRVZ4MXIwQ29zZAoweDU4UGxsWnd2QUt0L1liSVFJTTA2eWx5TW9EUUhQTjAxZ0tBZmNRTUNyd1J0YnZIWnFDaWtPVzlOb2Y4UlJOCndSOHB0ZGF1Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K"

	signKeyPem, err := base64.StdEncoding.DecodeString(keyStr)
	require.Nil(t, err)
	// 申请CSR
	csrBytes, err := CreateCSR(&CsrReq{
		Country:            "CN",
		Locality:           "ShanDong",
		Province:           "QingDao",
		OrganizationalUnit: "client",
		Organization:       "lcago.cer.org",
		CommonName:         "202507201" + ".sign",
		PrivateKeyBytes:    signKeyPem,
	})
	require.Nil(t, err)

	caKeyStr := "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR1RBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUJITTlWQVlJdEJIa3dkd0lCQVFRZ0x5VmlqSlZ2RWR2RXNTU20KSXNvV3JzVEg0emtkU1dXV0JXVFNXOGJtRzFHZ0NnWUlLb0VjejFVQmdpMmhSQU5DQUFRTXA2L1JTRVc1RFVKVApBUEY3UEhEczhiQkxXWlNYMTZwOFdHTVBrL3MySGg3Ym9xTWkzdG9POStjYXRmM0FIS0g4dlBUQlpmTkN1U3lECkdGVjkvVUo4Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0="

	caKeyPem, err := base64.StdEncoding.DecodeString(caKeyStr)
	require.Nil(t, err)

	caCertStr := "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNjekNDQWhtZ0F3SUJBZ0lERHVsV01Bb0dDQ3FCSE05VkFZTjFNSGt4Q3pBSkJnTlZCQVlUQWtOT01SRXcKRHdZRFZRUUlFd2hUYUdGdVJHOXVaekVRTUE0R0ExVUVCeE1IVVdsdVowUmhiekVXTUJRR0ExVUVDaE1OYkdOaApaMjh1WTJWeUxtOXlaekVTTUJBR0ExVUVDeE1KY205dmRDMWpaWEowTVJrd0Z3WURWUVFERXhCallTNXNZMkZuCmJ5NWpaWEl1YjNKbk1CNFhEVEl5TURZek1EQTJNekkxTlZvWERUTXlNRFl5TnpBMk16STFOVm93ZVRFTE1Ba0cKQTFVRUJoTUNRMDR4RVRBUEJnTlZCQWdUQ0ZOb1lXNUViMjVuTVJBd0RnWURWUVFIRXdkUmFXNW5SR0Z2TVJZdwpGQVlEVlFRS0V3MXNZMkZuYnk1alpYSXViM0puTVJJd0VBWURWUVFMRXdseWIyOTBMV05sY25ReEdUQVhCZ05WCkJBTVRFR05oTG14allXZHZMbU5sY2k1dmNtY3dXVEFUQmdjcWhrak9QUUlCQmdncWdSelBWUUdDTFFOQ0FBUU0KcDYvUlNFVzVEVUpUQVBGN1BIRHM4YkJMV1pTWDE2cDhXR01Qay9zMkhoN2JvcU1pM3RvTzkrY2F0ZjNBSEtIOAp2UFRCWmZOQ3VTeURHRlY5L1VKOG80R1BNSUdNTUE0R0ExVWREd0VCL3dRRUF3SUJCakFQQmdOVkhSTUJBZjhFCkJUQURBUUgvTUNrR0ExVWREZ1FpQkNDcndRcFEycHRsM1R5eWVOVU9CQ29Jb0xlVkpGYkgyOVgwdVRLeXR5KzcKdURBK0JnTlZIUkVFTnpBMWdnZGpaWEl1YjNKbmdnbHNiMk5oYkdodmMzU0NEV3hqWVdkdkxtTmxjaTV2Y21lQwpFR05oTG14allXZHZMbU5sY2k1dmNtY3dDZ1lJS29FY3oxVUJnM1VEU0FBd1JRSWhBS010OVdERmxuTUtpWXJyCmtUZ3MvdGdmdnBVaTNkZlA3UytzL2xsemdOZHNBaUFjTEllNkNkcGE3eE4rZEhiYUlESTBqSmpxYjdYeGhVODQKSzkrNFhhTDlIUT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"

	caCertPem, err := base64.StdEncoding.DecodeString(caCertStr)
	require.Nil(t, err)

	// 生成证书
	userCertBytes, err := CreateCertificate(&CertificateReq{
		IsCA:        false,
		ValidTime:   time.Hour * 24 * 365 * 100, // 100年
		CsrBytes:    csrBytes,
		CaCertBytes: caCertPem,
		CaKeyBytes:  caKeyPem,
	})
	require.Nil(t, err)

	println(string(userCertBytes))
}
