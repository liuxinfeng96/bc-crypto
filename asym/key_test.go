package asym

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/test-go/testify/require"
	"github.com/tjfoc/gmsm/sm2"
)

func TestGenerateKey(t *testing.T) {
	// EC_Secp256k1
	secp256k1Key, err := GenerateKey(EC_Secp256k1)
	require.Nil(t, err)

	keyPem, err := MarshalPrivateKey(secp256k1Key)
	require.Nil(t, err)

	fmt.Println(string(keyPem))

	secp256k1Key2, err := ParsePrivateKey(keyPem)
	require.Nil(t, err)

	secp256k1Key3, ok := secp256k1Key2.(*ecdsa.PrivateKey)
	require.Equal(t, true, ok)
	require.Equal(t, secp256k1Key3.Curve, secp256k1.S256())

	// EC_SM2
	sm2Key, err := GenerateKey(EC_SM2)
	require.Nil(t, err)

	keyPem, err = MarshalPrivateKey(sm2Key)
	require.Nil(t, err)

	fmt.Println(string(keyPem))

	sm2Key2, err := ParsePrivateKey(keyPem)
	require.Nil(t, err)

	sm2Key3, ok := sm2Key2.(*ecdsa.PrivateKey)
	require.Equal(t, true, ok)
	require.Equal(t, sm2Key3.Curve, sm2.P256Sm2())

	// EC_NISTP256
	p256Key, err := GenerateKey(EC_NISTP256)
	require.Nil(t, err)

	keyPem, err = MarshalPrivateKey(p256Key)
	require.Nil(t, err)

	fmt.Println(string(keyPem))

	p256Key2, err := ParsePrivateKey(keyPem)
	require.Nil(t, err)

	p256Key3, ok := p256Key2.(*ecdsa.PrivateKey)
	require.Equal(t, true, ok)
	require.Equal(t, p256Key3.Curve, elliptic.P256())

	// RSA2048
	rsaKey, err := GenerateKey(RSA2048)
	require.Nil(t, err)

	keyPem, err = MarshalPrivateKey(rsaKey)
	require.Nil(t, err)

	fmt.Println(string(keyPem))

	rsaKey2, err := ParsePrivateKey(keyPem)
	require.Nil(t, err)

	_, ok = rsaKey2.(*rsa.PrivateKey)
	require.Equal(t, true, ok)
}
