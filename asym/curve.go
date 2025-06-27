package asym

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
		return "UNKNOWN"
	}
}
