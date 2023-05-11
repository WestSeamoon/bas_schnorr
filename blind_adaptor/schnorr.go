package blind_adaptor

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Sign a 32 byte message with the private key, returning a 64 byte signature.
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#signing
func Sign(privateKey *big.Int, message [32]byte) ([64]byte, error) {
	sig := [64]byte{}
	if privateKey.Cmp(One) < 0 || privateKey.Cmp(new(big.Int).Sub(Curve.N, One)) > 0 {
		return sig, errors.New("the private key must be an integer in the range 1..n-1")
	}

	d := intToByte(privateKey)
	k0, err := deterministicGetK0(d, message)
	if err != nil {
		return sig, err
	}

	Rx, Ry := Curve.ScalarBaseMult(intToByte(k0))
	k := getK(Ry, k0)

	Px, Py := Curve.ScalarBaseMult(d)
	rX := intToByte(Rx)
	e := getE(Px, Py, rX, message)
	e.Mul(e, privateKey)
	k.Add(k, e)
	k.Mod(k, Curve.N)

	copy(sig[:32], rX)
	copy(sig[32:], intToByte(k))
	return sig, nil
}

// Verify a 64 byte signature of a 32 byte message against the public key.
// Returns an error if verification fails.
// https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki#verification
func Verify(publicKey [33]byte, message [32]byte, signature [64]byte) (bool, error) {
	Px, Py := Unmarshal(Curve, publicKey[:])

	if Px == nil || Py == nil || !Curve.IsOnCurve(Px, Py) {
		return false, errors.New("signature verification failed")
	}
	r := new(big.Int).SetBytes(signature[:32])
	if r.Cmp(Curve.P) >= 0 {
		return false, errors.New("r is larger than or equal to field size")
	}
	s := new(big.Int).SetBytes(signature[32:])
	if s.Cmp(Curve.N) >= 0 {
		return false, errors.New("s is larger than or equal to curve order")
	}

	e := getE(Px, Py, intToByte(r), message)
	sGx, sGy := Curve.ScalarBaseMult(intToByte(s))
	// e.Sub(Curve.N, e)
	ePx, ePy := Curve.ScalarMult(Px, Py, intToByte(e))
	ePy.Sub(Curve.P, ePy)
	Rx, Ry := Curve.Add(sGx, sGy, ePx, ePy)

	if (Rx.Sign() == 0 && Ry.Sign() == 0) || big.Jacobi(Ry, Curve.P) != 1 || Rx.Cmp(r) != 0 {
		return false, errors.New("signature verification failed")
	}
	return true, nil
}

func getE(Px, Py *big.Int, rX []byte, m [32]byte) *big.Int {
	r := append(rX, Marshal(Curve, Px, Py)...)
	r = append(r, m[:]...)
	h := sha256.Sum256(r)
	i := new(big.Int).SetBytes(h[:])
	return i.Mod(i, Curve.N)
}

func getK(Ry, k0 *big.Int) *big.Int {
	if big.Jacobi(Ry, Curve.P) == 1 {
		return k0
	}
	return k0.Sub(Curve.N, k0)
}

func deterministicGetK0(d []byte, message [32]byte) (*big.Int, error) {
	h := sha256.Sum256(append(d, message[:]...))
	i := new(big.Int).SetBytes(h[:])
	k0 := i.Mod(i, Curve.N)
	if k0.Sign() == 0 {
		return nil, errors.New("k0 is zero")
	}

	return k0, nil
}

func deterministicGetRandA() (*big.Int, error) {
	a, err := rand.Int(rand.Reader, N2)
	if err != nil {
		return nil, err
	}

	return a.Add(a, One), nil
}

func intToByte(i *big.Int) []byte {
	b1, b2 := [32]byte{}, i.Bytes()
	copy(b1[32-len(b2):], b2)
	return b1[:]
}

// Marshal converts a point into the form specified in section 2.3.3 of the
// SEC 1 standard.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3

	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// Unmarshal converts a point, serialised by Marshal, into an x, y pair. On
// error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return
	}
	if len(data) != 1+byteLen {
		return
	}

	x0 := new(big.Int).SetBytes(data[1 : 1+byteLen])
	P := curve.Params().P
	ySq := new(big.Int)
	ySq.Exp(x0, Three, P)
	ySq.Add(ySq, Seven)
	ySq.Mod(ySq, P)
	y0 := new(big.Int)
	P1 := new(big.Int).Add(P, One)
	d := new(big.Int).Mod(P1, Four)
	P1.Sub(P1, d)
	P1.Div(P1, Four)
	y0.Exp(ySq, P1, P)

	if new(big.Int).Exp(y0, Two, P).Cmp(ySq) != 0 {
		return
	}
	if y0.Bit(0) != uint(data[0]&1) {
		y0.Sub(P, y0)
	}
	x, y = x0, y0
	return
}
