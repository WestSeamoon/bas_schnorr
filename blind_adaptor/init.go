package blind_adaptor

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

var (
	// Curve is a KoblitzCurve which implements secp256k1.
	Curve = btcec.S256()
	// One holds a big integer of 1
	One = new(big.Int).SetInt64(1)
	// Two holds a big integer of 2
	Two = new(big.Int).SetInt64(2)
	// Three holds a big integer of 3
	Three = new(big.Int).SetInt64(3)
	// Four holds a big integer of 4
	Four = new(big.Int).SetInt64(4)
	// Seven holds a big integer of 7
	Seven = new(big.Int).SetInt64(7)
	// N2 holds a big integer of N-2
	N2 = new(big.Int).Sub(Curve.N, Two)
)

// 字符串转[]byte数组
func StringToByte(s string) []byte {
	s_byte, _ := hex.DecodeString(s) //asn1.Marshal(s) //hex.DecodeString(s)
	return s_byte

}

// []byte数组转大数
func ByteToBigint(b []byte) *big.Int {
	result := new(big.Int).SetBytes(b)
	return result
}

// 字符串转大数
func StringToBigint(s string) *big.Int {
	//bigint, _ := new(big.Int).SetString(s, 16)
	byte := StringToByte(s)
	bigint := ByteToBigint(byte)
	return bigint
}

func ByteToString(b []byte) string {
	s := hex.EncodeToString(b)
	return s
}

func BigintToByte(int *big.Int) []byte {
	byte := int.Bytes()
	return byte
}

func BigintToString(int *big.Int) string {
	byte := BigintToByte(int)
	s := ByteToString(byte)
	return s
}

type Point struct {
	X, Y *big.Int
}

// 字符串转点
func StringToPoint(s string) *Point {
	p := new(Point)
	len := len(s) / 2
	x := s[:len]
	y := s[len:]
	// pub.X = StringToBigint(x)
	// pub.Y = StringToBigint(y)
	p.X = StringToBigint(x)
	p.Y = StringToBigint(y)
	return p
}

// 点转字符串
func PointToString(point *Point) string {
	px := BigintToString(point.X)
	py := BigintToString(point.Y)
	p_s := fmt.Sprintf("%s%s", px, py)
	return p_s
}

// 点转[]byte
func PointToBytes(point *Point) []byte {
	px_bytes := BigintToByte(point.X)
	py_bytes := BigintToByte(point.Y)
	point_bytes := append(px_bytes, py_bytes...)
	return point_bytes
}

// c=H(m,RR)
func MsgToDigest(msg string, p *Point) *big.Int {
	var msg_byte []byte = []byte(msg)
	var sha_32byte = sha256.Sum256(msg_byte)
	sha_byte := sha_32byte[:]
	//digest := new(big.Int).SetBytes(sha_byte)
	//message := BigintToByte(digest)
	p_byte := PointToBytes(p)
	r := append(sha_byte, p_byte...)
	h := sha256.Sum256(r)
	digest := new(big.Int).SetBytes(h[:])
	return digest
}

// 生成R=rG
func NextR(rnd io.Reader, max *big.Int) (*big.Int, *big.Int, *big.Int, error) {
	intOne := new(big.Int).SetInt64(1)
	var k *big.Int
	var err error
	for {
		k, err = rand.Int(rnd, max)
		if err != nil {
			return nil, nil, nil, err
		}
		if k.Cmp(intOne) >= 0 {
			x, y := sm2P256V1.ScalarBaseMult(k.Bytes())
			return k, x, y, err
		}
	}
}

// 将变量(r,R)转换为string类型输出
func RtoString(rnd io.Reader) (string, string, error) {
	max := StringToBigint("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123")

	k, x, y, err := NextR(rnd, max)

	k_string := BigintToString(k)

	kx := BigintToString(x)
	ky := BigintToString(y)
	K := fmt.Sprintf("%s%s", kx, ky)

	return k_string, K, err
}
