package blind_adaptor

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)

// sm2P256V1 代表国密SM2推荐参数定义的椭圆曲线
var sm2P256V1 P256V1Curve

// P256V1Curve 代表国密SM2推荐参数定义的椭圆曲线:
// (1) 素数域256位椭圆曲线
// (2) 曲线方程为 Y^2 = X^3 + aX + b
// (3) 其他参数: p, a, b, n, Gx, Gy 详见国标SM2推荐曲线参数
// (4) 在GO语言标准库通用椭圆曲线参数类elliptic.CurveParams的基础上增加了参数a的属性
// (5) 由于SM2推荐曲线符合a=p-3, 所以上述曲线可简化为等价曲线 Y^2 = X^3 - 3X + b (mod p)
type P256V1Curve struct {
	*elliptic.CurveParams
	A *big.Int
}

// PublicKey 代表SM2算法的公钥类:
// (1) X,Y 为P点（有限素数域上基点G的D倍点)坐标
// (2) Curve 为SM2算法的椭圆曲线
type PublicKey struct {
	X, Y  *big.Int
	Curve P256V1Curve
}

// PrivateKey 代表SM2算法的私钥类:
// (1) D代表公钥P点相对于基点G的倍数
// (2) Curve 为SM2算法的椭圆曲线
type PrivateKey struct {
	D     *big.Int
	Curve P256V1Curve
}

type Sm2Signature struct {
	R *big.Int
	S *big.Int
}

// init() 初始化国密SM2推荐参数计算得出的椭圆曲线。
func init() {
	initSm2P256V1()
}

// initSm2P256V1 为初始化国密SM2推荐参数计算得出的椭圆曲线:
// (1) 基域F(p)为素数域
// (2) 一次元x的系数a=p-3, 所以曲线方程等价于 y^2 = x^3 - 3x^2 + b (mod p) (即符合FIPS186-3标准预设函数)
// (3) 余因子h=1,sm2H 代表基域Fp上椭圆曲线E的余因子h,由于SM2推荐曲线的余因子h=1, 即#E(Fp) = n
func initSm2P256V1() {
	sm2P, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	sm2A, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
	sm2B, _ := new(big.Int).SetString("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
	sm2N, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2Gx, _ := new(big.Int).SetString("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
	sm2Gy, _ := new(big.Int).SetString("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
	sm2P256V1.CurveParams = &elliptic.CurveParams{Name: "SM2-P-256-V1"}
	sm2P256V1.P = sm2P
	sm2P256V1.A = sm2A
	sm2P256V1.B = sm2B
	sm2P256V1.N = sm2N
	sm2P256V1.Gx = sm2Gx
	sm2P256V1.Gy = sm2Gy
	sm2P256V1.BitSize = BitSize
}

// GetSm2P256V1 为获取国密SM2椭圆曲线定义的函数。
func GetSm2P256V1() P256V1Curve {
	return sm2P256V1
}

// GenerateKey 为国密SM2生成秘钥对的函数:
// (1) 利用GO语言标准包crypto/rand生成随机数rand;
// (2) 将SM2推荐曲线参数和随机数rand输入GO语言标准包crypto/elliptic的公钥对生成方法GenerateKey()，生成密钥对核心参数(priv, x, y);
// (3) 根据PublicKey类和PrivateKey类的定义生成公钥和私钥的实例，并将上述核心参数赋值给实例各相应属性以完成初始化.
func GenerateKey(rand io.Reader) (string, string, error) {
	priv, x, y, err := elliptic.GenerateKey(sm2P256V1, rand)
	if err != nil {
		return "", "", err
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(priv)
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = x
	publicKey.Y = y
	d := BigintToString(privateKey.D)
	px := BigintToString(publicKey.X)
	py := BigintToString(publicKey.Y)
	p := fmt.Sprintf("%s%s", px, py)
	return d, p, nil
}

// RawBytesToPublicKey 将字节数组形式的原始格式数据转化为SM2公钥的方法:
// (1) 校验原始格式数据的字节长度(32的2倍,即64个字节)
// (2) 利用GO语言标准包math/big的SetBytes()方法将原始格式数据转变成大端整数
// (3) 赋值给PublicKey实例的相关属性，完成公钥初始化
func RawBytesToPublicKey(bytes []byte) (*PublicKey, error) {
	if len(bytes) != KeyBytes*2 {
		return nil, fmt.Errorf("Public key raw bytes length must be %d", KeyBytes*2) //errors.New(fmt.Sprintf("Public key raw bytes length must be %d", KeyBytes*2)) //
	}
	publicKey := new(PublicKey)
	publicKey.Curve = sm2P256V1
	publicKey.X = new(big.Int).SetBytes(bytes[:KeyBytes])
	publicKey.Y = new(big.Int).SetBytes(bytes[KeyBytes:])
	return publicKey, nil
}

// RawBytesToPrivateKey 将字节数组形式的原始格式数据转变为SM2私钥的方法:
// (1) 校验原始格式数据的字节长度(256位除以8，即32字节)
// (2) 利用GO语言标准包math/big的SetBytes()方法将原始格式数据转变成大端整数
// (3) 赋值给PrivateKey实例的相关属性，完成私钥初始化
func RawBytesToPrivateKey(bytes []byte) (*PrivateKey, error) {
	if len(bytes) != KeyBytes {
		return nil, errors.New(fmt.Sprintf("Private key raw bytes length must be %d", KeyBytes))
	}
	privateKey := new(PrivateKey)
	privateKey.Curve = sm2P256V1
	privateKey.D = new(big.Int).SetBytes(bytes)
	return privateKey, nil
}

// GetUnCompressBytes 为获取未压缩字节数组格式存储的公钥的方法:
// (1) 将PublicKey实例的坐标(x,y)分别转化为字节数组
// (2) 将“未压缩”标识"0x04"写入输出字节数组raw[]的首字节raw[0]
// (3) 将x坐标写入raw[:33], 将y坐标写入raw[33:]
func (pub *PublicKey) GetUnCompressBytes() []byte {
	xBytes := bigIntTo32Bytes(pub.X)
	yBytes := bigIntTo32Bytes(pub.Y)
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

// GetRawBytes 为获得字节数组格式存储的公钥的方法。
func (pub *PublicKey) GetRawBytes() []byte {
	raw := pub.GetUnCompressBytes()
	return raw[1:]
}

// GetRawBytes 为获得字节数组格式存储的私钥的方法。
func (pri *PrivateKey) GetRawBytes() []byte {
	dBytes := bigIntTo32Bytes(pri.D)
	dl := len(dBytes)
	if dl > KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw, dBytes[dl-KeyBytes:])
		return raw
	} else if dl < KeyBytes {
		raw := make([]byte, KeyBytes)
		copy(raw[KeyBytes-dl:], dBytes)
		return raw
	} else {
		return dBytes
	}
}

// CalculatePubKey 为SM2利用私钥推算公钥的方法:
// (1) 创设公钥实例，将私钥携带的曲线赋值给公钥实例
// (2) 利用GO语言标准包(crypto/elliptic)定义的Curve接口的ScalarBaseMult()方法，
// 根据椭圆曲线、基点G、私钥(D倍数)推算公钥(倍点P)
func CalculatePubKey(priv *PrivateKey) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = priv.Curve
	pub.X, pub.Y = priv.Curve.ScalarBaseMult(priv.D.Bytes())
	return pub
}

// nextK 为生成[1, max)范围内随机整数的函数:
// (1) 利用标准库math/big设置整数1
// (2) 利用标准库crypto/rand生成随机数
// (3) 审核随机数范围[1, max)
// (4) 本算法中max为基础域的阶数n
func NextK(rnd io.Reader, max *big.Int) (*big.Int, *big.Int, *big.Int, error) {
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

// 表示SM2 Key的大数比较小时，直接通过Bytes()函数得到的字节数组可能不够32字节，这个时候要补齐成32字节
func bigIntTo32Bytes(bn *big.Int) []byte {
	byteArr := bn.Bytes()
	byteArrLen := len(byteArr)
	if byteArrLen == KeyBytes {
		return byteArr
	}
	byteArr = append(make([]byte, KeyBytes-byteArrLen), byteArr...)
	return byteArr
}

// 公钥格式化
func PubToPublicKey(s string) *PublicKey {
	pub := new(PublicKey)
	pub.Curve = GetSm2P256V1()
	len := len(s) / 2
	x := s[:len]
	y := s[len:]
	// pub.X = StringToBigint(x)
	// pub.Y = StringToBigint(y)
	pub.X = StringToBigint(x)
	pub.Y = StringToBigint(y)
	return pub
}

// 私钥格式化
func PrivToPrivateKey(priv string) *PrivateKey {
	//d_bigint := StringToBigint(priv)
	d_bigint := StringToBigint(priv)
	var privateKey PrivateKey
	privateKey.D = d_bigint
	privateKey.Curve = GetSm2P256V1()
	return &privateKey
}
