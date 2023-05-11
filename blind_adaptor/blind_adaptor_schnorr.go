package blind_adaptor

import (
	"encoding/hex"
)

// 计算变量R=rG+Y
func R0R1_caculate(r0 string, r1 string, Y string) (string, string) {
	r0_byte := StringToByte(r0)
	//r0_big := StringToBigint(r0)
	r1_byte := StringToByte(r1)
	Y_Point := StringToPoint(Y)

	R0 := new(Point)
	R0x, R0y := sm2P256V1.ScalarBaseMult(r0_byte)
	//Curve.ScalarBaseMult(r0_byte)                          //rG
	R0.X, R0.Y = sm2P256V1.Add(R0x, R0y, Y_Point.X, Y_Point.Y) //rG+Y
	R0_string := PointToString(R0)

	R1 := new(Point)
	R1x, R1y := sm2P256V1.ScalarBaseMult(r1_byte)
	R1.X, R1.Y = sm2P256V1.Add(R1x, R1y, Y_Point.X, Y_Point.Y)
	R1_string := PointToString(R1)

	return R0_string, R1_string
}

// 消息盲化
func Blind_msg(a0, b0, a1, b1, R0, R1, P, msg string) (string, string, string, string) {
	a0_byte := StringToByte(a0)
	a1_byte := StringToByte(a1)
	b0_byte := StringToByte(b0)
	b1_byte := StringToByte(b1)
	P_Point := StringToPoint(P)
	b0_big := StringToBigint(b0)
	b1_big := StringToBigint(b1)
	R0_Point := StringToPoint(R0)
	R1_Point := StringToPoint(R1)

	RR0 := new(Point)
	RR1 := new(Point)
	aGx0, aGy0 := sm2P256V1.ScalarBaseMult(a0_byte)                   //aG
	bPx0, bPy0 := sm2P256V1.ScalarMult(P_Point.X, P_Point.Y, b0_byte) //bP
	bPy0.Sub(sm2P256V1.P, bPy0)                                       //-bP
	aGRx0, aGRy0 := sm2P256V1.Add(aGx0, aGy0, R0_Point.X, R0_Point.Y) //aG+R
	RR0.X, RR0.Y = sm2P256V1.Add(aGRx0, aGRy0, bPx0, bPy0)            //aG+R-bP
	//RR0_string := PointToString(RR0)

	e0_big := MsgToDigest(msg, RR0)
	//c0_big := Add(e0_big, b0_big)
	c0_big := Mod(Add(e0_big, b0_big), sm2P256V1.N)

	e0 := BigintToString(e0_big)
	c0 := BigintToString(c0_big)

	aGx1, aGy1 := sm2P256V1.ScalarBaseMult(a1_byte)                   //aG
	bPx1, bPy1 := sm2P256V1.ScalarMult(P_Point.X, P_Point.Y, b1_byte) //bP
	bPy1.Sub(sm2P256V1.P, bPy1)                                       //-bP
	aGRx1, aGRy1 := sm2P256V1.Add(aGx1, aGy1, R1_Point.X, R1_Point.Y) //aG+R
	RR1.X, RR1.Y = sm2P256V1.Add(aGRx1, aGRy1, bPx1, bPy1)            //aG+R-bP
	//RR1_string := PointToString(RR1)

	e1_big := MsgToDigest(msg, RR1)
	//c1_big := Add(e1_big, b1_big)
	c1_big := Mod(Add(e1_big, b1_big), sm2P256V1.N)

	e1 := BigintToString(e1_big)
	c1 := BigintToString(c1_big)

	return e0, c0, e1, c1

}

// 盲签计算
func Blind_sign(r, c, d string) (s string) {
	r_big := StringToBigint(r)
	c_big := StringToBigint(c)
	d_big := StringToBigint(d)
	cd := Mul(c_big, d_big) //cd
	//s_big := Sub(r_big, cd) //r-cd
	s_big := Mod(Sub(r_big, cd), sm2P256V1.N)
	s = BigintToString(s_big)
	return s
}

// 解盲
func Ublind_sign(blind_sig, a, e string) string {
	blind_s := StringToBigint(blind_sig)
	a_big := StringToBigint(a)
	//s_big := Add(blind_s, a_big) //s=a+blind_s
	s_big := Mod(Add(blind_s, a_big), sm2P256V1.N)
	s_byte := BigintToByte(s_big)
	e_byte := StringToByte(e)
	sig_byte := append(e_byte, s_byte...) //pre_sig=(e,s)
	pre_sig := hex.EncodeToString(sig_byte)

	return pre_sig

}

// 预签名验证
func PVrfy(msg, pre_sig, Y_Point, P_Point string) bool {
	len := len(pre_sig) / 2
	e_string := pre_sig[:len]
	s_string := pre_sig[len:]
	e_big := StringToBigint(e_string)
	e_byte := StringToByte(e_string)
	s_byte := StringToByte(s_string)
	sGx, sGy := sm2P256V1.ScalarBaseMult(s_byte) //sG
	Y := StringToPoint(Y_Point)
	P := StringToPoint(P_Point)
	sGYx, sGYy := sm2P256V1.Add(sGx, sGy, Y.X, Y.Y) //sG+Y
	ePx, ePy := sm2P256V1.ScalarMult(P.X, P.Y, e_byte)
	R := new(Point)
	R.X, R.Y = sm2P256V1.Add(sGYx, sGYy, ePx, ePy) //sG+Y+cP
	//R.X, R.Y = sm2P256V1.Add(sGx, sGy, ePx, ePy)

	//R_string := PointToString(R)

	expect_e := MsgToDigest(msg, R)
	expect_e = Mod(expect_e, sm2P256V1.N)
	//expect_e_string := BigintToString(expect_e)
	return expect_e.Cmp(e_big) == 0
	// 	return false, R_string
}

// 适配
func Adapt(pre_sig, y string) string {
	len := len(pre_sig) / 2
	e_string := pre_sig[:len]
	pres_string := pre_sig[len:]
	e_byte := StringToByte(e_string)
	pres_big := StringToBigint(pres_string)
	y_big := StringToBigint(y)
	s := Add(pres_big, y_big) //s=pre_s+y
	s = Mod(s, sm2P256V1.N)
	s_byte := BigintToByte(s)
	sig_byte := append(e_byte, s_byte...)
	sig := hex.EncodeToString(sig_byte)

	return sig
}

// 验证
func Vrfy(msg, sig, P_Point string) bool {
	len := len(sig) / 2
	e_string := sig[:len]
	s_string := sig[len:]
	e_big := StringToBigint(e_string)
	e_byte := StringToByte(e_string)
	s_byte := StringToByte(s_string)

	sGx, sGy := sm2P256V1.ScalarBaseMult(s_byte) //sG
	P := StringToPoint(P_Point)
	ePx, ePy := sm2P256V1.ScalarMult(P.X, P.Y, e_byte) //eP
	R := new(Point)
	R.X, R.Y = sm2P256V1.Add(sGx, sGy, ePx, ePy) //sG+eP

	expect_e := MsgToDigest(msg, R)
	expect_e = Mod(expect_e, sm2P256V1.N)

	return expect_e.Cmp(e_big) == 0
}

// 提取
func Ext(sig, presig string) string {
	len := len(sig) / 2
	s_string := sig[len:]
	pre_string := presig[len:]
	s_big := StringToBigint(s_string)
	pre_big := StringToBigint(pre_string)
	y_big := Sub(s_big, pre_big)
	y_big = Mod(y_big, sm2P256V1.N)
	y := BigintToString(y_big)

	return y

}

func R_test(a0, R0, msg string) (string, string) {
	a0_byte := StringToByte(a0)

	R0_Point := StringToPoint(R0)

	RR0 := new(Point)

	aGx0, aGy0 := sm2P256V1.ScalarBaseMult(a0_byte) //aG

	aGRx0, aGRy0 := sm2P256V1.Add(aGx0, aGy0, R0_Point.X, R0_Point.Y) //aG+R

	RR0.X, RR0.Y = aGRx0, aGRy0
	RR0_string := PointToString(RR0)

	e0_big := MsgToDigest(msg, RR0)

	e0 := BigintToString(e0_big)

	return e0, RR0_string

}

func Msg_test(msg string, R_Point string) string {
	R := StringToPoint(R_Point)
	e := MsgToDigest(msg, R)
	e_string := BigintToString(e)
	return e_string
}

func Dg_test(d string) string {
	d_byte := StringToByte(d)
	P := new(Point)
	P.X, P.Y = sm2P256V1.ScalarBaseMult(d_byte)
	pstring := PointToString(P)

	return pstring

}
