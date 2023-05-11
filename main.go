package main

import (
	"adaptor_schnorr/blind_adaptor"
	"crypto/rand"
	"fmt"
	"os"
	"time"
)

func main() {
	for {
		fmt.Println("请选择您的需求：")
		fmt.Println("1.生成2个临时变量r/随机数a和b")
		fmt.Println("2.计算R")
		fmt.Println("3.消息盲化")
		fmt.Println("4.生成盲签名")
		fmt.Println("5.盲签名解盲")
		fmt.Println("6.预签名验证")
		fmt.Println("7.预签名适配为正式签名")
		fmt.Println("8.正式签名验证")
		fmt.Println("9.提取困难关系证据")
		fmt.Println("0.退出")
		var require int
		fmt.Scanln(&require)
		switch require {
		case 0:
			os.Exit(-1)
		case 1:
			r0, _, _ := blind_adaptor.RtoString(rand.Reader)
			r1, _, _ := blind_adaptor.RtoString(rand.Reader)
			fmt.Println("生成的临时变量分别为:")
			fmt.Println("r0/a0/a1:", r0)
			fmt.Println("r1/b0/b1:", r1)
		case 2:
			var r0, r1, Y string
			fmt.Println("请输入r0:")
			fmt.Scanln(&r0)
			fmt.Println("请输入r1:")
			fmt.Scanln(&r1)
			fmt.Println("请输入困难关系状态:")
			fmt.Scanln(&Y)
			R0, R1 := blind_adaptor.R0R1_caculate(r0, r1, Y)
			fmt.Println("计算结果分别为:")
			fmt.Println("R0:", R0)
			fmt.Println("R1:", R1)
		case 3:
			var msg, P, R0, R1, a0, b0, a1, b1 string
			fmt.Println("请输入消息内容:")
			fmt.Scanln(&msg)
			fmt.Println("请输入公钥P:")
			fmt.Scanln(&P)
			fmt.Println("请输入R0")
			fmt.Scanln(&R0)
			fmt.Println("请输入R1")
			fmt.Scanln(&R1)
			fmt.Println("请输入盲化因子a0")
			fmt.Scanln(&a0)
			fmt.Println("请输入盲化因子a1")
			fmt.Scanln(&a1)
			fmt.Println("请输入盲化因子b0")
			fmt.Scanln(&b0)
			fmt.Println("请输入盲化因子b1")
			fmt.Scanln(&b1)
			// msg = "helloworld"
			// a0 = "29a0b9c201bc1cbb1c05b65df7af4b664929eefa0ad8c9429dfb0e9c584f55fd"
			// a1 = "84e6e81a4443b21ac3222fca54abf0eee4ca9a49212a7eb3cbd706a2d1760728"
			// b0 = "6662ce751239f3a61cb2a45ecf9f499bedbbe9cd6cce8b0e5dc1d123ef65ed07"
			// b1 = "47e77a6ba24bb33b148bd769e941908f4a9be55c3360f4c5c0e2f36d6cf5c40d"
			// R0 = "c5e59f42e4a615adca2830d3009cc559fe6edb41c3c990f467973b42783a0c7427d1f7172b35f65c34ed16adec51cc19ff0df60d99ae80664dae125f9b68cd0d"
			// R1 = "f0f7b2bc8130d13865739aa754f003cac7ea7b775b8a99c5baf3aa7e22d251ee6414e0635c1b9be53216aebfe0b3fb8d0c1a99a4debc4dd9b9d3a9e20a9072eb"
			// P = "384e1965c3afb16128f52c5ff24e9e1374a7ecae3ab5506168657ff848f62147f8e80134051400abce0e9c97513d8dfbbaa73952cac70589f245fbfa9c260df6"
			start := time.Now() //获取当前时间
			e0, c0, e1, c1 := blind_adaptor.Blind_msg(a0, b0, a1, b1, R0, R1, P, msg)
			times := time.Since(start) //运算用时
			fmt.Println("盲化后的消息分别为：")
			fmt.Println("e0: ", e0)
			fmt.Println("c0: ", c0)
			fmt.Println("e1: ", e1)
			fmt.Println("c1: ", c1)
			// fmt.Println("RR0: ", RR0)
			// fmt.Println("RR1: ", RR1)
			fmt.Println("运算用时：", times)
		case 4:
			var blind_msg, r, pri string
			// blind_msg = "f6344bdf760ba7a9aeb52664059a4820efe72d6fe16a65c1175c30d58a08a70c"
			// r = "055f45cf0330be9296c4daa4f0ed269f666025463b6f2455f46c445190e917fc"
			// pri = "d924a1276f744c374d2ba3eca13ef1d842de673b8c63314024e99cd18c7df971"
			fmt.Println("请输入要签名的盲消息:")
			fmt.Scanln(&blind_msg)
			fmt.Println("请输入临时变量r:")
			fmt.Scanln(&r)
			fmt.Println("请输入私钥：")
			fmt.Scanln(&pri)
			start := time.Now() //获取当前时间
			blind_sig := blind_adaptor.Blind_sign(r, blind_msg, pri)
			times := time.Since(start) //运算用时
			fmt.Println(blind_msg, "的盲签名为:", blind_sig)
			fmt.Println("运算用时：", times)
		case 5:
			var blind_sig, a, e string
			// blind_sig = "db93c7ca89a41b0b9127af6446e87fb27e0aa50194e23b9fba27de07e4cf3c4d"
			// a = "29a0b9c201bc1cbb1c05b65df7af4b664929eefa0ad8c9429dfb0e9c584f55fd"
			// e = "8fd17d6a63d1b4039202820535fafe85022b43a2749bdab2b99a5fb19aa2ba05"
			fmt.Println("请输入盲签名")
			fmt.Scanln(&blind_sig)
			fmt.Println("请输入盲化因子a")
			fmt.Scanln(&a)
			fmt.Println("请输入e")
			fmt.Scanln(&e)
			start := time.Now() //获取当前时间
			presign := blind_adaptor.Ublind_sign(blind_sig, a, e)
			times := time.Since(start) //运算用时
			fmt.Println("解盲后的预签名为:", presign)
			fmt.Println("运算用时：", times)
		case 6:
			var msg, pre_sig, Y, P string
			// msg = "helloworld"
			// P = "384e1965c3afb16128f52c5ff24e9e1374a7ecae3ab5506168657ff848f62147f8e80134051400abce0e9c97513d8dfbbaa73952cac70589f245fbfa9c260df6"
			// Y = "94369b147aedade7bae96dc52438399e62eda7e160dfc927321e9e67ad9445a27413f590246177535dfe01eefe0d18fb4097dd5f375fda3ed9f4f68ce093e509"
			// pre_sig = "8fd17d6a63d1b4039202820535fafe85022b43a2749bdab2b99a5fb19aa2ba050534818d8b6037c6ad2d65c23e97cb195530b4907df4ffb70466f89b03495127"
			fmt.Println("请输入消息内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入预签名：")
			fmt.Scanln(&pre_sig)
			fmt.Println("请输入困难关系状态:")
			fmt.Scanln(&Y)
			fmt.Println("请输入公钥：")
			fmt.Scanln(&P)
			start := time.Now() //获取当前时间
			ver := blind_adaptor.PVrfy(msg, pre_sig, Y, P)
			times := time.Since(start) //运算用时
			fmt.Println("预签名验证结果为:", ver)
			fmt.Println("运算用时：", times)
		case 7:
			var pre_sig, y string
			fmt.Println("请输入预签名：")
			fmt.Scanln(&pre_sig)
			fmt.Println("请输入困难关系证据")
			fmt.Scanln(&y)
			start := time.Now() //获取当前时间
			adapt := blind_adaptor.Adapt(pre_sig, y)
			times := time.Since(start) //运算用时
			fmt.Println("适配的正式签名为:\n", adapt)
			fmt.Println("运算用时：", times)
		case 8:
			var msg, sig, P string
			fmt.Println("请输入消息内容：")
			fmt.Scanln(&msg)
			fmt.Println("请输入签名：")
			fmt.Scanln(&sig)
			fmt.Println("请输入公钥：")
			fmt.Scanln(&P)
			start := time.Now() //获取当前时间
			ver := blind_adaptor.Vrfy(msg, sig, P)
			times := time.Since(start) //运算用时
			fmt.Println("签名验证结果为:", ver)
			fmt.Println("运算用时：", times)
		case 9:
			var pre_sig, sig string
			fmt.Println("请输入预签名:")
			fmt.Scanln(&pre_sig)
			fmt.Println("请输入sm2签名:")
			fmt.Scanln(&sig)
			start := time.Now() //获取当前时间
			extract_y := blind_adaptor.Ext(sig, pre_sig)
			times := time.Since(start) //运算用时
			fmt.Println("提取到的困难关系证据y为:\n", extract_y)
			fmt.Println("运算用时：", times)
		//case 10:
		// msg := "helloworld"
		// a0 := "29a0b9c201bc1cbb1c05b65df7af4b664929eefa0ad8c9429dfb0e9c584f55fd"
		// R0 := "c5e59f42e4a615adca2830d3009cc559fe6edb41c3c990f467973b42783a0c7427d1f7172b35f65c34ed16adec51cc19ff0df60d99ae80664dae125f9b68cd0d"
		// start := time.Now() //获取当前时间
		// e0, RR0 := blind_adaptor.R_test(a0, R0, msg)
		// digest := blind_adaptor.Msg_test(msg, RR0)
		//d := "d924a1276f744c374d2ba3eca13ef1d842de673b8c63314024e99cd18c7df971"
		//P := blind_adaptor.Dg_test(d)
		// times := time.Since(start) //运算用时
		// fmt.Println("digest:", digest)
		// fmt.Println("e0为:", e0)
		// fmt.Println("RR0为:", RR0)
		// fmt.Println("运算用时：", times)
		default:
			fmt.Println("请输入合法的数字！")
		}
	}

}
