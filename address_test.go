package gobbc

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestMakeKeyPair(t *testing.T) {
	tw := &TW{t, true}
	n := 100
	for i := 0; i < n; i++ {
		pair, err := MakeKeyPair()
		tw.
			Nil(err).
			True(len(pair.Pubk) == PubkeyHexLen-1, "公钥长度异常", len(pair.Pubk)).
			True(len(pair.Pubk) == len(pair.Privk), "公钥长度应该等于私钥长度？")
		t.Logf("pair:%#v\n", pair)
	}
}

func TestGetPubKeyAddress(t *testing.T) {
	tw := TW{t, true}

	tests := []struct {
		name           string
		pubk, shouldBe string
		err            error
	}{
		{
			pubk:     "e8e3770e774d5ad84a8ea65ed08cc7c5c30b42e045623604d5c5c6be95afb4f9",
			shouldBe: "1z6taz5dyrv2xa11pc92y0ggbrf2wf36gbtk8wjprb96qe3kqwfm3ayc1",
		},
		{
			pubk:     "287fd2022a526bfaae2c9780a78a70f4fa7f293b6afb183f1f05e4056b07119b",
			shouldBe: "1kc8getr5wg2hyfrrzdn3pabzzbt712n7g2bjsbqtdd92m0pjfwmfyw9j",
		},
		{
			name:     "自己生成的公钥",
			pubk:     "2b9ff534924ee322a73cd6fccc839f666b559f48c7fc68b16c5a69ba448dc4b0",
			shouldBe: "1p328th5td5d6scb8zk3mh7tnddk9z0yczkb3s9s2wd794d7nkwnk1n2w",
		},
	}

	for _, tt := range tests {
		pubk, shouldBe := tt.pubk, tt.shouldBe
		add, err := GetPubKeyAddress(pubk)
		tw.Nil(err).
			True(shouldBe == add, "地址不对", shouldBe)
	}

}

func TestTemplateAddr(t *testing.T) {
	// TODO 增加测试数据
	// 正常解析
	// 错误的长度
	// 公钥的解析
	// 。。。
	tw := TW{T: t}
	h := "02000102ff1b5b6a4c177953f738ac2eebdcaee40a1131530612cafcd86f509ac7c0b81f01654a017cb2c46cc21452ee2c8d52e70a8570393937264691da9f76be6c6f38a701"
	b, err := hex.DecodeString(h)
	tw.Nil(err)

	fmt.Println("expected:2+2+33*2 = 70", len(b))
	b = b[2:]
	fmt.Println("mn1(32+1)2(32+1) = 68", len(b))
	fmt.Println("m-n", b[:2])
	b = b[2:]
	fmt.Println("前33", b[:33])
	fmt.Println("后33", b[33:])

	for _, pub := range []string{
		"a7386f6cbe769fda91462637393970850ae7528d2cee5214c26cc4b27c014a65",
		"1fb8c0c79a506fd8fcca12065331110ae4aedceb2eac38f75379174c6a5b1bff",
	} {
		k, err := ParsePublicKeyHex(pub)
		tw.Nil(err)
		fmt.Println(k)
	}

}

func TestCreateTemplateDataDexOrder(t *testing.T) {
	t.Skip("这个测试跳过，后来改了字段，测试用例没改，需要修复这个测试")
	/**
	bigbang> addnewtemplate dexorder '{"seller_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","coinpair":"bbc/mkf","price":10,"fee": 0.002,"recv_address":"1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn","valid_height": 300,"match_address": "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd","deal_address": "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb"}'
	2140cp9r0rchawvvcvbtkxe440h844xx4h8h1hbcwdpd4tqtcxnjy1vqv
	bigbang> validateaddress 2140cp9r0rchawvvcvbtkxe440h844xx4h8h1hbcwdpd4tqtcxnjy1vqv
	{
	    "isvalid" : true,
	    "addressdata" : {
	        "address" : "2140cp9r0rchawvvcvbtkxe440h844xx4h8h1hbcwdpd4tqtcxnjy1vqv",
	        "ismine" : true,
	        "type" : "template",
	        "template" : "dexorder",
	        "templatedata" : {
	            "type" : "dexorder",
	            "hex" : "09000196ce8e4b621469f673603ae73b46b39143e04e4c3c138e36802bb1ca605546b707000000000000006262632f6d6b6600e8764817000000140000003900000000000000316a763738776a763232686d7a6377763037626b6b70686e6b6a353179306b6a633767397277646d30356572776d72326e3874766838796a6e2c010000012b3a537410d6c845cf420fb1e81286ad501e698784de66277cb6ee16429444a8390000000000000031663262326e336173626d3272623939666b316334777030363964307a3931656e78647a386b6d716d713766307738747a7736346864657662",
	            "dexorder" : {
	                "seller_address" : "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
	                "coinpair" : "bbc/mkf",
	                "price" : 10.000000,
	                "fee" : 0.002000,
	                "recv_address" : "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
	                "valid_height" : 300,
	                "match_address" : "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd",
	                "deal_address" : "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb"
	            }
	        }
	    }
	}
	*/

	tw := TW{T: t}
	add, data, err := CreateTemplateDataDexOrder(DexOrderParam{
		SellerAddress: "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
		Coinpair:      "bbc/mkf",
		Price:         10_0_000_000_000, //10
		Fee:           2_0,              //0.002
		RecvAddress:   "1jv78wjv22hmzcwv07bkkphnkj51y0kjc7g9rwdm05erwmr2n8tvh8yjn",
		ValidHeight:   300,
		MatchAddress:  "15cx56x0gtv44bkt21yryg4m6nn81wtc7gkf6c9vwpvq1cgmm8jm7m5kd",
		DealAddress:   "1f2b2n3asbm2rb99fk1c4wp069d0z91enxdz8kmqmq7f0w8tzw64hdevb",
	})
	tw.Nil(err)
	tw.Equal(
		"09000196ce8e4b621469f673603ae73b46b39143e04e4c3c138e36802bb1ca605546b707000000000000006262632f6d6b6600e8764817000000140000003900000000000000316a763738776a763232686d7a6377763037626b6b70686e6b6a353179306b6a633767397277646d30356572776d72326e3874766838796a6e2c010000012b3a537410d6c845cf420fb1e81286ad501e698784de66277cb6ee16429444a8390000000000000031663262326e336173626d3272623939666b316334777030363964307a3931656e78647a386b6d716d713766307738747a7736346864657662",
		data,
	)
	tw.Equal("2140cp9r0rchawvvcvbtkxe440h844xx4h8h1hbcwdpd4tqtcxnjy1vqv", add)
}

func TestPrice(t *testing.T) {
	x, y := "a0860100", "14000000"
	b, _ := hex.DecodeString(x)
	fmt.Println(binary.LittleEndian.Uint32(b))
	b, _ = hex.DecodeString(y)
	fmt.Println(binary.LittleEndian.Uint32(b))
}

func TestNewCDestinationFromAddress(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		wantErr bool
	}{
		// TODO: Add test cases.
		{"pubk", "1jmpqgcvhkmjrca298emrm02zd412zmrd8jc9etgdb1s2p4sn9xa2kjjd", false},
		{"template", "20w09v2efn50pvkncagjb0sxj37e36pfbjjnyzs4zcczy16g7tx7bm6d2", false},
		{"template base32 err", "20w09v2efn50pvkncagjb0sxj37e36pfbjjnyzs4zcczyI6g7tx7bm6d2", true},
		{"pubk validate err", "1jmpqgcvhkmjrca298emrm02zd412zmrd8jc9etgdb1s2p4sn9xa2kjj2", true},
		{"pubk len err", "1jmpqgcvhkmjrca298emrm02zd412zmrd8jc9etgdb1s2p4sn9xa2kjj", true},
		{"template validate err", "20w09v2efn50pvkncagjb0sxj37e36pfbjjnyzs4zcczy16g7tx7bm6d1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCDestinationFromAddress(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCDestinationFromAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestConvertAddress2pubk(t *testing.T) {
	tests := []struct {
		name    string
		args    string
		want    string
		wantErr bool
	}{
		{
			name:    "blank",
			args:    "",
			wantErr: true,
		},
		{
			name: "success",
			args: "1fhtnq5n1b9bte99x5fw0m7cw9jm4n6kgv9nbeynscsgzryvhjf7ny9tm",
			want: "cf93717bfc6166b97ab76ada709a4aa84c9c1d0af82b3d25a7575aa1965b757c",
		},
		{
			name:    "template",
			args:    "20w01rscsdy4p3sdv1g2m1dvp8e2rgxvzze35s0tchcztc0bjsvmew6h4",
			wantErr: true,
		},
		{
			name:    "base32 err",
			args:    "1fhtnq5n1b9bte99x5fw0m7cw9jm4n6kgv9nbeynscsgzryvhjf7nyitm",
			wantErr: true,
		},
		{
			name:    "check err",
			args:    "1fhtnq5n1b9bte99x5fw0m7cw9jm4n6kgv9nbeynscsgzryvhjf7ny9ta",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConvertAddress2pubk(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("ConvertAddress2pubk() error = %v, wantErr %v", err, tt.wantErr)
				return
			} else if err != nil {
				t.Log("err:", err)
			}
			if got != tt.want {
				t.Errorf("ConvertAddress2pubk() = %v, want %v", got, tt.want)
			}
		})
	}
}
