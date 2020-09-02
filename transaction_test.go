package gobbc

import (
	"fmt"
	"testing"
)

func TestDecodeTx(t *testing.T) {
	// TODO add data field
	for _, tt := range []struct {
		skip       bool
		name       string
		serializer Serializer
		data       string
		tx         Transaction
		txid       string
	}{
		{
			skip:       false,
			name:       "BBC tx",
			serializer: BBCSerializer,
			data:       "010000004aeaed5d00000000701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b00000000002799a49bcd8ca8723aa00aad86cec19d4d095191c20ce44000cfa7f6b09e9ed5d002b8336b3f242db6ecdc939c168f9613b14f0f4fd00418c3c9ba849c14aeaed5d0101f30b1fd894ba3eacf1b2309ce9fcb606892a70604af5791a732df423e47f001d9c64cd1d000000006400000000000000008164f1a77bd0e00f8023ffa2f7e0a76eb795414d9a57eb2f4ce5e9cc730c8103c501e1cbd24fa95312b81d2dc5ef6f60c39a9485819d4fa11bcfdde5f99151c8a4f981e14068ae196ce63ef403bc335ff439a00d1f00cc3e45cfc057354ea408cafad8e1fb769de3672a155545d490813e1c6eeefb7b4dec678e669c5de7e3c20b07",
			txid:       "5dedea4ac48d33229b61a4b7d7f5e8e84833775250cb8fa7091564943b7f8e1f",
			tx: Transaction{
				RawTransaction: RawTransaction{
					Version:   1,
					Typ:       0,
					Timestamp: 1575873098,
					LockUntil: 0,
					SizeIn:    2,
					Amount:    499_999_900,
					TxFee:     100,
				},
				HashAnchor: "00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70",
				Address:    "1yc5hzp4mq8zaswdj62eekz5p0t4jmw309btqj6kk5qt27s3z00embbrg",
				Sign:       "64f1a77bd0e00f8023ffa2f7e0a76eb795414d9a57eb2f4ce5e9cc730c8103c501e1cbd24fa95312b81d2dc5ef6f60c39a9485819d4fa11bcfdde5f99151c8a4f981e14068ae196ce63ef403bc335ff439a00d1f00cc3e45cfc057354ea408cafad8e1fb769de3672a155545d490813e1c6eeefb7b4dec678e669c5de7e3c20b07",
				Vin: []Vin{
					{Vout: 0, Txid: "5dede9096b7ffa0c0044ce201c1995d0d419ec6cd8aa00aa2387cad8bc499a79"},
					{Vout: 1, Txid: "5dedea4ac149a89b3c8c4100fdf4f0143b61f968c139c9cd6edb42f2b336832b"},
				},
			},
		},
		{
			name:       "MKF tx",
			serializer: MKFSerializer,
			data:       "02000000a61a4e5f0000000001e6c1600226855e8aac1e3d60f76e7b326527e4a72620f0f77af2ae86901a4e5f0002030001e21d6d49931304681ac8ed683d8e90dc8eb6793a875d5361b0bb72bdf9601823000000000030750000000000000000",
			tx: Transaction{
				RawTransaction: RawTransaction{
					Version:   2,
					Typ:       0,
					Timestamp: 1598954150,
					LockUntil: 0,
					Amount:    2300000,
					SizeIn:    1,
					TxFee:     30000,
				},
				HashAnchor: "0000000000000000000000000000000000000000000000000000000000000000",
				Address:    "20c003rgxdn4s64r4d0dchvb87p791q4epswkn1txadgv1evjqqwk97tv",
				Vin: []Vin{
					{"5f4e1a9086aef27af7f02026a7e42765327b6ef7603d1eac8a5e85260260c1e6", 0},
				},
			},
			txid: "5f4e1aa697bcccd1a215c94a58c3acc5cd60330bd27f70cf04147605db680195",
		},
	} {
		if tt.skip {
			continue
		}
		w := TW{T: t}
		tx, err := DecodeRawTransaction(tt.serializer, tt.data, true)
		if err != nil {
			t.Fatal(err)
		}
		w.
			Equal(tt.tx.Version, tx.Version).
			Equal(tt.tx.Typ, tx.Typ).
			Equal(tt.tx.Timestamp, tx.Timestamp).
			Equal(tt.tx.LockUntil, tx.LockUntil).
			Equal(tt.tx.HashAnchor, tx.HashAnchor).
			Equal(tt.tx.Address, tx.Address).
			Equal(tt.tx.SizeIn, tx.SizeIn).
			Equal(tt.tx.Amount, tx.Amount).
			Equal(tt.tx.TxFee, tx.TxFee).
			Equal(len(tt.tx.Vin), len(tx.Vin)).
			Equal(tt.tx.Sign, tx.Sign)

		for i, in := range tt.tx.Vin {
			w.Equal(in.Txid, tx.Vin[i].Txid)
			w.Equal(in.Vout, tx.Vin[i].Vout)
		}
		txid, err := tx.Txid(tt.serializer)
		w.Nil(err)
		w.Equal(tt.txid, txid)
	}

}

func TestTransactionDecodeEncode(t *testing.T) {
	tw := TW{T: t}
	{
		signedTxHexData := "010000008d31d65d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc000000000191b5093377f21fc5a76435351504ce5eae7591380cc3502672fb23c2f230d65d00016f757a33cf3b4f83f2b37b2308090f949c6f3870d50ceb3e5aa59b3118c66d7240420f0000000000640000000000000000816f757a33cf3b4f83f2b37b2308090f949c6f3870d50ceb3e5aa59b3118c66d720100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14fa178a313c5800bebda19cff9e745a346725838c9b5ecb388797bc04a21bca4a9077dc2140b805b6816ab2a35e692821b7904dcd8bbd52f14c7e5c095b1f20308"
		tx, err := DecodeRawTransaction(BBCSerializer, signedTxHexData, true)
		tw.Continue(false).Nil(err)

		serializedHex, err := tx.Encode(BBCSerializer, true)
		tw.Nil(err).
			Continue(true).
			Equal(signedTxHexData, serializedHex, "encode with sign data failed")
	}

	{ //测试签名
		createdTxHexData1 := "010000005948d75d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc0000000002e563f10b18dc361305815da5b464ae6af0a39e5ef2dccf1a74e63b219781d65d00a43970696b5c1b39b0bf4bc0b68df5fb993213c367709a0b3cd9b42c8d31d65d000100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14f40420f000000000064000000000000000000"
		privkHex := "3a7a45f05643fa2e7eeb11da2e2c66e43ddf4f7535dccbb3e6c07fb39201b1df"
		signedTxHexData1 := "010000005948d75d0000000069c07b268573a89eb2bf00a895d0ccd557b83af5490e15ca8d41dedc0000000002e563f10b18dc361305815da5b464ae6af0a39e5ef2dccf1a74e63b219781d65d00a43970696b5c1b39b0bf4bc0b68df5fb993213c367709a0b3cd9b42c8d31d65d000100815a6d40702a7da0a810de9ba76091cf0f7df0b7b56b7a6ef280c9ff26c14f40420f0000000000640000000000000000400d6c650009275f9fa4f64cbd4712e995f84f00f96d056b4610d983c8d0cbad8aefcf75dbfa3f9afaf4bd27e9062f96a2fbc8a98a4feb796bfde547dcb9836b0c"
		tx, err := DecodeRawTransaction(BBCSerializer, createdTxHexData1, false)
		tw.Continue(false).Nil(err)

		err = tx.SignWithPrivateKey(BBCSerializer, "", privkHex)
		tw.Continue(false).Nil(err)

		data, err := tx.Encode(BBCSerializer, true)

		tw.Continue(false).Nil(err).
			Continue(true).Equal(signedTxHexData1, data)
	}

}

func TestTxid(t *testing.T) {
	tw := TW{T: t}
	txData := "01000000f11de55d00000000701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b000000000014919fa098ca5acd9e990349c605f679b370d587086fa6428339415eff11de55d01017c755b96a15a57a7253d2bf80a1d9c4ca84a9a70da6ab77ab96661fc7b7193cf1027000000000000640000000000000000400cb19f280e587741bb1bd9c5803e7867e1995419fa2acc35a8f669cf70596276ccc7a2397940796d6356f5ad7d41778dbca06db1132546167e9f9d23cdb5f806"
	tx, err := DecodeRawTransaction(BBCSerializer, txData, true)
	tw.Nil(err)
	txid, err := tx.Txid(BBCSerializer)
	tw.Nil(err)
	tw.Equal("5de51df120c2762e6590be7c3bf259d61c50995202ff6e3c646144705538ea30", txid)
}

func TestTXBuilder(t *testing.T) {
	w := TW{T: t}
	createTX := "01000000dbb7cc5e00000000701af4705c5e6fcb04efc3ca3c851c1e4d8948e10923025f54bea9b0000000000182e7a2ae807032941897bd7e01a3221b91cdb63f0a2d64dcad937c9f98e3c55e01017c755b96a15a57a7253d2bf80a1d9c4ca84a9a70da6ab77ab96661fc7b7193cfb0c412000000000010270000000000000000"
	tx, err := NewTXBuilder().
		SetAnchor("00000000b0a9be545f022309e148894d1e1c853ccac3ef04cb6f5e5c70f41a70").
		SetTimestamp(1590474715).
		SetVersion(1).
		SetLockUntil(0).
		AddInput("5ec5e3989f7c93addc642d0a3fb6cd911b22a3017ebd971894327080aea2e782", 1).
		SetAddress("1fhtnq5n1b9bte99x5fw0m7cw9jm4n6kgv9nbeynscsgzryvhjf7ny9tm").
		SetAmount(1.23).
		SetFee(0.01).
		Build()
	w.Nil(err)
	encodeTX, err := tx.Encode(BBCSerializer, false)
	w.Nil(err).Equal(createTX, encodeTX)
}

func TestEncodeTX(t *testing.T) {
	w := TW{T: t}
	d := `010000001a8bd05e0000000032bde886ac78e6936fcf79f175dde0b1ba75b3f05984ec941077d0d2951100000183e9f785c685d20f2996b0995517eb1ca585341bfef2e38abdcb7d21c5d5cf5e00013ec340e16d2359548755d181d36eaaaa16629e0e312d051e0f89a8d4617cefe7008c86470000000010270000000000001a16190bd33d8742fc99056ca40cb3e3d51a8bd05e00313131313140fca924b45ea0328bc08110741af079c5f39b5218fab3e10645871e45f70c9daa143178952447699e9c6bcf179ab0dcdd62034a186386e17babc8aef8a7d69800`
	rtx, err := DecodeRawTransaction(BBCSerializer, d, true)
	w.Nil(err)
	tx := rtx.ToTransaction(true)
	fmt.Println(JSONIndent(tx))
}
