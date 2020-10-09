package gobbc

import (
	"errors"
	"fmt"
	"strings"
)

// RawTransaction 实际的序列话数据结构
// 注意：数据类型不要更改（序列化时对类型有依赖）
type RawTransaction struct {
	Version         uint16
	Typ             uint16 //type > typ
	Timestamp       uint32
	LockUntil       uint32
	HashAnchorBytes [32]byte `json:"-"` // fork id
	SizeIn          uint64   //input 数量
	Input           []byte   `json:"-"`
	Prefix          uint8    //addr prefix
	AddressBytes    [32]byte `json:"-"` // binary data (caller do not care about this field, you just care hex field)
	Amount          int64
	TxFee           int64
	SizeOut         uint64
	VchData         []byte `json:"-"` // binary (caller do not care about this field, you just care hex field)
	SizeSign        uint64 // binary sign data size, ref: https://github.com/bigbangcore/BigBang/wiki/IO-Stream#stdvector-stdmap-stdstring
	SignBytes       []byte `json:"-"` // [template data]sig
}

// Transaction . TODO 增加vout
type Transaction struct {
	RawTransaction
	HashAnchor string // hex string([65]byte)
	Address    string // hex string ([64 + 1]byte)
	Sign       string // hex string
	Vin        []Vin
	Data       string
}
type Vin struct {
	Txid string
	Vout int
}

// TXData 包含了原始交易数据和需要的模版数据，模版数据使用,(英文逗号)分隔
type TXData struct {
	TplHex string `json:"tpl_hex,omitempty"` //成员信息,通过rpc validateaddress (多签模版地址) 取到的值的ret.Addressdata.Templatedata.Hex
	TxHex  string `json:"tx_hex,omitempty"`  //encoded tx data
}

// ContainsMultisig .
func (data *TXData) ContainsMultisig() bool {
	for _, tpl := range strings.Split(data.TplHex, TemplateDataSpliter) {
		if len(tpl) == 0 {
			continue
		}
		if strings.HasPrefix(tpl, TemplateTypeMultisigPrefix) {
			return true
		}
	}
	return false
}

// EncodeString json marshal + hex encode
func (data *TXData) EncodeString() (string, error) {
	return fmt.Sprintf("enc;%s;%s", data.TplHex, data.TxHex), nil
}

// DecodeString parse jsonHex set value to data
func (data *TXData) DecodeString(jsonHex string) error {
	if !strings.HasPrefix(jsonHex, "enc;") {
		return errors.New("Tx data not has prefix: enc")
	}
	arr := strings.Split(jsonHex, ";")
	if len(arr) != 3 {
		return errors.New("tx data invalid format")
	}
	data.TplHex = arr[1]
	data.TxHex = arr[2]
	return nil
}
