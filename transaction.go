package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"github.com/shopspring/decimal"
	"golang.org/x/crypto/blake2b"
)

// DecodeRawTransaction hexed tx parse
func DecodeRawTransaction(serializer Serializer, txData string, decodeSignData bool) (*Transaction, error) {
	b, err := hex.DecodeString(txData)
	if err != nil {
		return nil, fmt.Errorf("hex decode tx data failed, %v", err)
	}
	rtx, err := serializer.Deserialize(b)
	if err != nil {
		return nil, err
	}
	if !decodeSignData {
		rtx.SizeSign = 0
		rtx.SignBytes = []byte{}
	}
	tx := rtx.ToTransaction(decodeSignData)
	return &tx, nil
}

// ToTransaction .
func (rtx RawTransaction) ToTransaction(includeSignData bool) Transaction {
	tx := Transaction{RawTransaction: rtx}
	tx.HashAnchor = hex.EncodeToString(CopyReverse(tx.HashAnchorBytes[:]))
	tx.Address, _ = EncodeAddress(tx.Prefix, hex.EncodeToString(CopyReverse(tx.AddressBytes[:])))
	if includeSignData {
		tx.Sign = hex.EncodeToString(tx.SignBytes)
	}
	tx.Data = hex.EncodeToString(tx.VchData)
	cursor := 0
	for i := 0; i < int(tx.SizeIn); i++ {
		tx.Vin = append(tx.Vin, Vin{
			Txid: hex.EncodeToString(CopyReverse(tx.Input[cursor : cursor+32])),
			Vout: int(tx.Input[cursor+32:][0]),
		})
		cursor = cursor + 33
	}
	return tx
}

// Encode .
func (rtx *RawTransaction) Encode(serializer Serializer, encodeSignData bool) (string, error) {
	b, err := rtx.EncodeBytes(serializer, encodeSignData)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// EncodeBytes .
func (rtx *RawTransaction) EncodeBytes(serializer Serializer, encodeSignData bool) ([]byte, error) {
	tx := *rtx
	if !encodeSignData {
		tx.SizeSign = 0
		tx.SignBytes = []byte{}
	}
	return serializer.Serialize(tx)
}

// Txid serialize tx -> blake2bSum256 -> reverse(got x) -> replace [0:4] with timestamp(bigEndian) -> hex encode
func (rtx *RawTransaction) Txid(serializer Serializer) (string, error) {
	msg, err := serializer.Serialize(*rtx)
	if err != nil {
		return "", fmt.Errorf("serialize tx err, %v", err)
	}
	hash := blake2b.Sum256(msg)
	b := reverseBytes(hash[:])
	binary.BigEndian.PutUint32(b[:], uint32(rtx.Timestamp))
	return hex.EncodeToString(b[:]), nil
}

// TxHash 计算tx hash, tx hash用于签名，签名本质上对txHash 进行ed25519签名
func (rtx *RawTransaction) TxHash(serializer Serializer) ([32]byte, error) {
	msg, err := rtx.EncodeBytes(serializer, false)
	if err != nil {
		return [32]byte{}, fmt.Errorf("failed to encode tx to sign msg, %v", err)
	}
	msg = msg[:len(msg)-1]
	// fmt.Println("[dbg] encoded tx bytes:", msg)
	return blake2b.Sum256(msg), nil
}

// SignWithPrivateKey 用私钥签名
// templateDataList: 使用[,]分隔的模版数据列表，
// - 对于不需要模版数据的交易传入空字符串即可，
// - 如果传入了模版数据签名后会将模版数据按照顺序放在签名前面，
// - 如果传入的模版数据检测到多重签名则在签名时使用多重签名机制
//
// 通常，在from为模版地址时需要传入from的模版数据，可以通过rpc validateaddress 获取(data.addressdata.templatedata.hex)
// 当to地址为vote类型模版地址时需要传入to地址模版数据
// 特别的，只有1种情况需要传入2个模版地址：delegate类型模版的owner为多签地址，从该地址转出时需要传入：delegate模版数据,多签模版数据
// （基于上面一种情况，如果转出地址为vote template可能还需要提供vote template data, 一共3个😂，这个未经测试、验证）
//
// 下面列出常见的场景：
// 一般公钥地址转出(到非vote template)->(不需要模版数据)
// 一般公钥地址投票时->投票模版数据
// 一般公钥投票赎回时->投票模版数据
// 多签地址签名（转账到一般地址)->多签模版数据
// 从dpos委托模版地址转出->委托模版数据
// 从dpos委托模版(owner为多签)地址转出->委托模版数据+多签模版数据
// 从pow挖矿模版地址转出->pow挖矿模版地址
//
// 注意：签名逻辑不对模版数据进行严格合理的校验，因为离线环境下无法感知模版数据的有效性，调用方需自行确保参数正确
func (rtx *RawTransaction) SignWithPrivateKey(serializer Serializer, templateDataList, privkHex string) error {
	var rawTemplateBytes []byte //移除每个模版的前2个byte（类型说明），并join
	var multisigTemplateData string

	for _, tpl := range strings.Split(templateDataList, TemplateDataSpliter) {
		if len(tpl) == 0 {
			continue
		}
		_b, err := hex.DecodeString(tpl)
		if err != nil {
			return fmt.Errorf("unable to decode template data: %v", err)
		}
		rawTemplateBytes = append(rawTemplateBytes, _b[2:]...) //前2位为模版类型
		if GetTemplateType(tpl) == TemplateTypeMultisig {
			multisigTemplateData = tpl
		}
	}

	if multisigTemplateData == "" && len(rtx.SignBytes) > 0 { //非多签确已经有签名数据了
		return errors.New("seems tx already signed")
	}
	privk, err := ParsePrivkHex(privkHex)
	if err != nil {
		return fmt.Errorf("unable to parse private key from hex data")
	}
	txHash, err := rtx.TxHash(serializer)
	if err != nil {
		return fmt.Errorf("calculate txid failed, %v", err)
	}

	if multisigTemplateData == "" { //单签
		sigBytes := ed25519.Sign(privk, txHash[:])
		if len(rawTemplateBytes) > 0 {
			rtx.SignBytes = append(rawTemplateBytes, sigBytes...)
		} else {
			rtx.SignBytes = sigBytes
		}
		rtx.SizeSign = uint64(len(rtx.SignBytes))
		return nil
	}

	// 对于多重签名，首次签名时签名数据应该为空
	// 非首次签名时，应包含模版数据和已有签名数据，模版数据应该以传入的为准并且和已有的签名模版数据一致
	// 每个私钥签名时，重新拼装签名数据
	var sigPart []byte
	_ls, _lt := len(rtx.SignBytes), len(rawTemplateBytes)
	if _ls > 0 { //已有签名数据
		// 首先检查签名数据中的模版数据与传入的模版数据一致
		if _ls < _lt {
			return fmt.Errorf("多签数据检查异常，现有签名长度(%d)小于传入的模版长度(%d)", _ls, _lt)
		}
		if !bytes.Equal(rawTemplateBytes, rtx.SignBytes[:_lt]) {
			// fmt.Println("[dbg]", hex.EncodeToString(rawTemplateBytes))
			// fmt.Println("[dbg]", hex.EncodeToString(rtx.SignBytes[:_lt]))
			return fmt.Errorf("多签数据检查异常，现有签名模版数据与传入的不一致")
		}
		sigPart = make([]byte, _ls-_lt)
		copy(sigPart, rtx.SignBytes[_lt:])
	}
	// 含多签的签名结构: | 模版数据 | 成员签名 ｜

	multisigInfo, err := ParseMultisigTemplateHex(multisigTemplateData)
	if err != nil {
		return fmt.Errorf("failed to parse multisig template data, %v", err)
	}
	sig, err := CryptoMultiSign(multisigInfo.Pubks(), privk, txHash[:], sigPart)
	if err != nil {
		return fmt.Errorf("CryptoMultiSign error, %v", err)
	}
	rtx.SignBytes = append(rawTemplateBytes, sig...)
	rtx.SizeSign = uint64(len(rtx.SignBytes))
	return nil
}

// TXBuilder .
type TXBuilder struct {
	rtx *RawTransaction
	err error
}

func NewTXBuilder() *TXBuilder {
	return &TXBuilder{
		rtx: &RawTransaction{
			Version: 1,
			Typ:     0, //token

		},
	}
}

// return b.err != nil
func (b *TXBuilder) setErr(e error) bool {
	if b.err == nil {
		b.err = e
	}
	return b.err != nil
}

// SetAnchor 锚定分支id
func (b *TXBuilder) SetAnchor(anchor string) *TXBuilder {
	bytes, err := hex.DecodeString(anchor)
	if err != nil {
		b.setErr(fmt.Errorf("hex decode anchor failed, %v", err))
		return b
	}
	if len(bytes) != 32 {
		b.setErr(fmt.Errorf("%s 似乎不是合法的 anchor,长度不是32", anchor))
		return b
	}
	copy(b.rtx.HashAnchorBytes[:], reverseBytes(bytes))
	return b
}

// SetTimestamp 当前时间戳
func (b *TXBuilder) SetTimestamp(timestamp int) *TXBuilder {
	b.rtx.Timestamp = uint32(timestamp)
	return b
}

// SetLockUntil lock until
func (b *TXBuilder) SetLockUntil(lockUntil int) *TXBuilder {
	b.rtx.LockUntil = uint32(lockUntil)
	return b
}

// SetVersion 当前版本 1
func (b *TXBuilder) SetVersion(v int) *TXBuilder {
	b.rtx.Version = uint16(v)
	return b
}

// SetType tx type
func (b *TXBuilder) SetType(v int) *TXBuilder {
	b.rtx.Typ = uint16(v)
	return b
}

// AddInput 参考listunspent,确保输入金额满足amount
func (b *TXBuilder) AddInput(txid string, vout uint8) *TXBuilder {
	bytes, err := hex.DecodeString(txid)
	if err != nil {
		b.setErr(fmt.Errorf("%s 似乎不是合法的txid, %v", txid, err))
		return b
	}
	b.rtx.SizeIn++
	input := append(reverseBytes(bytes), vout)
	b.rtx.Input = append(b.rtx.Input, input...)
	return b
}

// SetAddress 转账地址
func (b *TXBuilder) SetAddress(add string) *TXBuilder {
	switch add[0] {
	case AddressPrefixPubk, AddressPrefixTpl: //1: pubk address, 2: 模版地址
		prefix, pubkOrHash, err := GetAddressBytes(add)
		if b.setErr(err) {
			return b
		}
		b.rtx.Prefix = prefix
		copy(b.rtx.AddressBytes[:], pubkOrHash)
	default:
		b.setErr(errors.New("unknown address type"))
	}

	return b
}

// SetAmount 转账金额
func (b *TXBuilder) SetAmount(amount float64) *TXBuilder {
	if amount < 0 {
		b.setErr(fmt.Errorf("amount should be greater than 0"))
		return b
	}
	b.rtx.Amount = decimal.NewFromFloat(amount).Mul(decimal.NewFromInt(Precision)).IntPart()
	return b
}

// SetFee 手续费，目前0.01，如果带data则0.03, 额外需咨询BBC
func (b *TXBuilder) SetFee(fee float64) *TXBuilder {
	if fee < 0 {
		b.setErr(fmt.Errorf("amount should be greater than 0"))
		return b
	}
	b.rtx.TxFee = decimal.NewFromFloat(fee).Mul(decimal.NewFromInt(Precision)).IntPart()
	return b
}

// SetRawData https://github.com/BigBang-Foundation/BigBang/wiki/通用Tx-vchData系列化定义,
// 原始data设置,不自动填充任何数据（不自动提供uuid time format数据）
func (b *TXBuilder) SetRawData(data []byte) *TXBuilder {
	b.rtx.SizeOut = uint64(len(data))
	b.rtx.VchData = data
	return b
}

// SetDataWith 指定uuid,timestamp,data
func (b *TXBuilder) SetDataWith(_uuid string, timestamp int64, dataFmt string, data []byte) *TXBuilder {
	_id, err := uuid.Parse(_uuid)
	if err != nil {
		b.setErr(errors.Wrap(err, "parse uuid failed"))
		return b
	}
	vd, err := NewVchDataWith(_id, time.Unix(timestamp, 0), dataFmt, data)
	if err != nil {
		b.setErr(errors.Wrap(err, "new vch data err"))
		return b
	}
	return b.SetRawData(vd.Bytes())
}

// SetData 自动编码数据,自动生成uuid和时间戳,不带格式描述
func (b *TXBuilder) SetData(data []byte) *TXBuilder {
	vd, err := NewVchData("", data)
	if err != nil {
		b.setErr(errors.Wrap(err, "new vch data err"))
		return b
	}
	return b.SetRawData(vd.Bytes())
}

// Build .
func (b *TXBuilder) Build() (*RawTransaction, error) {
	if b.rtx.SizeIn == 0 {
		return nil, errors.New("no input provided")
	}
	if b.rtx.Amount == 0 {
		return nil, errors.New("amount not set")
	}
	if b.rtx.TxFee == 0 {
		return nil, errors.New("tx fee not set")
	}

	{ //不再检查forkID, MKF不需要这个
		// noZeroFound := true
		// for i := 0; i < 32; i++ {
		// 	if b.rtx.HashAnchorBytes[i] != 0 {
		// 		noZeroFound = false
		// 		break
		// 	}
		// }
		// if noZeroFound {
		// 	return nil, errors.New("fork id not provided")
		// }
	}
	if b.err != nil {
		return nil, b.err
	}
	return b.rtx, nil
}
