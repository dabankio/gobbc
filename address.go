package gobbc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/blake2b"
)

//some len const
const (
	PubkeyHexLen     = 32*2 + 1
	PrivkeyHexLen    = 32*2 + 1
	PubkeyAddressLen = 57 + 1
	Uint256HexLen    = 65

	templateDexorder = 9

	AddressPrefixPubk = '1'
	AddressPrefixTpl  = '2'

	PrefixPubk     = 1
	PrefixTemplate = 2
)

// AddrKeyPair 地址、私钥、公钥
type AddrKeyPair struct {
	Addr  string
	Privk string
	Pubk  string
}

// MakeKeyPair .
func MakeKeyPair() (AddrKeyPair, error) {
	var pair AddrKeyPair
	pubk, privk, err := ed25519.GenerateKey(nil)
	if err != nil {
		return pair, err
	}

	pair.Pubk = CopyReverseThenEncodeHex(pubk)
	pair.Privk = CopyReverseThenEncodeHex(privk.Seed())

	addr, err := GetPubKeyAddress(pair.Pubk)
	if err != nil {
		return pair, err
	}
	pair.Addr = addr
	return pair, nil
}

// Seed2string 私钥字符串
func Seed2string(seed []byte) string {
	return CopyReverseThenEncodeHex(seed)
}

// Seed2pubk .
func Seed2pubk(seed []byte) ([]byte, error) {
	if l := len(seed); l != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid seed len, %v", l)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), nil
}

// Seed2pubkString .
func Seed2pubkString(seed []byte) (string, error) {
	pubk, err := Seed2pubk(seed)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(reverseBytes(pubk)), nil
}

// PrivateKeyHex2Seed 解析私钥为实际使用的seed
func PrivateKeyHex2Seed(hexedPrivk string) ([]byte, error) {
	b, err := hex.DecodeString(hexedPrivk)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode private key, %v", err)
	}
	return reverseBytes(b), nil
}

// ParsePublicKeyHex 解析私钥为实际使用的seed
func ParsePublicKeyHex(hexedPubK string) ([]byte, error) {
	b, err := hex.DecodeString(hexedPubK)
	if err != nil {
		return nil, fmt.Errorf("failed to hex decode private key, %v", err)
	}
	if l := len(b); l != 32 {
		return nil, fmt.Errorf("invalid public key, invalid len: %d", l)
	}
	return reverseBytes(b), nil
}

// MultisigInfo 多签信息
type MultisigInfo struct {
	Hex     string
	M, N    uint8 //m-n签名,N名成员需要至少M个签名
	Members []MultisigMember
}

// MultisigMember .
type MultisigMember struct {
	Pub    []byte
	Weight uint8
}

// SignTemplatePart 签名时签名的前半部分
func (mi MultisigInfo) SignTemplatePart() []byte {
	b, _ := hex.DecodeString(mi.Hex[4:])
	return b
}

// Pubks 参与签名的公钥列表
func (mi MultisigInfo) Pubks() [][]byte {
	var pubks [][]byte
	for _, m := range mi.Members {
		pubks = append(pubks, m.Pub)
	}
	return pubks
}

// ParsePrivkHex BBC 私钥解析为ed25519.PrivateKey
func ParsePrivkHex(privkHex string) (ed25519.PrivateKey, error) {
	b, err := hex.DecodeString(privkHex)
	if err != nil {
		return nil, err
	}
	seed := CopyReverse(b)
	if l := len(seed); l != ed25519.SeedSize {
		return nil, fmt.Errorf("ed25519: bad seed length: %d", l)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GetPubKeyAddress Get Address hex string from public key hex string
func GetPubKeyAddress(pubk string) (string, error) {
	return EncodeAddress(PrefixPubk, pubk)
}

// EncodeAddress Get Address hex string from public key hex string
func EncodeAddress(prefix uint8, hexed string) (string, error) {
	if len(hexed) != 64 {
		return "", errors.New("invalid address len, should be 64")
	}
	ui := uint256SetHex(hexed)
	return strconv.Itoa(int(prefix)) + Base32Encode(ui[:]), nil
}

// ConvertAddress2pubk .
func ConvertAddress2pubk(address string) (string, error) {
	if address[0] != AddressPrefixPubk {
		return "", errors.New("pubk address should start with 1")
	}
	enc := base32.NewEncoding(base32Alphabet)
	b, err := enc.DecodeString(address[1:])
	if err != nil {
		return "", fmt.Errorf("base32 decode address err, %v", err)
	}
	pubk := hex.EncodeToString(reverseBytes(b))

	validateAddr, err := GetPubKeyAddress(pubk)
	if err != nil {
		return "", fmt.Errorf("校验不通过, %v", err)
	}
	if validateAddr != address {
		return "", fmt.Errorf("校验不通过")
	}
	return pubk[6:], nil //前 3 byte是校验位
}

type Address string

func NewCDestinationFromString(s string) (cd CDestination, err error) {
	if len(s) != 66 { //2*(32+1)
		return cd, errors.New("invalid len, should be 66")
	}
	i, e := strconv.Atoi(s[:2])
	if e != nil {
		return cd, e
	}
	cd.Prefix = uint8(i)
	b, e := hex.DecodeString(s[2:])
	if e != nil {
		return cd, e
	}
	copy(cd.Data[:], b)
	return
}

type CDestination struct {
	Prefix uint8
	Data   [32]byte
}

func (a CDestination) String() string {
	add, _ := EncodeAddress(a.Prefix, hex.EncodeToString(CopyReverse(a.Data[:])))
	return add
}

type VoteTpl struct {
	Delegate CDestination
	Voter    CDestination
}

// DexOrderParam .
type DexOrderParam struct {
	SellerAddress Address `json:"seller_address"`
	Coinpair      string  `json:"coinpair"`
	Price         int64   `json:"price"`
	Fee           int32   `json:"fee"`
	RecvAddress   string  `json:"recv_address"`
	ValidHeight   int32   `json:"valid_height"`
	MatchAddress  Address `json:"match_address"`
	DealAddress   string  `json:"deal_address"`
	Timestamp     uint32  `json:"timestamp"`
}

// CreateTemplateDataDexOrder return tplID, tplData, error
func CreateTemplateDataDexOrder(p DexOrderParam) (string, string, error) {
	buf := bytes.NewBuffer(nil)
	var errs []error

	write := func(v interface{}) {
		if e := binary.Write(buf, binary.LittleEndian, v); e != nil {
			errs = append(errs, e)
		}
	}
	writeAddress := func(add Address) {
		prefix, b, e := GetAddressBytes(string(add))
		if e != nil {
			errs = append(errs, e)
			return
		}
		b = append([]byte{prefix}, b...)
		if _, e = buf.Write(b); e != nil {
			errs = append(errs, e)
		}
	}
	writeString := func(s string) {
		b := []byte(s)
		write(int64(len(b)))
		if _, e := buf.Write(b); e != nil {
			errs = append(errs, e)
		}
	}
	// os << destSeller << vCoinPair << nPrice << nFee << vRecvDest << nValidHeight << destMatch << destDeal;
	write(int16(templateDexorder))
	writeAddress(p.SellerAddress)
	writeString(p.Coinpair)
	write(p.Price)
	write(p.Fee)
	writeString(p.RecvAddress)
	write(p.ValidHeight)
	writeAddress(p.MatchAddress)
	writeString(p.DealAddress)
	write(p.Timestamp)
	if len(errs) != 0 {
		return "", "", fmt.Errorf("some errors when write binary: %v", errs)
	}
	hash := blake2b.Sum256(buf.Bytes()[2:]) //remove type
	x := make([]byte, 2)
	binary.LittleEndian.PutUint16(x, templateDexorder)
	x = append(x, hash[:len(hash)-2]...)
	return string(AddressPrefixTpl) + Base32Encode(x[:]), hex.EncodeToString(buf.Bytes()), nil
}

// GetAddressBytes prefix, pubkOrHash, error
func GetAddressBytes(add string) (byte, []byte, error) {
	switch add[0] {
	case AddressPrefixPubk: //1: pubk address
		pubk, err := ConvertAddress2pubk(add)
		if err != nil {
			return 0, nil, err
		}
		bytes, err := hex.DecodeString(pubk)
		if err != nil {
			return 0, nil, err
		}
		return 1, reverseBytes(bytes), nil
	case AddressPrefixTpl: //模版地址
		enc := base32.NewEncoding(base32Alphabet)
		db, err := enc.DecodeString(add[1:])
		if err != nil {
			return 0, nil, err
		}
		return 2, db[:], nil
	default:
		return 0, nil, errors.New("unknown address type")
	}
}
