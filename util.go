package gobbc

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
)

var Debug bool

// UntilError execute all func until error returned
func UntilError(fns ...func() error) error {
	for _, fn := range fns {
		if e := fn(); e != nil {
			return e
		}
	}
	return nil
}

// CopyReverse copy and reverse []byte
func CopyReverse(bs []byte) []byte {
	s := make([]byte, len(bs))
	copy(s, bs)
	return reverseBytes(s)
}

// reverseBytes reverse []byte s, and return s
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

// CopyReverseThenEncodeHex 复制[]byte,反转后hex.EncodeToString
func CopyReverseThenEncodeHex(bs []byte) string {
	return hex.EncodeToString(CopyReverse(bs))
}

// GetTemplateType 如果解析失败则返回TemplateTypeMin(0)
func GetTemplateType(templateData string) TemplateType {
	b, err := hex.DecodeString(templateData[:4])
	if err != nil {
		return TemplateTypeMin
	}
	v := binary.LittleEndian.Uint16(b)
	return TemplateType(v)
}

func ParseVchData(raw []byte) (*VchData, error) {
	l := len(raw)
	if l < 16+4+1 {
		return nil, errors.New("invlaid vchData len")
	}
	idx := 0
	ret := VchData{}
	copy(ret.uuid[:], raw[idx:16])
	idx += 16
	copy(ret.time[:], raw[idx:idx+4])
	idx += 4
	ret.dataFmtDescSize = raw[idx]
	idx++
	if ret.dataFmtDescSize > 0 {
		if l < idx+int(ret.dataFmtDescSize) {
			return nil, errors.New("invalid vchData len(fmt size)")
		}
		ret.dataFmtDesc = make([]byte, ret.dataFmtDescSize)
		copy(ret.dataFmtDesc, raw[idx:idx+int(ret.dataFmtDescSize)])
		idx += int(ret.dataFmtDescSize)
	}
	ret.data = raw[idx:]
	return &ret, nil
}

// NewVchData .
// dataFmtDesc: eg,JSON BSON MsgPack (为空时表示没有格式)
func NewVchData(dataFmtDesc string, data []byte) (VchData, error) {
	id, err := uuid.NewUUID()
	if err != nil {
		return VchData{}, err
	}
	return NewVchDataWith(id, time.Now(), dataFmtDesc, data)
}

// NewVchDataWith with uuid time
func NewVchDataWith(uuid uuid.UUID, time time.Time, dataFmtDesc string, data []byte) (VchData, error) {
	fmtStr := base64.StdEncoding.EncodeToString([]byte(dataFmtDesc))
	if len(fmtStr) > math.MaxUint8 {
		return VchData{}, errors.New("data format desc to long")
	}
	d := VchData{
		uuid:            uuid,
		dataFmtDescSize: uint8(len(fmtStr)),
		dataFmtDesc:     []byte(fmtStr),
		data:            data,
	}
	binary.LittleEndian.PutUint32(d.time[:], uint32(time.Unix()))
	return d, nil
}

// VchData https://github.com/BigBang-Foundation/BigBang/wiki/通用Tx-VchData系列化定义
type VchData struct {
	uuid            [16]byte
	time            [4]byte
	dataFmtDescSize uint8  //数据格式描述长度
	dataFmtDesc     []byte //数据格式描述
	data            []byte
}

func (vd VchData) Bytes() []byte {
	return bytes.Join([][]byte{
		vd.uuid[:], vd.time[:], {vd.dataFmtDescSize}, vd.dataFmtDesc, vd.data,
	}, nil)
}

func (vd VchData) DataFmtDesc() (string, error) {
	b, e := base64.StdEncoding.DecodeString(string(vd.dataFmtDesc))
	return string(b), e
}

func (vd VchData) RawDataFmtDesc() []byte { return vd.dataFmtDesc }

func (vd VchData) Time() time.Time {
	ui := binary.LittleEndian.Uint32(vd.time[:])
	return time.Unix(int64(ui), 0)
}

func (vd VchData) UUID() uuid.UUID { return vd.uuid }

func (vd VchData) Data() []byte { return vd.data }

// UtilDataEncoding 将tx data 进行编码
func UtilDataEncoding(data []byte) (string, error) {
	vchd, err := NewVchData("", data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(vchd.Bytes()), nil
}
