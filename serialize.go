package gobbc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"unsafe"
)

var BBCSerializer Serializer = serializer{includeAnchor: true}
var MKFSerializer Serializer = serializer{includeAnchor: false}

// Serializer tx Serializer
type Serializer interface {
	Serialize(RawTransaction) ([]byte, error)
	Deserialize([]byte) (RawTransaction, error)
}

type serializer struct {
	includeAnchor bool
}

func (s serializer) Serialize(rtx RawTransaction) ([]byte, error) {
	buf := bytes.NewBuffer(nil)

	var errs []error

	write := func(v interface{}) {
		if e := binary.Write(buf, binary.LittleEndian, v); e != nil {
			errs = append(errs, e)
		}
	}
	fnWriteSize := func(size uint64) {
		if e := writeSize(size, buf); e != nil {
			errs = append(errs, e)
		}
	}
	write(rtx.Version)
	write(rtx.Typ)
	write(rtx.Timestamp)
	write(rtx.LockUntil)
	if s.includeAnchor {
		buf.Write(rtx.HashAnchorBytes[:])
	}
	fnWriteSize(rtx.SizeIn)

	buf.Write(rtx.Input) //:33*int(rtx.SizeIn)
	write(rtx.Prefix)
	buf.Write(rtx.AddressBytes[:])
	write(rtx.Amount)
	write(rtx.TxFee)
	fnWriteSize(rtx.SizeOut)
	buf.Write(rtx.VchData)
	fnWriteSize(rtx.SizeSign)
	buf.Write(rtx.SignBytes)

	var err error
	if len(errs) != 0 {
		err = fmt.Errorf("some errors when write binary: %v", errs)
	}
	return buf.Bytes(), err
}

func (s serializer) Deserialize(b []byte) (RawTransaction, error) {
	var errs []error
	var err error

	var tx RawTransaction
	buffer := bytes.NewBuffer(b)
	readValue := func(v interface{}) {
		if e := binary.Read(buffer, binary.LittleEndian, v); e != nil {
			if Debug {
				log.Printf("[ERR]解析tx数据时无法读取到字段: %v(%T)\n", v, v)
			}
			errs = append(errs, e)
		}
	}

	var size int
	readValue(&tx.Version)
	readValue(&tx.Typ)
	readValue(&tx.Timestamp)
	readValue(&tx.LockUntil)
	if s.includeAnchor {
		copy(tx.HashAnchorBytes[:], buffer.Next(int(unsafe.Sizeof(tx.HashAnchorBytes))))
	}

	tx.SizeIn, err = readSize(buffer, buffer)
	if err != nil {
		return tx, fmt.Errorf("read input size err, %v", err)
	}

	size = 33 * int(tx.SizeIn)
	tx.Input = make([]byte, size)
	copy(tx.Input, buffer.Next(size))

	readValue(&tx.Prefix)
	copy(tx.AddressBytes[:], buffer.Next(int(unsafe.Sizeof(tx.AddressBytes))))
	readValue(&tx.Amount)
	readValue(&tx.TxFee)
	tx.SizeOut, err = readSize(buffer, buffer)
	if err != nil {
		return tx, fmt.Errorf("read output size err, %v", err)
	}

	size = int(tx.SizeOut)
	tx.VchData = make([]byte, size)
	copy(tx.VchData, buffer.Next(size)) //考虑逻辑是什么？。。。是不是直接表示字节数，而不是out的笔数

	tx.SizeSign, err = readSize(buffer, buffer)
	if err != nil {
		return tx, fmt.Errorf("read signature size err, %v", err)
	}

	size = int(tx.SizeSign)
	tx.SignBytes = make([]byte, size)
	copy(tx.SignBytes, buffer.Next(size))

	if len(errs) != 0 {
		err = fmt.Errorf("some errors when read binary: %v", errs)
	}
	return tx, err
}

func writeSize(size uint64, buf *bytes.Buffer) error {
	switch sz := size; {
	case sz < 0xFD:
		return binary.Write(buf, binary.LittleEndian, uint8(size))
	case sz <= 0xffff:
		buf.WriteByte(0xfd)
		return binary.Write(buf, binary.LittleEndian, uint16(size))
	case sz <= 0xFFFFFFFF:
		buf.WriteByte(0xfe)
		return binary.Write(buf, binary.LittleEndian, uint32(size))
	case sz > 0xFFFFFFFF:
		buf.WriteByte(0xff)
		return binary.Write(buf, binary.LittleEndian, size)
	default:
		return fmt.Errorf("should not here, write size, unexpected size: %d", size)
	}
}
func readSize(reader io.ByteReader, buffer io.Reader) (uint64, error) {
	sizeFlag, err := reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("unable to read size byte, %v", err)
	}
	switch sz := sizeFlag; {
	case sz < 0xfd:
		return uint64(sz), nil
	case sz == 0xfd:
		var size uint16
		e := binary.Read(buffer, binary.LittleEndian, &size)
		return uint64(size), e
	case sz == 0xfe:
		var size uint32
		e := binary.Read(buffer, binary.LittleEndian, &size)
		return uint64(size), e
	case sz == 0xff:
		var size uint64
		e := binary.Read(buffer, binary.LittleEndian, &size)
		return size, e
	default:
		return 0, fmt.Errorf("unexpected size flag %d", sz)
	}
}
