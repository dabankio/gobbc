package gobbc

import (
	"encoding/base64"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestUtilDataEncoding(t *testing.T) {
	x := "hello"
	enc, err := UtilDataEncoding([]byte(x))
	if err != nil {
		t.Fatal(err)
	}
	// 32+8+2+2*5 = 52
	if len(enc) != 52 {
		t.Errorf("should with len 52: %s len: %d", enc, len(enc))
	}
	if !strings.HasSuffix(enc, "0068656c6c6f") {
		t.Error("should has suffix")
	}
}

func TestDataFmt(t *testing.T) {
	for _, s := range []string{
		"json", "JSON", "MsgPack", "BSON", "",
	} {
		fmt.Println(s, base64.StdEncoding.EncodeToString([]byte(s)))
	}
}

func TestParseVchData(t *testing.T) {
	d, err := NewVchData("JSON", []byte(`{"name": "mike"}`)) //16
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseVchData(d.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(d, *p) {
		t.Error("not equal,want:\n", d, "\ngot\n", *p)
	}
	fmtDesc, err := p.DataFmtDesc()
	if err != nil {
		t.Fatal(err)
	}
	if fmtDesc != "JSON" {
		t.Errorf("fmt decode err:got %s", fmtDesc)
	}
	fmt.Println(p.DataFmtDesc())
	fmt.Println(p.Time(), p.UUID())
}
