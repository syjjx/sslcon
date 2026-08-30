package proto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"testing"
)

// 黄金向量由 openconnect/lzs.c 编译的 C 程序生成（lzs_harness.c），
// 用于保证 Go 实现的 LZS 与 openconnect 线上格式逐位一致
var lzsGolden = []struct {
	name  string
	input string // hex
	want  string // 压缩后的 hex（C 实现输出）
}{
	{"hello x3", "68656c6c6f2068656c6c6f2068656c6c6f", "34194d86c378830de780"},
	{"20xA", "4141414141414141414141414141414141414141", "20e07ef000"},
	{"pattern", "00ff10ff20ff30ff40ff50ff60ff70ff80ff90ffa0ff", "003fc20ff103fc60ff203fca0ff303fce0ff403fd20ff503ff00"},
	{"abc", "616263", "30988c7800"},
	{"empty", "", "c000"},
}

func TestLZSGoldenCompress(t *testing.T) {
	for _, g := range lzsGolden {
		t.Run(g.name, func(t *testing.T) {
			src, _ := hex.DecodeString(g.input)
			want, _ := hex.DecodeString(g.want)
			dst := make([]byte, 4096)
			n, err := lzsCompress(dst, src)
			if err != nil {
				t.Fatalf("compress error: %v", err)
			}
			if !bytes.Equal(dst[:n], want) {
				t.Fatalf("压缩结果与 openconnect 不一致\n got: %x\nwant: %x", dst[:n], want)
			}
		})
	}
}

func TestLZSGoldenDecompress(t *testing.T) {
	for _, g := range lzsGolden {
		t.Run(g.name, func(t *testing.T) {
			src, _ := hex.DecodeString(g.input)
			compressed, _ := hex.DecodeString(g.want)
			dst := make([]byte, 4096)
			n, err := lzsDecompress(dst, compressed)
			if err != nil {
				t.Fatalf("decompress error: %v", err)
			}
			if !bytes.Equal(dst[:n], src) {
				t.Fatalf("解压结果与原文不一致\n got: %x\nwant: %x", dst[:n], src)
			}
		})
	}
}

// 随机数据 + 结构化数据往返测试
func TestLZSRoundtrip(t *testing.T) {
	// 模拟 IP 包的特征：头部 + 重复块 + 随机载荷
	inputs := [][]byte{
		{},
		{0x45, 0x00, 0x00, 0x3c},
		bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef}, 64),
		[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" + string(bytes.Repeat([]byte("cookie=abc123; "), 20))),
	}

	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 50; i++ {
		b := make([]byte, rng.Intn(2048))
		if i%3 == 0 {
			// 部分重复数据，制造可压缩性
			for j := range b {
				b[j] = byte(j % 37)
			}
		} else {
			_, _ = rng.Read(b)
		}
		inputs = append(inputs, b)
	}

	for i, input := range inputs {
		compressed := make([]byte, 4096)
		n, err := lzsCompress(compressed, input)
		if err != nil {
			t.Fatalf("case %d compress: %v", i, err)
		}
		restored := make([]byte, 4096)
		m, err := lzsDecompress(restored, compressed[:n])
		if err != nil {
			t.Fatalf("case %d decompress: %v", i, err)
		}
		if m != len(input) || !bytes.Equal(restored[:m], input) {
			t.Fatalf("case %d roundtrip mismatch: len %d != %d", i, m, len(input))
		}
	}
}

// LZ4 往返（block 模式）
func TestLZ4Roundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20; i++ {
		input := make([]byte, rng.Intn(2048))
		if i%2 == 0 {
			for j := range input {
				input[j] = byte('A' + j%26)
			}
		} else {
			_, _ = rng.Read(input)
		}
		compressed := make([]byte, 4096)
		n, err := CompressData(CompLZ4, input, compressed)
		if err != nil {
			t.Fatalf("case %d lz4 compress: %v", i, err)
		}
		if n >= len(input) {
			continue // 不可压缩数据可能不压缩
		}
		restored := make([]byte, 4096)
		m, err := DecompressData(CompLZ4, compressed[:n], restored)
		if err != nil {
			t.Fatalf("case %d lz4 decompress: %v", i, err)
		}
		if !bytes.Equal(restored[:m], input) {
			t.Fatalf("case %d lz4 roundtrip mismatch", i)
		}
	}
}

// ParseCompression 解析
func TestParseCompression(t *testing.T) {
	cases := map[string]Compression{
		"oc-lz4":  CompLZ4,
		"lzs":     CompLZS,
		"deflate": CompDeflate,
		"":        CompNone,
		"garbage": CompNone,
		"LZS":     CompNone, // 服务器不会发大写，但保持严格
	}
	for in, want := range cases {
		if got := ParseCompression(in); got != want {
			t.Errorf("ParseCompression(%q) = %v, want %v", in, got, want)
		}
	}
}

// 压缩枚举 JSON 输出应为可读字符串
func TestCompressionMarshalJSON(t *testing.T) {
	cases := map[Compression]string{
		CompNone:    `"none"`,
		CompLZ4:     `"oc-lz4"`,
		CompLZS:     `"lzs"`,
		CompDeflate: `"deflate"`,
	}
	for in, want := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("Marshal(%v): %v", in, err)
		}
		if string(b) != want {
			t.Errorf("Marshal(%v) = %s, want %s", in, b, want)
		}
	}
}
