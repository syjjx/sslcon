package proto

import (
	"encoding/json"
	"errors"

	"github.com/pierrec/lz4/v4"
)

// Compression 表示协商的压缩算法。
// 线上协商值见 String()：oc-lz4 / lzs / deflate（deflate 暂未实现）。
// 数据帧类型：0x00 未压缩，0x08 压缩（见 protocol.go Header 注释）。
type Compression int

const (
	CompNone Compression = iota
	CompLZ4
	CompLZS
	CompDeflate
)

// String 返回线上协商使用的名称（与 openconnect cstp.c 一致）
func (c Compression) String() string {
	switch c {
	case CompLZ4:
		return "oc-lz4"
	case CompLZS:
		return "lzs"
	case CompDeflate:
		return "deflate"
	}
	return "none"
}

// MarshalJSON 让 status 输出可读字符串（如 "lzs"）而非枚举整数
func (c Compression) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

// ParseCompression 解析服务器下发的 X-*-Content-Encoding 值
func ParseCompression(s string) Compression {
	switch s {
	case "oc-lz4":
		return CompLZ4
	case "lzs":
		return CompLZS
	case "deflate":
		return CompDeflate
	}
	return CompNone
}

var (
	errCompressionUnsupported = errors.New("unsupported compression")
	errLZSInputTooShort       = errors.New("lzs: input too short")
	errLZSOutputFull          = errors.New("lzs: output buffer full")
	errLZSInvalid             = errors.New("lzs: invalid sequence")
)

// CompressData 将 src 压缩到 dst，返回压缩后长度。
// 调用方需保证 dst 容量足够（压缩可能略大于原数据）。
func CompressData(c Compression, src, dst []byte) (int, error) {
	switch c {
	case CompLZ4:
		n, err := lz4.CompressBlock(src, dst, nil)
		return n, err
	case CompLZS:
		return lzsCompress(dst, src)
	}
	return 0, errCompressionUnsupported
}

// DecompressData 将 src 解压到 dst，返回解压后长度。
func DecompressData(c Compression, src, dst []byte) (int, error) {
	switch c {
	case CompLZ4:
		return lz4.UncompressBlock(src, dst)
	case CompLZS:
		return lzsDecompress(dst, src)
	}
	return 0, errCompressionUnsupported
}

// ---------------------------------------------------------------------------
// LZS (Cisco Lempel-Ziv-Stac) 实现，逐位移植自 openconnect/lzs.c
// （Copyright © 2008-2015 Intel Corporation, David Woodhouse, LGPL-2.1）
// 位流为 MSB-first，压缩输出以 16 位 0xc000 结束标记收尾。
// ---------------------------------------------------------------------------

const (
	lzsHashBits     = 16
	lzsHashSize     = 1 << lzsHashBits
	lzsMaxHistory   = 1 << 11 // 最高可表示的偏移是 11 位
	lzsInvalidOfs   = 0xffff
	lzsMaxInputSize = lzsInvalidOfs + 1 // 输入限制 64KiB
)

func lzsDecompress(dst, src []byte) (int, error) {
	outlen := 0
	srclen := len(src)
	si := 0
	bitsLeft := 8
	var data uint32

	getBits := func(bits int) error {
		if srclen-si < 2 {
			return errLZSInputTooShort
		}
		if bits >= 8 || bits >= bitsLeft {
			// 需要当前字节剩余的全部位，并推进输入指针
			data = uint32(src[si]) << uint(bits-bitsLeft) & ((1 << uint(bits)) - 1)
			si++
			bitsLeft += 8 - bits
			if bits > 8 || bitsLeft < 8 {
				// 还需要下一个字节的部分位
				data |= uint32(src[si]) >> uint(bitsLeft)
				if bits > 8 && bitsLeft == 0 {
					bitsLeft = 8
					si++
				}
			}
		} else {
			data = uint32(src[si]) >> uint(bitsLeft-bits) & ((1 << uint(bits)) - 1)
			bitsLeft -= bits
		}
		return nil
	}

	for {
		// 读 9 位，这是最小且最常见的单元
		if err := getBits(9); err != nil {
			return 0, err
		}

		// 0bbbbbbbb 是字面字节
		for data < 0x100 {
			if outlen == len(dst) {
				return 0, errLZSOutputFull
			}
			dst[outlen] = byte(data)
			outlen++
			if err := getBits(9); err != nil {
				return 0, err
			}
		}

		// 110000000 是结束标记
		if data == 0x180 {
			return outlen, nil
		}

		// 11bbbbbbb 是 7 位偏移
		offset := uint16(data & 0x7f)

		// 10bbbbbbbbbbb 是 11 位偏移，再读 4 位
		if data < 0x180 {
			if err := getBits(4); err != nil {
				return 0, err
			}
			offset <<= 4
			offset |= uint16(data)
		}

		// 压缩序列，读长度
		if err := getBits(2); err != nil {
			return 0, err
		}
		var length int
		if data != 3 {
			// 00, 01, 10 ==> 2, 3, 4
			length = int(data) + 2
		} else {
			if err := getBits(2); err != nil {
				return 0, err
			}
			if data != 3 {
				// 1100, 1101, 1110 => 5, 6, 7
				length = int(data) + 5
			} else {
				// 每个 1111 前缀加 15，最后加 4 位值
				length = 8
				for {
					if err := getBits(4); err != nil {
						return 0, err
					}
					if data != 15 {
						length += int(data)
						break
					}
					length += 15
				}
			}
		}
		if offset == 0 || int(offset) > outlen {
			return 0, errLZSInvalid
		}
		if length+outlen > len(dst) {
			return 0, errLZSOutputFull
		}

		for length > 0 {
			dst[outlen] = dst[outlen-int(offset)]
			outlen++
			length--
		}
	}
}

func lzsCompress(dst, src []byte) (int, error) {
	if len(src) > lzsMaxInputSize {
		return 0, errLZSOutputFull
	}
	srclen := len(src)
	dstlen := len(dst)
	inpos, outpos := 0, 0

	var (
		longestMatchLen uint16
		hofs, longestMatchOfs uint16
		hashTable   [lzsHashSize]uint16 // 输入缓冲偏移，0xffff 表示无效
		hashChain   [lzsMaxHistory]uint16
		outbits     uint32
		nrOutbits   int
	)

	hashAt := func(p int) uint16 {
		return uint16(src[p]) | uint16(src[p+1])<<8
	}

	putBits := func(nr int, bits uint32) error {
		outbits <<= uint(nr)
		outbits |= bits
		nrOutbits += nr
		if nr > 8 {
			nrOutbits -= 8
			if outpos == dstlen {
				return errLZSOutputFull
			}
			dst[outpos] = byte(outbits >> uint(nrOutbits))
			outpos++
		}
		if nrOutbits >= 8 {
			nrOutbits -= 8
			if outpos == dstlen {
				return errLZSOutputFull
			}
			dst[outpos] = byte(outbits >> uint(nrOutbits))
			outpos++
		}
		return nil
	}

	for i := range hashTable {
		hashTable[i] = lzsInvalidOfs
	}

	for inpos < srclen-2 {
		hash := hashAt(inpos)
		hofs = hashTable[hash]

		hashChain[inpos&(lzsMaxHistory-1)] = hofs
		hashTable[hash] = uint16(inpos)

		if hofs == lzsInvalidOfs || int(hofs)+lzsMaxHistory <= inpos {
			if err := putBits(9, uint32(src[inpos])); err != nil {
				return 0, err
			}
			inpos++
			continue
		}

		// 16 位哈希保证前两个字节匹配
		longestMatchLen = 2
		longestMatchOfs = hofs

		for ; hofs != lzsInvalidOfs && int(hofs)+lzsMaxHistory > inpos; hofs = hashChain[int(hofs)&(lzsMaxHistory-1)] {
			matchLen := int(longestMatchLen) - 1
			if matchLen > 0 && bytesEqual(src[int(hofs)+2:int(hofs)+2+matchLen], src[inpos+2:inpos+2+matchLen]) {
				longestMatchOfs = hofs
				for {
					longestMatchLen++
					if int(longestMatchLen)+inpos == srclen {
						goto gotMatch
					}
					if src[int(longestMatchLen)+inpos] != src[int(longestMatchLen)+int(hofs)] {
						break
					}
				}
			}
		}

	gotMatch:
		offset := inpos - int(longestMatchOfs)
		length := int(longestMatchLen)

		if offset < 0x80 {
			if err := putBits(9, 0x180|uint32(offset)); err != nil {
				return 0, err
			}
		} else {
			if err := putBits(13, 0x1000|uint32(offset)); err != nil {
				return 0, err
			}
		}

		if length < 5 {
			if err := putBits(2, uint32(length-2)); err != nil {
				return 0, err
			}
		} else if length < 8 {
			if err := putBits(4, uint32(length+7)); err != nil {
				return 0, err
			}
		} else {
			length += 7
			for length >= 30 {
				if err := putBits(8, 0xff); err != nil {
					return 0, err
				}
				length -= 30
			}
			if length >= 15 {
				if err := putBits(8, 0xf0+uint32(length-15)); err != nil {
					return 0, err
				}
			} else {
				if err := putBits(4, uint32(length)); err != nil {
					return 0, err
				}
			}
		}

		// 如果已经结束，就不必再更新哈希表
		if inpos+int(longestMatchLen) >= srclen-2 {
			inpos += int(longestMatchLen)
			break
		}

		// 首字节已加入哈希表，加入其余部分
		inpos++
		remaining := int(longestMatchLen) - 1
		for remaining > 0 {
			hash := hashAt(inpos)
			hashChain[inpos&(lzsMaxHistory-1)] = hashTable[hash]
			hashTable[hash] = uint16(inpos)
			inpos++
			remaining--
		}
	}

	// 结尾特殊情况
	if inpos == srclen-2 {
		hash := hashAt(inpos)
		hofs = hashTable[hash]

		if hofs != lzsInvalidOfs && int(hofs)+lzsMaxHistory > inpos {
			offset := inpos - int(hofs)
			if offset < 0x80 {
				if err := putBits(9, 0x180|uint32(offset)); err != nil {
					return 0, err
				}
			} else {
				if err := putBits(13, 0x1000|uint32(offset)); err != nil {
					return 0, err
				}
			}
			// 长度 2
			if err := putBits(2, 0); err != nil {
				return 0, err
			}
		} else {
			if err := putBits(9, uint32(src[inpos])); err != nil {
				return 0, err
			}
			if err := putBits(9, uint32(src[inpos+1])); err != nil {
				return 0, err
			}
		}
	} else if inpos == srclen-1 {
		if err := putBits(9, uint32(src[inpos])); err != nil {
			return 0, err
		}
	}

	// 结束标记，附带 7 个零位确保刷出
	if err := putBits(16, 0xc000); err != nil {
		return 0, err
	}

	return outpos, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
