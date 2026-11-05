// Package usn đọc NTFS USN Journal (Windows File Server, host Windows mount LUN SAN).
// USN Journal là nhật ký thay đổi metadata của volume: tên file, thư mục cha, lý do thay đổi.
// Đọc journal không mở file nào và không đọc nội dung file.
package usn

import (
	"encoding/binary"
	"fmt"
	"time"
	"unicode/utf16"
)

// Các cờ lý do (USN_REASON_*).
const (
	ReasonDataOverwrite  = 0x00000001
	ReasonDataExtend     = 0x00000002
	ReasonDataTruncation = 0x00000004
	ReasonFileCreate     = 0x00000100
	ReasonFileDelete     = 0x00000200
	ReasonRenameOldName  = 0x00001000
	ReasonRenameNewName  = 0x00002000
	ReasonClose          = 0x80000000

	reasonData = ReasonDataOverwrite | ReasonDataExtend | ReasonDataTruncation

	attrDirectory = 0x10
	// FILETIME (100ns từ 1601) → Unix (100ns từ 1970).
	filetimeEpochDelta = 116444736000000000
)

// Record là một bản ghi USN_RECORD_V2.
type Record struct {
	FRN       uint64
	ParentFRN uint64
	USN       int64
	TS        time.Time
	Reason    uint32
	Attr      uint32
	Name      string
}

// IsDir cho biết bản ghi thuộc về thư mục.
func (r Record) IsDir() bool { return r.Attr&attrDirectory != 0 }

// ParseRecords tách các bản ghi trong buf (sau 8 byte đầu là USN/FRN tiếp theo).
// Bản ghi phiên bản khác V2 (ReFS dùng V3) được bỏ qua và đếm trong skipped.
func ParseRecords(buf []byte) (recs []Record, skipped int, err error) {
	for off := 0; off+8 <= len(buf); {
		length := int(binary.LittleEndian.Uint32(buf[off:]))
		if length == 0 {
			break
		}
		if length < 8 || off+length > len(buf) {
			return recs, skipped, fmt.Errorf("bản ghi USN hỏng tại offset %d (len %d)", off, length)
		}
		rec := buf[off : off+length]
		off += length
		if binary.LittleEndian.Uint16(rec[4:]) != 2 {
			skipped++
			continue
		}
		if len(rec) < 60 {
			return recs, skipped, fmt.Errorf("bản ghi USN V2 quá ngắn: %d", len(rec))
		}
		nameLen := int(binary.LittleEndian.Uint16(rec[56:]))
		nameOff := int(binary.LittleEndian.Uint16(rec[58:]))
		if nameOff+nameLen > len(rec) {
			return recs, skipped, fmt.Errorf("tên file vượt bản ghi USN")
		}
		u16 := make([]uint16, nameLen/2)
		for i := range u16 {
			u16[i] = binary.LittleEndian.Uint16(rec[nameOff+2*i:])
		}
		ft := int64(binary.LittleEndian.Uint64(rec[32:]))
		recs = append(recs, Record{
			FRN:       binary.LittleEndian.Uint64(rec[8:]),
			ParentFRN: binary.LittleEndian.Uint64(rec[16:]),
			USN:       int64(binary.LittleEndian.Uint64(rec[24:])),
			TS:        time.Unix(0, (ft-filetimeEpochDelta)*100),
			Reason:    binary.LittleEndian.Uint32(rec[40:]),
			Attr:      binary.LittleEndian.Uint32(rec[52:]),
			Name:      string(utf16.Decode(u16)),
		})
	}
	return recs, skipped, nil
}

// EncodeRecord tạo bản ghi USN_RECORD_V2 (dùng cho test và công cụ mô phỏng).
func EncodeRecord(r Record) []byte {
	u16 := utf16.Encode([]rune(r.Name))
	length := 60 + 2*len(u16)
	length = (length + 7) &^ 7
	b := make([]byte, length)
	binary.LittleEndian.PutUint32(b[0:], uint32(length))
	binary.LittleEndian.PutUint16(b[4:], 2)
	binary.LittleEndian.PutUint64(b[8:], r.FRN)
	binary.LittleEndian.PutUint64(b[16:], r.ParentFRN)
	binary.LittleEndian.PutUint64(b[24:], uint64(r.USN))
	binary.LittleEndian.PutUint64(b[32:], uint64(r.TS.UnixNano()/100+filetimeEpochDelta))
	binary.LittleEndian.PutUint32(b[40:], r.Reason)
	binary.LittleEndian.PutUint32(b[52:], r.Attr)
	binary.LittleEndian.PutUint16(b[56:], uint16(2*len(u16)))
	binary.LittleEndian.PutUint16(b[58:], 60)
	for i, c := range u16 {
		binary.LittleEndian.PutUint16(b[60+2*i:], c)
	}
	return b
}
