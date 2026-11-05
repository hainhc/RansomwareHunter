//go:build windows

package scanner

import (
	"encoding/binary"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var procGetFileInformationByHandleEx = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFileInformationByHandleEx")

const (
	fileIdBothDirectoryInfo        = 10
	fileIdBothDirectoryRestartInfo = 11
	fileListDirectory              = 0x0001
	fileAttributeDirectory         = 0x10
	errNoMoreFiles                 = syscall.Errno(18)
	// FILETIME (100ns từ 1601) → Unix (ns từ 1970).
	filetimeEpochDelta = 116444736000000000
)

// readDir liệt kê thư mục bằng GetFileInformationByHandleEx(FileIdBothDirectoryInfo):
// một handle thư mục (quyền List Folder), trả về tên + FileId + kích thước + thời gian theo lô.
// Trên SMB tương ứng lệnh QUERY_DIRECTORY; không mở file con nào.
func readDir(dir string) ([]entry, error) {
	p, err := syscall.UTF16PtrFromString(longPath(dir))
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(p, fileListDirectory,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(h)

	raw := make([]uint64, 8192) // 64 KiB, căn lề 8 byte
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&raw[0])), len(raw)*8)
	class := uintptr(fileIdBothDirectoryRestartInfo)
	var out []entry
	for {
		r1, _, e1 := procGetFileInformationByHandleEx.Call(uintptr(h), class,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if r1 == 0 {
			if e1 == errNoMoreFiles {
				return out, nil
			}
			return out, e1
		}
		class = fileIdBothDirectoryInfo
		off := 0
		for {
			rec := buf[off:]
			next := binary.LittleEndian.Uint32(rec[0:])
			nameLen := int(binary.LittleEndian.Uint32(rec[60:]))
			u16 := make([]uint16, nameLen/2)
			for k := range u16 {
				u16[k] = binary.LittleEndian.Uint16(rec[104+2*k:])
			}
			name := string(utf16.Decode(u16))
			if name != "." && name != ".." {
				attrs := binary.LittleEndian.Uint32(rec[56:])
				ft := int64(binary.LittleEndian.Uint64(rec[24:]))
				out = append(out, entry{
					name:  name,
					id:    binary.LittleEndian.Uint64(rec[96:]),
					size:  int64(binary.LittleEndian.Uint64(rec[40:])),
					mtime: (ft - filetimeEpochDelta) * 100,
					dir:   attrs&fileAttributeDirectory != 0,
				})
			}
			if next == 0 {
				break
			}
			off += int(next)
		}
	}
}

// longPath thêm tiền tố \\?\ để vượt giới hạn 260 ký tự.
func longPath(p string) string {
	if strings.HasPrefix(p, `\\?\`) {
		return p
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	if strings.HasPrefix(abs, `\\`) {
		return `\\?\UNC\` + abs[2:]
	}
	return `\\?\` + abs
}
