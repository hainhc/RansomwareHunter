//go:build !windows

package scanner

import (
	"os"
	"syscall"
)

// readDir liệt kê thư mục và lấy inode/kích thước/mtime bằng lstat.
// Trên NFS, client dùng READDIRPLUS nên thuộc tính thường đã có sẵn trong cache của lần liệt kê.
func readDir(dir string) ([]entry, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil && len(des) == 0 {
		return nil, err
	}
	out := make([]entry, 0, len(des))
	for _, de := range des {
		info, err := de.Info()
		if err != nil {
			continue // mục vừa biến mất giữa readdir và lstat
		}
		e := entry{name: de.Name(), size: info.Size(), mtime: info.ModTime().UnixNano(), dir: de.IsDir()}
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			e.id = uint64(st.Ino)
		}
		out = append(out, e)
	}
	return out, nil
}
