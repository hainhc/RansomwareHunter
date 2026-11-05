// rh-simulator: tạo dữ liệu thử và mô phỏng hành vi đổi đuôi hàng loạt trên thư mục TEST.
// Không mã hóa gì: chỉ đổi tên file (và ở chế độ copydelete thì ghi file mới bằng dữ liệu ngẫu nhiên).
// Mọi lệnh trừ seed chỉ chạy trên thư mục có file đánh dấu do seed tạo ra.
//
//	rh-simulator seed   -dir D:\rh-test -files 20000 -dirs 400
//	rh-simulator attack -dir D:\rh-test -ext .lockbit -rate 1000 -limit 2000 -note Restore-My-Files.txt
//	rh-simulator benign -dir D:\rh-test -from jpg -to jpeg
//	rh-simulator office -dir D:\rh-test -limit 500
//	rh-simulator syslog -target 127.0.0.1:5514 -format synology -files 3000 -rate 3000
package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const marker = ".rh-simulator-testdir"

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "seed":
		err = seed(os.Args[2:])
	case "attack":
		err = attack(os.Args[2:])
	case "benign":
		err = benign(os.Args[2:])
	case "office":
		err = office(os.Args[2:])
	case "syslog":
		err = syslogSim(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "lỗi:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "dùng: rh-simulator seed|attack|benign|office|syslog -h")
	os.Exit(2)
}

var exts = []string{"docx", "xlsx", "pdf", "pptx", "jpg", "png", "txt", "csv", "zip", "dwg"}

func seed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	dir := fs.String("dir", "", "thư mục test (sẽ được tạo)")
	files := fs.Int("files", 2000, "số file")
	dirs := fs.Int("dirs", 40, "số thư mục")
	size := fs.Int("size", 8<<10, "kích thước trung bình mỗi file (byte)")
	_ = fs.Parse(args)
	if *dir == "" {
		return errors.New("cần -dir")
	}
	if entries, err := os.ReadDir(*dir); err == nil && len(entries) > 0 && !isTestDir(*dir) {
		return fmt.Errorf("%s không rỗng và không phải thư mục test", *dir)
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, marker), []byte("RansomwareHunter simulator test directory\n"), 0o644); err != nil {
		return err
	}
	buf := make([]byte, 2**size)
	_, _ = rand.Read(buf)
	start := time.Now()
	for i := 0; i < *files; i++ {
		d := filepath.Join(*dir, fmt.Sprintf("Phong%03d", i%*dirs/10), fmt.Sprintf("Thu muc %03d", i%*dirs))
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
		n := mrand.IntN(2 * *size)
		// Đuôi thay đổi theo cả chỉ số file và thư mục để mỗi thư mục có nhiều loại file.
		name := fmt.Sprintf("Tai lieu %06d.%s", i, exts[(i + i / *dirs)%len(exts)])
		if err := os.WriteFile(filepath.Join(d, name), buf[:n], 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("Đã tạo %d file trong %d thư mục tại %s (%s)\n", *files, *dirs, *dir, time.Since(start).Round(time.Millisecond))
	return nil
}

func attack(args []string) error {
	fs := flag.NewFlagSet("attack", flag.ExitOnError)
	dir := fs.String("dir", "", "thư mục test")
	ext := fs.String("ext", ".lockbit", "phần nối thêm / đuôi mới")
	mode := fs.String("mode", "append", "append (a.docx→a.docx.ext) | replace (a.docx→a.ext) | random (đuôi ngẫu nhiên từng file) | copydelete (ghi file mới rồi xóa file gốc)")
	rate := fs.Int("rate", 1000, "số file/phút (0 = nhanh nhất có thể)")
	limit := fs.Int("limit", 0, "số file tối đa (0 = tất cả)")
	note := fs.String("note", "Restore-My-Files.txt", "tên ransom note tạo trong mỗi thư mục (rỗng = không tạo)")
	_ = fs.Parse(args)
	files, err := targets(*dir, *limit)
	if err != nil {
		return err
	}
	var delay time.Duration
	if *rate > 0 {
		delay = time.Minute / time.Duration(*rate)
	}
	noted := map[string]bool{}
	start := time.Now()
	fmt.Printf("Bắt đầu mô phỏng lúc %s: %d file, chế độ %s\n", start.Format("15:04:05.000"), len(files), *mode)
	for i, p := range files {
		d := filepath.Dir(p)
		if *note != "" && !noted[d] {
			noted[d] = true
			_ = os.WriteFile(filepath.Join(d, *note), []byte("Simulated ransom note - RansomwareHunter test\n"), 0o644)
		}
		var np string
		switch *mode {
		case "append", "copydelete":
			np = p + *ext
		case "replace":
			np = strings.TrimSuffix(p, filepath.Ext(p)) + *ext
		case "random":
			np = p + "." + randExt()
		default:
			return fmt.Errorf("mode không hợp lệ: %s", *mode)
		}
		if *mode == "copydelete" {
			fi, err := os.Stat(p)
			if err != nil {
				continue
			}
			b := make([]byte, fi.Size()+512)
			_, _ = rand.Read(b)
			if err := os.WriteFile(np, b, 0o644); err != nil {
				return err
			}
			if err := os.Remove(p); err != nil {
				return err
			}
		} else if err := os.Rename(p, np); err != nil {
			return err
		}
		if delay > 0 {
			next := start.Add(time.Duration(i+1) * delay)
			time.Sleep(time.Until(next))
		}
	}
	fmt.Printf("Xong lúc %s: %d file, %d ransom note, %s\n", time.Now().Format("15:04:05.000"),
		len(files), len(noted), time.Since(start).Round(time.Millisecond))
	return nil
}

func benign(args []string) error {
	fs := flag.NewFlagSet("benign", flag.ExitOnError)
	dir := fs.String("dir", "", "thư mục test")
	from := fs.String("from", "jpg", "đuôi gốc")
	to := fs.String("to", "jpeg", "đuôi mới")
	_ = fs.Parse(args)
	files, err := targets(*dir, 0)
	if err != nil {
		return err
	}
	n := 0
	for _, p := range files {
		if strings.EqualFold(filepath.Ext(p), "."+*from) {
			if err := os.Rename(p, strings.TrimSuffix(p, filepath.Ext(p))+"."+*to); err != nil {
				return err
			}
			n++
		}
	}
	fmt.Printf("Đổi đuôi hợp lệ %d file .%s → .%s\n", n, *from, *to)
	return nil
}

// office mô phỏng cách Word lưu file: đổi tên bản gốc thành ~WRL*.tmp, ghi ~WRD*.tmp, đổi tên về tên gốc.
func office(args []string) error {
	fs := flag.NewFlagSet("office", flag.ExitOnError)
	dir := fs.String("dir", "", "thư mục test")
	limit := fs.Int("limit", 500, "số file docx")
	_ = fs.Parse(args)
	files, err := targets(*dir, 0)
	if err != nil {
		return err
	}
	n := 0
	for _, p := range files {
		if n >= *limit || !strings.EqualFold(filepath.Ext(p), ".docx") {
			continue
		}
		d := filepath.Dir(p)
		wrl, wrd := filepath.Join(d, "~WRL0001.tmp"), filepath.Join(d, "~WRD0000.tmp")
		if err := os.WriteFile(wrd, []byte("new version"), 0o644); err != nil {
			return err
		}
		if err := os.Rename(p, wrl); err != nil {
			return err
		}
		if err := os.Rename(wrd, p); err != nil {
			return err
		}
		if err := os.Remove(wrl); err != nil {
			return err
		}
		n++
	}
	fmt.Printf("Mô phỏng lưu Office cho %d file\n", n)
	return nil
}

func targets(dir string, limit int) ([]string, error) {
	if dir == "" {
		return nil, errors.New("cần -dir")
	}
	if !isTestDir(dir) {
		return nil, fmt.Errorf("%s không có file đánh dấu %s; chỉ chạy trên thư mục do lệnh seed tạo", dir, marker)
	}
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == marker || strings.HasPrefix(d.Name(), "Restore-") || strings.HasPrefix(d.Name(), "!") || strings.HasPrefix(d.Name(), "000_") {
			return nil
		}
		out = append(out, p)
		return nil
	})
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, err
}

func isTestDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, marker))
	return err == nil
}

func randExt() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	for i := range b {
		b[i] = letters[mrand.IntN(len(letters))]
	}
	return string(b)
}
