package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"ransomwarehunter/internal/config"
	"ransomwarehunter/internal/syslogconn"
)

// syslogTest đọc các dòng log mẫu (từ capture_file hoặc chép từ Log Center / QuLog) và cho biết
// định dạng đọc được dòng nào, để hiệu chỉnh trước khi trỏ NAS thật vào.
func syslogTest(args []string) error {
	fs := flag.NewFlagSet("syslog-test", flag.ExitOnError)
	format := fs.String("format", "synology", "định dạng có sẵn: synology | qnap, hoặc tên trong custom_formats của -config")
	cfgPath := fs.String("config", "", "file cấu hình (để dùng custom_formats)")
	file := fs.String("file", "", "file chứa các dòng log mẫu")
	_ = fs.Parse(args)
	if *file == "" {
		return errors.New("cần -file")
	}
	f := syslogconn.Builtin[*format]
	if *cfgPath != "" {
		var cfg config.Server
		if err := config.Load(*cfgPath, &cfg); err != nil {
			return err
		}
		if cfg.Syslog != nil {
			for _, cf := range cfg.Syslog.CustomFormats {
				if cf.Name != *format {
					continue
				}
				var err error
				if f, err = syslogconn.NewCustom(cf.Name, cf.Regex, cf.Ops, cf.RenameSep, cf.DirKinds); err != nil {
					return err
				}
			}
		}
	}
	if f == nil {
		return fmt.Errorf("không có định dạng %q", *format)
	}
	b, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	names := map[syslogconn.Status]string{syslogconn.Matched: "OK", syslogconn.Ignored: "BỎ QUA",
		syslogconn.Unmatched: "KHÔNG KHỚP", syslogconn.Incomplete: "THIẾU DỮ LIỆU"}
	count := map[syslogconn.Status]int{}
	for _, line := range strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		// Dòng từ capture_file có dạng "thời gian<TAB>loại<TAB>nguồn<TAB>dòng log".
		if parts := strings.SplitN(line, "\t", 4); len(parts) == 4 {
			line = parts[3]
		}
		p, st := f.Parse(line)
		count[st]++
		if st != syslogconn.Matched {
			fmt.Printf("%-13s %s\n", names[st], line)
			continue
		}
		fmt.Printf("%-13s %-6s %s", names[st], p.Op, p.Path)
		if p.OldPath != "" {
			fmt.Printf("  (cũ: %s)", p.OldPath)
		}
		fmt.Printf("  user=%q ip=%q dir=%v\n", p.User, p.IP, p.IsDir)
	}
	fmt.Printf("\nTổng: %d OK, %d bỏ qua, %d không khớp, %d thiếu dữ liệu (định dạng %s, đã đối chiếu log thật: %v)\n",
		count[syslogconn.Matched], count[syslogconn.Ignored], count[syslogconn.Unmatched], count[syslogconn.Incomplete],
		f.Name, f.Verified)
	return nil
}
