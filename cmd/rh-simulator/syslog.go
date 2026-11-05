package main

import (
	"flag"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"time"
)

// syslogSim gửi dòng log thao tác file giả lập (định dạng Synology/QNAP) tới rh-server, gồm
// lưu lượng bình thường của nhiều người dùng và một cuộc đổi đuôi hàng loạt của một tài khoản.
// Không chạm vào file nào; chỉ để kiểm thử connector syslog khi chưa có NAS thật.
func syslogSim(args []string) error {
	fs := flag.NewFlagSet("syslog", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1:5514", "địa chỉ syslog của rh-server")
	network := fs.String("network", "udp", "udp hoặc tcp")
	format := fs.String("format", "synology", "synology | qnap")
	host := fs.String("host", "syno01", "hostname NAS trong header syslog")
	share := fs.String("share", "KeToan", "tên share")
	files := fs.Int("files", 3000, "số file bị đổi đuôi")
	rate := fs.Int("rate", 3000, "số file/phút")
	ext := fs.String("ext", ".dmr64", "phần nối thêm")
	user := fs.String("user", `CORP\user01`, "tài khoản thực hiện đổi đuôi")
	ip := fs.String("ip", "10.10.5.23", "IP máy trạm thực hiện đổi đuôi")
	note := fs.String("note", "HOW_TO_RECOVER_FILES.txt", "ransom note mỗi thư mục (rỗng = không)")
	noise := fs.Int("noise", 5, "số dòng read/write bình thường của người dùng khác cho mỗi file bị đổi")
	_ = fs.Parse(args)

	c, err := net.Dial(*network, *target)
	if err != nil {
		return err
	}
	defer c.Close()
	send := func(op, path, newPath, kind, u, addr string, size int) error {
		var msg string
		switch *format {
		case "synology":
			p := path
			if newPath != "" {
				p += " -> " + newPath
			}
			msg = fmt.Sprintf("<134>%s %s WinFileService Event: %s, Path: %s, File/Folder: %s, Size: %.2f KB, User: %s, IP: %s",
				time.Now().Format(time.Stamp), *host, op, p, kind, float64(size)/1024, u, addr)
		case "qnap":
			p := "/share/CACHEDEV1_DATA" + path
			if newPath != "" {
				p += " -> /share/CACHEDEV1_DATA" + newPath
			}
			msg = fmt.Sprintf("<14>%s %s qlogd[1234]: conn log: Users: %s, Source IP: %s, Computer name: PC-01, Connection type: SMB, Accessed resources: %s, Action: %s",
				time.Now().Format(time.Stamp), *host, u, addr, p, map[string]string{
					"create": "Write", "rename": "Rename", "delete": "Delete", "read": "Read", "write": "Write"}[op])
		default:
			return fmt.Errorf("format không hợp lệ: %s", *format)
		}
		if *network == "tcp" {
			msg += "\n"
		}
		_, err := c.Write([]byte(msg))
		return err
	}

	exts := []string{"docx", "xlsx", "pdf", "pptx", "csv", "dwg", "zip", "png"}
	others := []string{"user02", "user03", "user04"}
	var delay time.Duration
	if *rate > 0 {
		delay = time.Minute / time.Duration(*rate)
	}
	start := time.Now()
	fmt.Printf("Bắt đầu gửi lúc %s tới %s/%s (%s)\n", start.Format("15:04:05.000"), *network, *target, *format)
	noted := map[string]bool{}
	for i := 0; i < *files; i++ {
		dir := fmt.Sprintf("/%s/Phong%02d/Thang%02d", *share, i/250, i%12+1)
		if *note != "" && !noted[dir] {
			noted[dir] = true
			if err := send("create", dir+"/"+*note, "", "File", *user, *ip, 900); err != nil {
				return err
			}
		}
		name := fmt.Sprintf("%s/Chung tu %05d.%s", dir, i, exts[i%len(exts)])
		size := 4096 + mrand.IntN(1<<20)
		if err := send("rename", name, name+*ext, "File", *user, *ip, size); err != nil {
			return err
		}
		for k := 0; k < *noise; k++ {
			op := []string{"read", "write"}[k%2]
			u := others[mrand.IntN(len(others))]
			p := fmt.Sprintf("/%s/Chung/BaoCao %03d.xlsx", *share, mrand.IntN(500))
			if err := send(op, p, "", "File", u, fmt.Sprintf("10.10.6.%d", 10+mrand.IntN(50)), 20480); err != nil {
				return err
			}
		}
		if delay > 0 {
			time.Sleep(time.Until(start.Add(time.Duration(i+1) * delay)))
		}
	}
	fmt.Printf("Xong lúc %s: %d file đổi đuôi, %d ransom note, %d dòng nhiễu\n",
		time.Now().Format("15:04:05.000"), *files, len(noted), *files**noise)
	return nil
}
