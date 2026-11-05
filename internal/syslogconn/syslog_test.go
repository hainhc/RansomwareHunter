package syslogconn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"ransomwarehunter/internal/event"
)

// Dòng mẫu theo đúng bố cục log SMB transfer log của DSM 7 (header bị lặp khi đi qua relay),
// tên người dùng/đường dẫn đã thay bằng dữ liệu giả.
var synoLines = []string{
	`Sep 15 22:49:45 172.17.0.1 Sep 15 22:49:45 Syno_Nas WinFileService Event: rename, Path: /KeToan/2026/Bao cao, Q3.xlsx -> /KeToan/2026/Bao cao, Q3.xlsx.lockbit, File/Folder: File, Size: 34.81 MB, User: user01@corp.local, IP: 192.168.19.59`,
	`<134>Oct 30 07:30:01 Syno_Nas WinFileService Event: create, Path: /KeToan/2026/HOW_TO_RECOVER.txt, File/Folder: File, Size: 0 Bytes, User: CORP\user01, IP: fe80::d5af:66fc:e768:80e`,
	`Sep 15 22:49:49 172.17.0.1 Sep 15 22:49:49 Syno_Nas WinFileService Event: delete, Path: /KeToan/2026/old, File/Folder: Folder, Size: 0 Bytes, User: user01, IP: 192.168.19.59`,
	`Sep 19 23:38:27 172.17.0.1 Sep 19 23:38:27 Syno_Nas WinFileService Event: read, Path: /Software/Thumbs.db, File/Folder: File, Size: 18.00 KB, User: user02, IP: 192.168.19.60`,
	`Sep 15 22:49:20 172.17.0.1 Sep 15 22:49:20 Syno_Nas WinFileService Event: write, Path: /KeToan/props.conf, File/Folder: File, Size: 1.41 KB, User: user01, IP: 192.168.19.59`,
	`Sep 15 22:49:20 Syno_Nas Connection: User [smb] from [SMB(192.168.10.20)] via [CIFS(SMB3)] accessed shared folder [datastore].`,
}

func TestSynologyParse(t *testing.T) {
	f := Builtin["synology"]
	type want struct {
		st              Status
		op              event.Op
		path, old, user string
		ip              string
		dir             bool
		size            int64
	}
	wants := []want{
		{Matched, event.OpRename, "KeToan/2026/Bao cao, Q3.xlsx.lockbit", "KeToan/2026/Bao cao, Q3.xlsx", "user01@corp.local", "192.168.19.59", false, 36500930},
		{Matched, event.OpCreate, "KeToan/2026/HOW_TO_RECOVER.txt", "", `CORP\user01`, "fe80::d5af:66fc:e768:80e", false, 0},
		{Matched, event.OpDelete, "KeToan/2026/old", "", "user01", "192.168.19.59", true, 0},
		{st: Ignored},
		{Matched, event.OpModify, "KeToan/props.conf", "", "user01", "192.168.19.59", false, 1443},
		{st: Unmatched},
	}
	for i, line := range synoLines {
		p, st := f.Parse(line)
		w := wants[i]
		if st != w.st {
			t.Fatalf("dòng %d: status=%v muốn %v", i, st, w.st)
		}
		if st != Matched {
			continue
		}
		got := want{st, p.Op, p.Path, p.OldPath, p.User, p.IP, p.IsDir, p.Size}
		if got != w {
			t.Errorf("dòng %d:\n có  %+v\n muốn %+v", i, got, w)
		}
	}
}

func TestQNAPProvisionalParse(t *testing.T) {
	f := Builtin["qnap"]
	line := `<14>Oct 30 07:31:02 qnap01 qlogd[1234]: conn log: Users: user01, Source IP: 10.10.5.23, Computer name: PC-KT01, Connection type: SMB, Accessed resources: /share/CACHEDEV1_DATA/KeToan/a.docx -> /share/CACHEDEV1_DATA/KeToan/a.docx.akira, Action: Rename`
	p, st := f.Parse(line)
	if st != Matched || p.Op != event.OpRename || p.User != "user01" || p.IP != "10.10.5.23" {
		t.Fatalf("st=%v p=%+v", st, p)
	}
	d := Device{System: "qnap01", Format: f, SharePrefix: `\\qnap01\`,
		Strip: regexp.MustCompile(`^/share/(CACHEDEV\d+_DATA|MD0_DATA|HDA_DATA)/`)}
	ev, ok := d.toEvent(p)
	if !ok || ev.Share != `\\qnap01\KeToan` || ev.Path != "a.docx.akira" || ev.OldPath != "a.docx" {
		t.Fatalf("ev=%+v", ev)
	}
	// Rename không có tên mới: không đoán, ghi nhận Incomplete để hiệu chỉnh.
	if _, st := f.Parse(strings.Replace(line, " -> /share/CACHEDEV1_DATA/KeToan/a.docx.akira", "", 1)); st != Incomplete {
		t.Fatalf("st=%v", st)
	}
}

func TestCustomFormat(t *testing.T) {
	f, err := NewCustom("samba", `\|(?P<user>[^|]*)\|(?P<ip>[^|]*)\|[^|]*\|(?P<op>renameat|unlinkat)\|ok\|(?P<old>[^|]*)\|?(?P<new>[^|]*)$`,
		map[string]string{"renameat": "rename", "unlinkat": "delete"}, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	p, st := f.Parse(`smbd_audit: |user01|10.0.0.9|KeToan|renameat|ok|KeToan/a.pdf|KeToan/a.pdf.enc`)
	if st != Matched || p.OldPath != "KeToan/a.pdf" || p.Path != "KeToan/a.pdf.enc" {
		t.Fatalf("st=%v p=%+v", st, p)
	}
	if _, err := NewCustom("x", `(?P<op>\w+)`, nil, "", nil); err == nil {
		t.Fatal("thiếu nhóm path phải báo lỗi")
	}
}

func TestReceiverUDPAndTCP(t *testing.T) {
	out := make(chan event.FileEvent, 100)
	capture := filepath.Join(t.TempDir(), "unmatched.log")
	r, err := New(Config{
		ListenUDP: "127.0.0.1:0", ListenTCP: "127.0.0.1:0", CaptureFile: capture,
		Devices: []Device{{Address: "127.0.0.1", System: "syno01", Format: Builtin["synology"], SharePrefix: `\\syno01\`}},
	}, out, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	// Dùng Handle trực tiếp cho UDP để không phụ thuộc cổng; TCP kiểm tra framing qua kết nối thật.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, l := range synoLines {
		if err := r.Handle(ctx, "127.0.0.1", l); err != nil {
			t.Fatal(err)
		}
	}
	_ = r.Handle(ctx, "10.9.9.9", synoLines[0]) // thiết bị không khai báo

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go r.serveTCP(ctx, ln)
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	msg := synoLines[1]
	fmt.Fprintf(c, "%d %s", len(msg), msg) // octet-counting
	fmt.Fprintf(c, "%s\n", synoLines[2])   // theo dòng
	c.Close()

	var got []string
	timeout := time.After(3 * time.Second)
	for len(got) < 6 {
		select {
		case ev := <-out:
			got = append(got, fmt.Sprintf("%s %s %s>%s %s", ev.Op, ev.Share, ev.OldPath, ev.Path, ev.Actor.User))
		case <-timeout:
			t.Fatalf("chỉ nhận %d sự kiện: %v", len(got), got)
		}
	}
	if got[0] != `RENAME \\syno01\KeToan 2026/Bao cao, Q3.xlsx>2026/Bao cao, Q3.xlsx.lockbit user01@corp.local` {
		t.Fatalf("got[0]=%q", got[0])
	}
	st := r.Stats()
	if st.Matched != 6 || st.Ignored != 1 || st.Unmatched != 1 || st.UnknownDevice != 1 {
		t.Fatalf("stats=%+v", st)
	}
	r.capFile.Close()
	b, _ := os.ReadFile(capture)
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	n := 0
	for sc.Scan() {
		n++
		if !strings.Contains(sc.Text(), "\tUNMATCHED\t127.0.0.1\t") {
			t.Fatalf("capture=%q", sc.Text())
		}
	}
	if n != 1 {
		t.Fatalf("capture có %d dòng", n)
	}
}
