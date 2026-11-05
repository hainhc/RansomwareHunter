package usn

import (
	"fmt"
	"testing"
	"time"
)

const root = 0x0005000000000005

func newTestTracker() *Tracker {
	t := NewTracker("fs01", "D:", []Root{{Path: `Shares\Finance`, Share: `\\fs01\Finance`}}, root)
	t.AddDir(100, root, "Shares")
	t.AddDir(101, 100, "Finance")
	t.AddDir(102, 101, "2026")
	t.AddDir(200, root, "Other")
	return t
}

func feed(t *Tracker, recs ...Record) []string {
	var buf []byte
	for i, r := range recs {
		r.USN = int64(i + 1)
		r.TS = time.Date(2026, 10, 30, 14, 0, i, 0, time.UTC)
		buf = append(buf, EncodeRecord(r)...)
	}
	parsed, skipped, err := ParseRecords(buf)
	if err != nil || skipped != 0 || len(parsed) != len(recs) {
		panic(fmt.Sprint(err, skipped, len(parsed)))
	}
	var out []string
	for _, r := range parsed {
		for _, ev := range t.Handle(r) {
			out = append(out, fmt.Sprintf("%s %s|%s>%s %s", ev.Op, ev.Share, ev.OldPath, ev.Path, ev.Pair))
		}
	}
	return out
}

func TestRansomwareRenameSequence(t *testing.T) {
	tr := newTestTracker()
	got := feed(tr,
		Record{FRN: 500, ParentFRN: 102, Reason: ReasonRenameOldName, Name: "BaoCao.xlsx"},
		Record{FRN: 500, ParentFRN: 102, Reason: ReasonRenameNewName, Name: "BaoCao.xlsx.lockbit"},
		Record{FRN: 500, ParentFRN: 102, Reason: ReasonRenameNewName | ReasonClose, Name: "BaoCao.xlsx.lockbit"},
		Record{FRN: 501, ParentFRN: 102, Reason: ReasonFileCreate, Name: "Restore-My-Files.txt"},
		Record{FRN: 501, ParentFRN: 102, Reason: ReasonFileCreate | ReasonDataExtend, Name: "Restore-My-Files.txt"},
		Record{FRN: 501, ParentFRN: 102, Reason: ReasonFileCreate | ReasonDataExtend | ReasonClose, Name: "Restore-My-Files.txt"},
		Record{FRN: 502, ParentFRN: 101, Reason: ReasonDataOverwrite | ReasonClose, Name: "a.docx"},
		Record{FRN: 503, ParentFRN: 101, Reason: ReasonFileDelete | ReasonClose, Name: "b.pdf"},
		Record{FRN: 504, ParentFRN: 200, Reason: ReasonFileCreate | ReasonClose, Name: "ngoai-share.txt"},
	)
	want := []string{
		`RENAME \\fs01\Finance|2026/BaoCao.xlsx>2026/BaoCao.xlsx.lockbit EXACT`,
		`CREATE \\fs01\Finance|>2026/Restore-My-Files.txt `,
		`MODIFY \\fs01\Finance|>a.docx `,
		`DELETE \\fs01\Finance|>b.pdf `,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("\n%v\nmuốn\n%v", got, want)
	}
}

func TestDirectoryCacheFollowsRenames(t *testing.T) {
	tr := newTestTracker()
	feed(tr,
		Record{FRN: 300, ParentFRN: 101, Reason: ReasonFileCreate | ReasonClose, Attr: attrDirectory, Name: "Q3"},
		Record{FRN: 300, ParentFRN: 101, Reason: ReasonRenameOldName, Attr: attrDirectory, Name: "Q3"},
		Record{FRN: 300, ParentFRN: 102, Reason: ReasonRenameNewName, Attr: attrDirectory, Name: "Quy3"},
	)
	got := feed(tr, Record{FRN: 600, ParentFRN: 300, Reason: ReasonFileCreate | ReasonClose, Name: "x.docx"})
	if len(got) != 1 || got[0] != `CREATE \\fs01\Finance|>2026/Quy3/x.docx ` {
		t.Fatalf("got=%v", got)
	}
}

func TestMoveAcrossShareBoundary(t *testing.T) {
	tr := newTestTracker()
	got := feed(tr,
		Record{FRN: 700, ParentFRN: 200, Reason: ReasonRenameOldName, Name: "x.docx"},
		Record{FRN: 700, ParentFRN: 102, Reason: ReasonRenameNewName, Name: "x.docx"},
	)
	if len(got) != 1 || got[0] != `CREATE \\fs01\Finance|>2026/x.docx ` {
		t.Fatalf("got=%v", got)
	}
}

func TestCountExt(t *testing.T) {
	tr := newTestTracker()
	c := ExtCounter{}
	tr.CountExt(c, 102, "a.DOCX")
	tr.CountExt(c, 101, "b.docx")
	tr.CountExt(c, 200, "c.docx")
	if c[`\\fs01\Finance`]["docx"] != 2 || len(c) != 1 {
		t.Fatalf("c=%v", c)
	}
}
