package event

import "testing"

func TestExt(t *testing.T) {
	cases := map[string]string{
		"BaoCao.XLSX":        "xlsx",
		"a.docx.lockbit":     "lockbit",
		".bashrc":            "",
		"README":             "",
		"trailing.":          "",
		"archive.tar.gz":     "gz",
		"Hợp đồng 2026.docx": "docx",
	}
	for in, want := range cases {
		if got := Ext(in); got != want {
			t.Errorf("Ext(%q) = %q, muốn %q", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		old, new          string
		ok                bool
		from, to, display string
	}{
		{"BaoCao.xlsx", "BaoCao.xlsx.lockbit", true, ".xlsx", ".lockbit", ".xlsx.lockbit"},
		{"a.docx", "a.locked", true, ".docx", ".locked", ".locked"},
		{"a.docx", "A.DOCX", false, "", "", ""},
		{"a.docx", "b.docx", false, "", "", ""},
		{"a.pdf", "a.pdf.id-1A2B3C4D.[x@mail.cc].wallet", true, ".pdf", ".id-{HEX}.[{EMAIL}].wallet", ".pdf.id-{HEX}.[{EMAIL}].wallet"},
		{"notes", "notes.enc", true, NoExt, ".enc", ".enc"},
	}
	for _, c := range cases {
		tr, ok := Classify(c.old, c.new)
		if ok != c.ok {
			t.Fatalf("Classify(%q,%q) ok=%v", c.old, c.new, ok)
		}
		if !ok {
			continue
		}
		if tr.From != c.from || tr.To != c.to || tr.Display() != c.display {
			t.Errorf("Classify(%q,%q) = %+v display=%q", c.old, c.new, tr, tr.Display())
		}
	}
}

func TestTemplate(t *testing.T) {
	cases := map[string]string{
		".lockbit":                              ".lockbit",
		".id-9F8E7D6C.[a@b.io].wallet":          ".id-{HEX}.[{EMAIL}].wallet",
		".encrypted_20261030":                   ".encrypted_{NUM}",
		".a1b2c3d4e5f6g7":                       ".{RND}",
		".encryptedfiles":                       ".encryptedfiles",
		".3f2504e0-4f89-11d3-9a0c-0305e82c3301": ".{UUID}",
	}
	for in, want := range cases {
		if got := Template(in); got != want {
			t.Errorf("Template(%q) = %q, muốn %q", in, got, want)
		}
	}
}

func TestBenign(t *testing.T) {
	b := DefaultBenign()
	benign := [][2]string{
		{"~WRD0000.tmp", "BaoCao.docx"},
		{"BaoCao.docx", "~WRL0001.tmp"},
		{"setup.exe.crdownload", "setup.exe"},
		{"data.csv", "data.csv.bak"},
		{"~$BaoCao.docx", "x.y"},
	}
	for _, p := range benign {
		if !b.IsBenign(p[0], p[1]) {
			t.Errorf("IsBenign(%q,%q) = false", p[0], p[1])
		}
	}
	if b.IsBenign("BaoCao.docx", "BaoCao.docx.lockbit") {
		t.Error("đổi đuôi ransomware bị coi là hợp lệ")
	}
}
