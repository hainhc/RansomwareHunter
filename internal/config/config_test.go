package config

import (
	"testing"
	"time"
)

func TestExampleConfigsLoad(t *testing.T) {
	var s Server
	if err := Load("../../configs/rh-server.example.json", &s); err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	d := s.DetectConfig()
	if d.Window != time.Minute || d.IncidentQuiet != 10*time.Minute || len(d.Canaries) != 3 {
		t.Fatalf("detect=%+v", d)
	}
	if s.Scanners[0].Share != `\\nas01\Finance` || s.USN[0].Source().PollInterval != 500*time.Millisecond {
		t.Fatalf("scanners=%+v usn=%+v", s.Scanners, s.USN)
	}
	var a Agent
	if err := Load("../../configs/rh-agent.example.json", &a); err != nil {
		t.Fatal(err)
	}
	if len(a.USN) != 1 || len(a.USN[0].Roots) != 2 {
		t.Fatalf("agent=%+v", a)
	}
}
