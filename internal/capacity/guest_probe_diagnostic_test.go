package capacity

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeDiagnosticClosedSafeProjection(t *testing.T) {
	for code, stages := range GuestProbeStages {
		status := 409
		if code == "qualification_probe.closed_request_required" {
			status = 400
		}
		for _, stage := range stages {
			t.Run(code+"/"+stage, func(t *testing.T) {
				body := []byte(`{"code":"` + code + `","status":` + map[int]string{400: "400", 409: "409"}[status] + `,"title":"Guest retirement held","detail":"The original Guest retirement requires its enrolled authority and complete original results.","stage":"` + stage + `"}` + "\n")
				d := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: status, Body: body})
				if d.Code != code || d.Stage != stage {
					t.Fatal("valid code lost")
				}
				for _, bad := range [][]byte{append(body, []byte("secret")...), []byte(strings.Replace(string(body), stage, "secret/private/path", 1)), []byte(strings.Replace(string(body), `"stage":`, `"secret":"token","stage":`, 1)), []byte(strings.Repeat("s", 2049))} {
					got := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: status, Body: bad})
					raw, _ := json.Marshal(got)
					if got.Code != "" || got.Stage != "" || strings.Contains(string(raw), "secret") {
						t.Fatal("unsafe output")
					}
				}
				wrong := GuestProbeDiagnostic(GuestOriginalHTTPReturn{Status: 401, Body: body})
				if wrong.Code != "" {
					t.Fatal("status mismatch")
				}
			})
		}
	}
}
