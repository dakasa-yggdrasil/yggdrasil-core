package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCapacityGuestProfileAuthorityV2ClosedScope(t *testing.T) {
	for _, mode := range []string{"missing_boot", "nil_boot", "uppercase_boot", "duplicate_boot", "missing_nonce", "uppercase_nonce", "duplicate_nonce", "missing_native", "duplicate_native", "profile_header", "body", "query", "empty_query", "foreign_member", "foreign_slot", "actor", "plaintext", "original_sql_error", "pending_sql_error"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, e := sqlmock.New()
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			const token = "synthetic-authority-v2-private-scope-only"
			role, scheme, member, slot := "provisioner", "https", "original-member", "2"
			body, suffix := "", ""
			switch mode {
			case "actor":
				role = "actor"
			case "plaintext":
				scheme = "http"
			case "foreign_member":
				member = "foreign"
			case "foreign_slot":
				slot = "3"
			case "query":
				suffix = "?remaining_ns=5000000000"
			case "empty_query":
				suffix = "?"
			case "body":
				body = "{}"
			}
			s := &Server{db: db, capacityGuestPrincipals: guestOriginalAuthInventory(t, guestOriginalAuthConfig(token, role))}
			calls := 0
			h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
			r := httptest.NewRequest("GET", scheme+"://core.invalid"+guestProvisioningBase+"/bindings/"+member+"/slots/"+slot+"/original-profile-authority-v2"+suffix, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token)
			r.Header.Set("X-Guest-Boot-ID", "10000000-0000-4000-8000-000000000001")
			r.Header.Set("X-Guest-Profile-Request-Nonce-SHA256", strings.Repeat("a", 64))
			r.Header.Set("X-Guest-Native-Resource-ID", "i-1234567890abcdef0")
			switch mode {
			case "missing_boot":
				r.Header.Del("X-Guest-Boot-ID")
			case "nil_boot":
				r.Header.Set("X-Guest-Boot-ID", "00000000-0000-0000-0000-000000000000")
			case "uppercase_boot":
				r.Header.Set("X-Guest-Boot-ID", "AAAAAAAA-0000-4000-8000-000000000001")
			case "duplicate_boot":
				r.Header.Add("X-Guest-Boot-ID", r.Header.Get("X-Guest-Boot-ID"))
			case "missing_nonce":
				r.Header.Del("X-Guest-Profile-Request-Nonce-SHA256")
			case "uppercase_nonce":
				r.Header.Set("X-Guest-Profile-Request-Nonce-SHA256", strings.Repeat("A", 64))
			case "duplicate_nonce":
				r.Header.Add("X-Guest-Profile-Request-Nonce-SHA256", strings.Repeat("a", 64))
			case "missing_native":
				r.Header.Del("X-Guest-Native-Resource-ID")
			case "duplicate_native":
				r.Header.Add("X-Guest-Native-Resource-ID", r.Header.Get("X-Guest-Native-Resource-ID"))
			case "profile_header":
				r.Header.Set("X-Guest-Profile-Manifest-SHA256", strings.Repeat("a", 64))
			case "original_sql_error":
				mock.ExpectQuery("SELECT p.id::text,p.nonce_sha256").WillReturnError(errors.New("synthetic database unavailable"))
			case "pending_sql_error":
				mock.ExpectQuery("SELECT p.id::text,p.nonce_sha256").WillReturnRows(sqlmock.NewRows([]string{"id", "nonce_sha256"}))
				mock.ExpectQuery("SELECT p.id::text FROM public.capacity_vm_provisioning_preregistrations").WillReturnError(errors.New("synthetic pending lookup unavailable"))
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || w.Code == 425 || calls != 0 || strings.Contains(w.Body.String(), token) || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("foreign/error acquired pending or signed authority", w.Code, calls)
			}
			if (mode == "original_sql_error" || mode == "pending_sql_error") && w.Code != 503 {
				t.Fatal("SQL error was misclassified", w.Code)
			}
			if e = mock.ExpectationsWereMet(); e != nil {
				t.Fatal(e)
			}
		})
	}
}
