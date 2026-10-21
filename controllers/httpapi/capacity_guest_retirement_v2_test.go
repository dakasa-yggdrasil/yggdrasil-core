package httpapi

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
)

// Every malformed scope refuses before touching a DB or reserving an ordinal.
// Complete authentication and real ledger execution remain owning native tests.
func TestCapacityGuestRetirementV2ClosedAuthorityBeforeReservation(t *testing.T) {
	for _, kind := range []string{"method", "path", "missing_id", "noncanonical_id", "bad_phase", "unknown_query", "duplicate_query", "reordered_query", "missing_hash", "bad_hash", "duplicate_hash", "body", "chunked", "missing_principal"} {
		t.Run(kind, func(t *testing.T) {
			id := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			request := httptest.NewRequest(http.MethodGet, model.GuestRetirementV2AuthorityPath+"?request_id="+id+"&phase=before_start", nil)
			request.Header.Set("X-Guest-Retirement-Intent-SHA256", strings.Repeat("b", 64))
			principal := &capacityGuestPrincipal{}
			switch kind {
			case "method":
				request.Method = http.MethodPost
			case "path":
				request.URL.Path += "/caller"
			case "missing_id":
				request.URL.RawQuery = "phase=before_start"
			case "noncanonical_id":
				request.URL.RawQuery = "request_id=" + strings.ToUpper(id) + "&phase=before_start"
			case "bad_phase":
				request.URL.RawQuery = "request_id=" + id + "&phase=after_return"
			case "unknown_query":
				request.URL.RawQuery += "&caller=1"
			case "duplicate_query":
				request.URL.RawQuery += "&phase=before_start"
			case "reordered_query":
				request.URL.RawQuery = "phase=before_start&request_id=" + id
			case "missing_hash":
				request.Header.Del("X-Guest-Retirement-Intent-SHA256")
			case "bad_hash":
				request.Header.Set("X-Guest-Retirement-Intent-SHA256", "caller")
			case "duplicate_hash":
				request.Header.Add("X-Guest-Retirement-Intent-SHA256", strings.Repeat("b", 64))
			case "body":
				request.Body = io.NopCloser(strings.NewReader("x"))
				request.ContentLength = 1
			case "chunked":
				request.ContentLength = -1
				request.TransferEncoding = []string{"chunked"}
			case "missing_principal":
				principal = nil
			}
			response := httptest.NewRecorder()
			(&Server{}).serveGuestOriginalAuthorityV2(response, request, principal, repository.CapacityStore{})
			if response.Code != http.StatusForbidden {
				t.Fatal("malformed private scope reached reservation", response.Code)
			}
		})
	}
}
