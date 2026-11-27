package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/dakasa-yggdrasil/yggdrasil-core/repository"
	"github.com/google/uuid"
)

type nativePhaseUnreadableBody struct{ t *testing.T }

func (b nativePhaseUnreadableBody) Read([]byte) (int, error) {
	b.t.Fatal("unauthorized original-return body was read")
	return 0, nil
}
func (nativePhaseUnreadableBody) Close() error { return nil }

func TestNativeWorkerPhaseHTTPAuthenticateBeforeBody(t *testing.T) {
	token := "ci-private-native-writer-token"
	principals := capacityMutationTestPrincipal(t, token, uuid.NewString())
	s := &Server{capacityMutationPrincipals: principals}
	h := s.requireAuthenticatedConsoleAPIs(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("native callback reached another auth surface") }))
	for _, credential := range []string{"", "human-session", token} {
		r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerPhaseBasePath+"receive", nil)
		r.Body = nativePhaseUnreadableBody{t}
		if credential != "" {
			r.Header.Set("Authorization", "Bearer "+credential)
		}
		r.AddCookie(&http.Cookie{Name: authSessionCookieName(), Value: "human-cookie"})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), token) {
			t.Fatal("non-writer credential reached Native custody", w.Code)
		}
	}
	s.capacityMutationPrincipals[0].capabilities["ensure_native_worker_pool"] = true
	s.capacityMutationPrincipals[0].base.status = "revoked"
	r := httptest.NewRequest(http.MethodPost, "https://core.example"+nativeWorkerPhaseBasePath+"receive", nil)
	r.Body = nativePhaseUnreadableBody{t}
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal("revoked writer accepted", w.Code)
	}
}

func TestNativeWorkerPhaseOriginalReceiveClosedAndBounded(t *testing.T) {
	v := model.CapacityNativeWorkerPhaseReceive{PermitID: uuid.New(), BindingName: "ci-pool", SettlementToken: "ci-private-settlement", HTTPStatus: 200, TransportCompleted: true, OriginalReturn: bytes.Repeat([]byte("x"), 1700000), CompletedAt: time.Now().UTC()}
	raw, _ := json.Marshal(v)
	if len(raw) <= 2<<20 || len(raw) >= 4<<20 {
		t.Fatal("fixture does not exercise base64 body envelope")
	}
	got, err := decodeNativeWorkerPhaseReceive(raw)
	if err != nil || !bytes.Equal(got.OriginalReturn, v.OriginalReturn) {
		t.Fatal("complete original wire was changed or refused", err)
	}
	v.OriginalReturn = []byte("private-original")
	raw, _ = json.Marshal(v)
	for _, bad := range [][]byte{
		append(append([]byte{}, raw...), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"binding_name":"other","binding_name":`), 1),
		bytes.Replace(raw, []byte(`"http_status":200`), []byte(`"http_status":null`), 1),
		bytes.Replace(raw, []byte(`"transport_completed":true`), []byte(`"transport_completed":"true"`), 1),
		bytes.Replace(raw, []byte(`"binding_name":`), []byte(`"Binding_Name":`), 1),
		bytes.Replace(raw, []byte(`"settlement_token":`), []byte(`"caller_proof":`), 1),
	} {
		if _, err := decodeNativeWorkerPhaseReceive(bad); err == nil {
			t.Fatal("ambiguous original-return envelope accepted")
		}
	}
	v.OriginalReturn = make([]byte, (2<<20)+1)
	raw, _ = json.Marshal(v)
	if _, err := decodeNativeWorkerPhaseReceive(raw); err == nil {
		t.Fatal("oversize original wire accepted")
	}
}

func TestNativeWorkerPhaseRoutesRequireControlAuthority(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodHead} {
		for _, action := range []string{"read", "redeem", "receive", "unknown"} {
			r := httptest.NewRequest(method, nativeWorkerPhaseBasePath+action, nil)
			if (&Server{}).workerRouteAllowed(r) {
				t.Fatal("API worker allowed Native authority callback", method, action)
			}
		}
	}
}

type nativePhaseWorkerCompositionFixture struct {
	source       string
	legacyReads  int
	prepareCalls int
}

func (r *nativePhaseWorkerCompositionFixture) SourceCommit() string { return r.source }
func (r *nativePhaseWorkerCompositionFixture) ObserveAuthority(context.Context, model.Manifest) (*model.CapacityNativeWorkerPoolObservation, error) {
	r.legacyReads++
	return nil, errors.New("legacy pool callback is not phase authority")
}
func (r *nativePhaseWorkerCompositionFixture) Prepare(a model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerLaunch, error) {
	r.prepareCalls++
	return model.CapacityNativeWorkerLaunch{AttemptID: a.ID}, nil
}
func (*nativePhaseWorkerCompositionFixture) CaptureOriginalReturn(context.Context, model.CapacityNativeWorkerAttempt) (model.CapacityNativeWorkerOriginalReturn, error) {
	return model.CapacityNativeWorkerOriginalReturn{}, repository.ErrCapacityNativeReturnPending
}
func (*nativePhaseWorkerCompositionFixture) Qualify(context.Context, model.CapacityNativeWorkerAttempt, model.CapacityNativeWorkerOriginalReturn) (model.CapacityNativeWorkerObservation, error) {
	return model.CapacityNativeWorkerObservation{}, repository.ErrCapacityDisabled
}

func TestProtectedNativePhaseReaderCompositionPreservesIndependentWorkerPort(t *testing.T) {
	s := &Server{}
	if s.nativeWorkerRuntime != nil || s.nativeWorkerPhaseRuntime != nil {
		t.Fatal("phase runtime enabled by default")
	}
	worker := &nativePhaseWorkerCompositionFixture{source: strings.Repeat("a", 40)}
	WithProtectedNativeWorkerPhaseReader(worker, nil)(s)
	wrapped, ok := s.nativeWorkerRuntime.(nativeWorkerWithPhaseAuthority)
	if !ok || wrapped.NativeWorkerRuntime != worker || wrapped.reader == nil || wrapped.reader.server != s || wrapped.reader.readiness != nil || s.nativeWorkerPhaseRuntime != wrapped.reader || wrapped.SourceCommit() != worker.source {
		t.Fatal("protected composition replaced worker source or invented readiness")
	}
	a := model.CapacityNativeWorkerAttempt{ID: uuid.New()}
	if launch, err := wrapped.Prepare(a); err != nil || launch.AttemptID != a.ID || worker.prepareCalls != 1 {
		t.Fatal("protected reader did not preserve pure worker preparation", err)
	}
	if _, err := wrapped.ObservePhaseAuthority(t.Context(), model.Manifest{ID: uuid.New()}); !errors.Is(err, repository.ErrCapacityDisabled) || worker.legacyReads != 0 {
		t.Fatal("missing protected reader authority fell back to useful-pool callback", err)
	}
	WithProtectedNativeWorkerPhaseReader(nil, nil)(s)
	if s.nativeWorkerRuntime != nil || s.nativeWorkerPhaseRuntime == nil {
		t.Fatal("read-only composition implicitly installed a provider runtime")
	}
}

func TestProtectedNativePhaseReaderResolvesExactStoredPolicyBeforeAdapter(t *testing.T) {
	for _, mode := range []string{"missing_policy", "wrong_kind", "checksum_changed", "invalid_json", "no_phase_observer"} {
		t.Run(mode, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			id := uuid.New()
			kind, checksum, spec := "capacity_policy", "qualified-policy", []byte(`{}`)
			switch mode {
			case "wrong_kind":
				kind = "workflow"
			case "checksum_changed":
				checksum = "new-unqualified-policy"
			case "invalid_json":
				spec = []byte(`{"native_worker_lifecycle_binding":`)
			}
			query := mock.ExpectQuery(`(?s)SELECT.*FROM public.manifests.*WHERE id = \$1`).WithArgs(id)
			if mode == "missing_policy" {
				query.WillReturnError(repository.ErrManifestNotFound)
			} else {
				now := time.Now().UTC()
				query.WillReturnRows(sqlmock.NewRows([]string{"id", "api_version", "kind", "namespace", "name", "version", "active", "description", "labels", "spec", "checksum", "created_at", "updated_at"}).AddRow(id, "yggdrasil.io/v1alpha1", kind, "realm", "fixed-pool", 2, true, "", []byte(`{}`), spec, checksum, now, now))
			}
			s := &Server{db: db}
			// Only the exact policy row is expected. A credentials/catalog query
			// or adapter result cannot rescue an invalid policy/reader binding.
			reader := &serverNativeWorkerPhaseReader{server: s}
			if _, err := reader.PreparePhase(t.Context(), model.CapacityNativeWorkerAttempt{PolicyID: id, PolicyChecksum: "qualified-policy"}, "register"); err == nil {
				t.Fatal("unqualified stored policy reached adapter composition", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
	// A missing process authority is not a virtual pool or successful empty read.
	for _, reader := range []*serverNativeWorkerPhaseReader{nil, {}, {server: &Server{}}} {
		if _, err := reader.forPolicy(t.Context(), uuid.New(), ""); !errors.Is(err, repository.ErrCapacityDisabled) {
			t.Fatal("missing protected store accepted", err)
		}
	}
}
