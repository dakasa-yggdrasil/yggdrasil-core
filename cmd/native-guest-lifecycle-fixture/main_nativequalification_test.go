//go:build linux && nativequalification

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/controllers/httpapi"
)

// These real HTTP lifetime checks do not create VM/capacity evidence.
func TestOriginalNativeHTTPReturnedOwners(t *testing.T) {
	t.Run("serve_close_does_not_join_original_handler", func(t *testing.T) {
		original, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		owners, err := httpapi.NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		entered, canceled, release, handlerReturned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseOriginal := func() { releaseOnce.Do(func() { close(release) }) }
		defer releaseOriginal()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{BaseContext: func(net.Listener) context.Context { return original }, Handler: originalNativeHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(handlerReturned)
			close(entered)
			<-r.Context().Done()
			close(canceled)
			<-release
		}), owners)}
		serveReturned := make(chan error, 1)
		go func() { serveReturned <- server.Serve(listener) }()
		clientReturned := make(chan error, 1)
		client := &http.Client{Timeout: time.Minute}
		go func() {
			response, err := client.Get("http://" + listener.Addr().String())
			if response != nil {
				err = errors.Join(err, response.Body.Close())
			}
			clientReturned <- err
		}()
		<-entered
		cancel()
		<-canceled
		if err := server.Close(); err != nil {
			t.Fatal(err)
		}
		if err := <-serveReturned; !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
		probe, cancelProbe := context.WithCancel(context.Background())
		cancelProbe()
		if err := owners.Join(probe); !errors.Is(err, context.Canceled) {
			t.Fatal("Serve/Close masqueraded as handler return", err)
		}
		if _, finish, err := owners.Begin(); err == nil || finish != nil {
			t.Fatal("sealed owner launched replacement")
		}
		releaseOriginal()
		if err := owners.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
		<-handlerReturned
		<-clientReturned
	})
	t.Run("same_handler_return_is_required_after_shutdown", func(t *testing.T) {
		original, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		owners, err := httpapi.NewNativeOriginalWorkflowOwners(original)
		if err != nil {
			t.Fatal(err)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		releaseOriginal := func() { releaseOnce.Do(func() { close(release) }) }
		defer releaseOriginal()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{BaseContext: func(net.Listener) context.Context { return original }, Handler: originalNativeHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-release; w.WriteHeader(204) }), owners)}
		serveReturned, shutdownReturned, clientReturned := make(chan error, 1), make(chan error, 1), make(chan error, 1)
		go func() { serveReturned <- server.Serve(listener) }()
		go func() {
			response, err := (&http.Client{Timeout: time.Minute}).Get("http://" + listener.Addr().String())
			if response != nil {
				err = errors.Join(err, response.Body.Close())
			}
			clientReturned <- err
		}()
		<-entered
		go func() { shutdownReturned <- server.Shutdown(context.Background()) }()
		if err := <-serveReturned; !errors.Is(err, http.ErrServerClosed) {
			t.Fatal(err)
		}
		probe, cancelProbe := context.WithCancel(context.Background())
		cancelProbe()
		if err := owners.Join(probe); !errors.Is(err, context.Canceled) {
			t.Fatal("listener return erased active handler", err)
		}
		releaseOriginal()
		if err := <-shutdownReturned; err != nil {
			t.Fatal(err)
		}
		if err := owners.Join(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := <-clientReturned; err != nil {
			t.Fatal(err)
		}
	})
	originalNativeHTTPDiagnosticContracts(t)
}

// Runs within the existing owner-lifetime root; no native capacity evidence is
// created by these observer/privacy assertions.
func originalNativeHTTPDiagnosticContracts(t *testing.T) {
	var output bytes.Buffer
	priorWriter, priorFlags, priorPrefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&output)
	log.SetFlags(log.Ldate | log.Ltime)
	log.SetPrefix("")
	defer func() { log.SetOutput(priorWriter); log.SetFlags(priorFlags); log.SetPrefix(priorPrefix) }()
	original, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	owners, err := httpapi.NewNativeOriginalWorkflowOwners(original)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "private-token-body-header-query-DO-NOT-LOG"
	calls := 0
	handler := originalNativeHTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("X-Test-Mode") == "panic" {
			panic(secret)
		}
		if r.Method == http.MethodGet {
			return
		}
		w.Header().Set("X-Private-Test", secret)
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(secret))
	}), owners)
	body := &originalNativeUnreadBody{}
	request := httptest.NewRequest(http.MethodPost, "https://core.invalid/internal/capacity/guest-provisioning/registrations?private="+secret, body)
	request.Header.Set("Authorization", secret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || response.Body.String() != secret || response.Header().Get("X-Private-Test") != secret || body.reads != 0 || body.closes != 0 {
		t.Fatal("diagnostic changed the original HTTP response or read the request")
	}
	id := "ab12891f-db5a-4bef-a4c3-7d8dd10686b3"
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://core.invalid/internal/capacity/guest-provisioning/preregistrations/"+id, nil))
	before := output.Len()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "https://core.invalid/internal/capacity/guest-provisioning/installations", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://core.invalid/internal/capacity/guest-provisioning/preregistrations/"+id+"/create-witness", nil))
	if output.Len() != before {
		t.Fatal("unrelated original routes were logged")
	}
	panicRequest := httptest.NewRequest(http.MethodPost, "https://core.invalid/internal/capacity/guest-provisioning/registrations", nil)
	panicRequest.Header.Set("X-Test-Mode", "panic")
	func() {
		defer func() {
			if recover() != secret {
				t.Fatal("observer changed original panic")
			}
		}()
		handler.ServeHTTP(httptest.NewRecorder(), panicRequest)
	}()
	if err := owners.Join(context.Background()); err != nil {
		t.Fatal(err)
	}
	beforeCalls := calls
	closed := httptest.NewRecorder()
	handler.ServeHTTP(closed, httptest.NewRequest(http.MethodPost, "https://core.invalid/internal/capacity/guest-provisioning/registrations", nil))
	if closed.Code != http.StatusServiceUnavailable || calls != beforeCalls {
		t.Fatal("observer bypassed sealed owner refusal")
	}
	text := output.String()
	for _, expected := range []string{
		"ordinal=1 route=registration_post phase=end status=409 status_observed=true returned=true",
		"ordinal=2 route=receipt_get phase=end status=0 status_observed=false returned=true",
		"ordinal=3 route=registration_post phase=end status=0 status_observed=false returned=false",
		"ordinal=4 route=registration_post phase=end status=503 status_observed=true returned=true",
	} {
		if !strings.Contains(text, expected) {
			t.Fatal("actual status/handler return observation lost", expected)
		}
	}
	if strings.Count(text, "phase=begin") != 4 || strings.Count(text, "phase=end") != 4 || strings.Contains(text, secret) || strings.Contains(text, id) || strings.Contains(text, "Authorization") || strings.Contains(text, "core.invalid") {
		t.Fatal("diagnostic leaked private data or changed call multiplicity")
	}
}

type originalNativeUnreadBody struct{ reads, closes int }

func (b *originalNativeUnreadBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (b *originalNativeUnreadBody) Close() error             { b.closes++; return nil }
