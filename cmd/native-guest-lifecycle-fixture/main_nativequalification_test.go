//go:build linux && nativequalification

package main

import (
	"context"
	"errors"
	"net"
	"net/http"
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
}
