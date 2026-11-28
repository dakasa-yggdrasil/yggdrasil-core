package repository

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

type nativeReadinessControlBody struct {
	io.Reader
	closeErr error
	closed   int
	onClose  func()
}

func (b *nativeReadinessControlBody) Close() error {
	b.closed++
	if b.onClose != nil {
		b.onClose()
	}
	return b.closeErr
}

type nativeReadinessFaultReader struct{}

func (nativeReadinessFaultReader) Read([]byte) (int, error) {
	return 0, errors.New("private fixture read failure")
}

func TestNativeReadinessOriginalControlRequiresReadCloseContextAndExactSource(t *testing.T) {
	const target = "https://10.244.1.2:9446/probe/report"
	const source = "1111111111111111111111111111111111111111"
	for _, fault := range []string{"none", "read", "close", "cancel_at_close", "call_with_body", "wrong_method", "wrong_url", "missing_source", "duplicate_source", "wrong_source", "missing_tls", "wrong_mime", "overflow"} {
		t.Run(fault, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			body := &nativeReadinessControlBody{Reader: bytes.NewBufferString(`{"private_fixture":"original"}`)}
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			response := &http.Response{StatusCode: 200, Request: request, Body: body, Header: http.Header{"X-Yggdrasil-Source-Commit": {source}, "Content-Type": {"application/json"}}, TLS: &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{{}}}}}
			var callErr error
			switch fault {
			case "read":
				body.Reader = nativeReadinessFaultReader{}
			case "close":
				body.closeErr = errors.New("private fixture close failure")
			case "cancel_at_close":
				body.onClose = cancel
			case "call_with_body":
				callErr = errors.New("private fixture transport error")
			case "wrong_method":
				response.Request.Method = http.MethodPost
			case "wrong_url":
				response.Request.URL, _ = url.Parse("https://10.244.1.3:9446/probe/report")
			case "missing_source":
				response.Header.Del("X-Yggdrasil-Source-Commit")
			case "duplicate_source":
				response.Header.Add("X-Yggdrasil-Source-Commit", source)
			case "wrong_source":
				response.Header.Set("X-Yggdrasil-Source-Commit", strings.Repeat("2", 40))
			case "missing_tls":
				response.TLS = nil
			case "wrong_mime":
				response.Header.Set("Content-Type", "text/plain")
			case "overflow":
				body.Reader = bytes.NewReader(bytes.Repeat([]byte{'x'}, (256<<10)+1))
			}
			status, raw, complete := nativeReadinessOriginalControl(ctx, response, callErr, http.MethodGet, target, source)
			if status != 200 || body.closed != 1 || complete != (fault == "none") || len(raw) > 256<<10 {
				t.Fatal("original completion/source guard drift", fault, status, complete, body.closed, len(raw))
			}
			if fault == "close" && !bytes.Contains(raw, []byte("original")) {
				t.Fatal("Close failure discarded original private bytes")
			}
			if fault == "overflow" && len(raw) != 256<<10 {
				t.Fatal("overflow custody did not retain exact bounded prefix")
			}
		})
	}
}

func TestNativeReadinessRunKeysRepresentationsAndCloseNeverExposeSeeds(t *testing.T) {
	raw := bytes.Repeat([]byte("private-readiness-seed-value-"), 16)[:nativeReadinessSeedCount*32]
	keys, err := newNativeReadinessKeys(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []any{keys, *keys} {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, text := range []string{fmt.Sprint(v), fmt.Sprintf("%+v", v), fmt.Sprintf("%#v", v), string(encoded)} {
			if strings.Contains(text, string(raw)) || strings.Contains(text, base64.StdEncoding.EncodeToString(raw)) {
				t.Fatal("private run material leaked through representation")
			}
		}
	}
	copy := append([]byte(nil), keys.seeds...)
	owned := keys.seeds
	keys.close()
	if keys.seeds != nil {
		t.Fatal("owned seed handle remained usable")
	}
	if _, err := keys.key(0); err == nil {
		t.Fatal("closed run key regenerated a signing identity")
	}
	if !bytes.Equal(copy, raw) {
		t.Fatal("representation modified original fixture")
	}
	if !bytes.Equal(owned, make([]byte, len(owned))) {
		t.Fatal("Close did not wipe owned seed storage")
	}
}

func TestNativeReadinessPrivateJournalBoundPreservesClosedCanonicalCodec(t *testing.T) {
	large := map[string]any{"ciphertext": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 2<<20)), "nonce": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 12))}
	raw, err := json.Marshal(large)
	if err != nil {
		t.Fatal(err)
	}
	var out nativeReadinessCipher
	if capacity.DecodeNativeCapacity(json.RawMessage(raw), &out) == nil {
		t.Fatal("public2MiB decoder was silently enlarged")
	}
	if capacity.DecodeNativeReadinessJournalJSON(raw, &out) != nil || len(out.Ciphertext) != 2<<20 || len(out.Nonce) != 12 {
		t.Fatal("bounded private original archive could not be read")
	}
	for _, bad := range []string{`{"nonce":"","nonce":"","ciphertext":""}`, `{"Nonce":"","ciphertext":""}`, `{"nonce":"","ciphertext":"","unknown":""}`, `{"nonce":"","ciphertext":"","ſchema":1}`} {
		if capacity.DecodeNativeReadinessJournalJSON([]byte(bad), &out) == nil {
			t.Fatal("private archive accepted duplicate/alias/unknown fields")
		}
	}
	huge := bytes.Repeat([]byte{' '}, (48<<20)+1)
	if capacity.DecodeNativeReadinessJournalJSON(huge, &out) == nil {
		t.Fatal("private archive exceeded fixed48MiB bound")
	}
}
