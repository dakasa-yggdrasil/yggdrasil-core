package capacity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

var ErrGuestOriginalTransport = errors.New("original private Guest transport unavailable; recover by exact GET")

const GuestOriginalBodyNoRead = "no_original_body_read"
const GuestOriginalBodyCompleteRead = "complete_original_body_read"
const GuestOriginalBodyIncompleteRead = "incomplete_original_body_read"

type GuestOriginalHTTPReturn struct {
	StartedAt             time.Time
	DoStartedAt           time.Time
	DriverReturnedAt      time.Time
	PreflightFailed       bool
	DoReturnedAt          time.Time
	ReadReturnedAt        time.Time
	CloseReturnedAt       time.Time
	Status                int
	Body                  []byte
	ReceivedBodyBytes     int
	ResponseSHA256        string
	ResponseBodyScope     string
	RetainedPrefixBytes   int
	RetainedPrefixSHA256  string
	DoFailed              bool
	ReadFailed            bool
	CloseFailed           bool
	OriginalContextFailed bool
}

type GuestOriginalHTTPClient struct {
	origin    string
	client    *http.Client
	transport *http.Transport
}

// Credentials are loaded from the exact approved source references outside
// any database transaction. The old read-only SSH credential is never used.
func NewGuestOriginalHTTPClient(member model.CapacityGuestRetirementMemberBinding, caPEM, certificatePEM, keyPEM []byte) (*GuestOriginalHTTPClient, error) {
	u, err := url.Parse(member.Origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || len(caPEM) == 0 || len(caPEM) > 1<<20 || len(certificatePEM) == 0 || len(certificatePEM) > 1<<20 || len(keyPEM) == 0 || len(keyPEM) > 1<<20 {
		return nil, ErrGuestOriginalTransport
	}
	ca := x509.NewCertPool()
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil || !ca.AppendCertsFromPEM(caPEM) {
		return nil, ErrGuestOriginalTransport
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca, Certificates: []tls.Certificate{certificate}}, DisableCompression: true, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 4}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrGuestOriginalTransport }}
	return &GuestOriginalHTTPClient{origin: member.Origin, client: client, transport: transport}, nil
}

func (c *GuestOriginalHTTPClient) Close() {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
}

// Each invocation is exactly one HTTP call. The workflow/store decides whether
// it is the sole original POST or a same-identity read; this client never retries.
func (c *GuestOriginalHTTPClient) Original(ctx context.Context, method, path string, body []byte) (result GuestOriginalHTTPReturn, returnedError error) {
	result.StartedAt = time.Now().UTC()
	result.ResponseBodyScope = GuestOriginalBodyNoRead
	result.RetainedPrefixSHA256 = BusinessCreationSHA256([]byte{})
	defer func() { result.DriverReturnedAt = time.Now().UTC(); result.OriginalContextFailed = ctx.Err() != nil }()
	allowed := method == http.MethodGet && path == "/v1/runtime-snapshot" || (method == http.MethodPost || method == http.MethodGet) && path == "/v1/retirement" || method == http.MethodGet && GuestOriginalNativeQEMUProviderEnabled("native-qemu") && (path == "/v1/qualification-serving-probe" || path == "/v1/qualification-source-refusal")
	if c == nil || c.client == nil || !allowed || len(body) < 1 || len(body) > GuestBootstrapLimit || ctx.Err() != nil {
		result.PreflightFailed = true
		return result, ErrGuestOriginalTransport
	}
	if deadline, exists := ctx.Deadline(); !exists || !deadline.After(result.StartedAt) {
		result.PreflightFailed = true
		return result, ErrGuestOriginalTransport
	}
	request, err := http.NewRequestWithContext(ctx, method, c.origin+path, bytes.NewReader(body))
	if err != nil {
		result.PreflightFailed = true
		return result, ErrGuestOriginalTransport
	}
	request.Header.Set("Content-Type", "application/json")
	result.DoStartedAt = time.Now().UTC()
	response, doErr := c.client.Do(request)
	result.DoReturnedAt = time.Now().UTC()
	result.DoFailed = doErr != nil
	if response != nil && response.Body != nil {
		result.Status = response.StatusCode
		var readErr error
		result.Body, readErr = io.ReadAll(io.LimitReader(response.Body, GuestBootstrapLimit+1))
		result.ReadReturnedAt = time.Now().UTC()
		// These facts describe the ACTUAL bounded read (including cap+1),
		// before retaining its smaller in-memory prefix. They never claim an
		// unobserved whole HTTP response or a persisted private SQL body.
		result.ReceivedBodyBytes = len(result.Body)
		result.ResponseSHA256 = BusinessCreationSHA256(result.Body)
		result.ResponseBodyScope = GuestOriginalBodyCompleteRead
		if readErr != nil || len(result.Body) > GuestBootstrapLimit {
			result.ResponseBodyScope = GuestOriginalBodyIncompleteRead
		}
		closeErr := response.Body.Close()
		result.CloseReturnedAt = time.Now().UTC()
		result.ReadFailed, result.CloseFailed = readErr != nil || len(result.Body) > GuestBootstrapLimit, closeErr != nil
		if len(result.Body) > GuestBootstrapLimit {
			// Retain the bounded original prefix as an explicitly incomplete
			// read, never a successful typed reply or a completeness witness.
			result.Body = result.Body[:GuestBootstrapLimit]
		}
		result.RetainedPrefixBytes = len(result.Body)
		result.RetainedPrefixSHA256 = BusinessCreationSHA256(result.Body)
	} else if doErr == nil {
		result.DoFailed = true
	}
	result.OriginalContextFailed = ctx.Err() != nil
	if result.DoFailed || result.ReadFailed || result.CloseFailed || result.OriginalContextFailed || result.Status != http.StatusOK {
		return result, errors.Join(ErrGuestOriginalTransport, ctx.Err())
	}
	return result, nil
}

func GuestOriginalHTTPDecode(result GuestOriginalHTTPReturn, out any) error {
	if result.ResponseBodyScope != GuestOriginalBodyCompleteRead || !GuestOriginalHTTPBodyFactsValid(result.ResponseBodyScope, result.ReadReturnedAt, result.ReceivedBodyBytes, result.ResponseSHA256, result.RetainedPrefixBytes, result.RetainedPrefixSHA256, result.ReadFailed) || result.RetainedPrefixBytes != len(result.Body) || result.RetainedPrefixSHA256 != BusinessCreationSHA256(result.Body) || result.PreflightFailed || result.StartedAt.IsZero() || result.DoStartedAt.IsZero() || result.DoReturnedAt.IsZero() || result.ReadReturnedAt.IsZero() || result.CloseReturnedAt.IsZero() || result.DriverReturnedAt.IsZero() || result.DoStartedAt.Before(result.StartedAt) || result.DoReturnedAt.Before(result.DoStartedAt) || result.DriverReturnedAt.Before(result.CloseReturnedAt) || result.DoFailed || result.ReadFailed || result.CloseFailed || result.OriginalContextFailed || result.Status != http.StatusOK || result.ReadReturnedAt.Before(result.DoReturnedAt) || result.CloseReturnedAt.Before(result.ReadReturnedAt) || DecodeGuestLifecycle(result.Body, out) != nil {
		return fmt.Errorf("complete original private Guest HTTP return required")
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(canonical, result.Body) {
		return fmt.Errorf("canonical original private Guest reply required")
	}
	return nil
}

// Validate the source read/prefix projection only. Close, context, HTTP status
// and SQL retention remain independent; this function grants no authority.
func GuestOriginalHTTPBodyFactsValid(scope string, readAt time.Time, received int, responseSHA string, prefix int, prefixSHA string, readFailed bool) bool {
	if received < 0 || received > GuestBootstrapLimit+1 || prefix < 0 || prefix > GuestBootstrapLimit || prefix != min(received, GuestBootstrapLimit) || !ValidDigest(prefixSHA) || (prefix == 0 && prefixSHA != BusinessCreationSHA256([]byte{})) {
		return false
	}
	if scope == GuestOriginalBodyNoRead {
		return readAt.IsZero() && received == 0 && responseSHA == "" && prefix == 0 && prefixSHA == BusinessCreationSHA256([]byte{}) && !readFailed
	}
	if readAt.IsZero() || !ValidDigest(responseSHA) || (received <= GuestBootstrapLimit && responseSHA != prefixSHA) {
		return false
	}
	if scope == GuestOriginalBodyCompleteRead {
		return !readFailed && received <= GuestBootstrapLimit && prefix == received && responseSHA == prefixSHA
	}
	return scope == GuestOriginalBodyIncompleteRead && readFailed
}
