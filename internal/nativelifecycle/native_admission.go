package lifecycle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const NativeAdmissionPath = "/internal-runtime/native-admission"
const NativeAdmissionKeyHeader = "X-Native-Admission-Key"
const NativeAdmissionSchemaVersion = 2

var ErrNativeAdmission = errors.New("native process admission unavailable")

// The process nonce is minted by this main invocation, not projected by a
// caller. A restarted process cannot open roots with its predecessor's frame.
type NativeAdmissionChallenge struct {
	NativeTerminationChallenge
	ProcessNonce string `json:"process_nonce"`
}

type NativeAdmissionObservation struct {
	SchemaVersion    int                       `json:"schema_version"`
	Namespace        string                    `json:"namespace"`
	PodName          string                    `json:"pod_name"`
	PodUID           string                    `json:"pod_uid"`
	ImageDigest      string                    `json:"image_digest"`
	LaneRosterSHA256 string                    `json:"lane_roster_sha256"`
	ProcessNonce     string                    `json:"process_nonce"`
	ObservedAt       time.Time                 `json:"observed_at"`
	State            string                    `json:"state"`
	Challenge        *NativeAdmissionChallenge `json:"challenge,omitempty"`
	ChallengeSHA256  string                    `json:"challenge_sha256,omitempty"`
}

type NativeAdmissionGuard struct {
	group              *Group
	cfg                NativeTerminationConfig
	enabled            bool
	key, nonce, roster string
	bootedAt           time.Time
	mu                 sync.Mutex
	opened             bool
	originHash         string
}

// Construction performs no network or background work. Consumers mount the
// authenticated observation on an already-owned health/metrics listener, await
// projection before business roots, and open roots after actual startup returns.
func NewNativeAdmissionGuardFromEnvironment(group *Group) (*NativeAdmissionGuard, error) {
	g := &NativeAdmissionGuard{group: group}
	switch os.Getenv("NATIVE_ADMISSION_ENABLED") {
	case "", "false":
		return g, nil
	case "true":
	default:
		return nil, ErrNativeAdmission
	}
	g.enabled, g.key = true, os.Getenv("NATIVE_ADMISSION_KEY")
	g.cfg = NativeTerminationConfig{ProjectionDirectory: os.Getenv("NATIVE_TERMINATION_PROJECTION_DIR"), ImageDigest: os.Getenv("NATIVE_TERMINATION_IMAGE_DIGEST"), MessageFile: os.Getenv("NATIVE_TERMINATION_MESSAGE_FILE")}
	if g.cfg.MessageFile == "" {
		g.cfg.MessageFile = "/dev/termination-log"
	}
	if group == nil || len(g.key) < 32 || len(g.key) > 512 || !filepath.IsAbs(g.cfg.ProjectionDirectory) || filepath.Clean(g.cfg.ProjectionDirectory) != g.cfg.ProjectionDirectory || strings.Contains(g.cfg.ProjectionDirectory, "..") || !nativeImageDigest(g.cfg.ImageDigest) || !filepath.IsAbs(g.cfg.MessageFile) {
		return nil, ErrNativeAdmission
	}
	names := make([]string, 0)
	for name := range group.Snapshot().Lanes {
		names = append(names, name)
	}
	var err error
	g.roster, err = NativeTerminationRosterSHA256(names)
	if err != nil {
		return nil, ErrNativeAdmission
	}
	g.nonce, g.bootedAt = uuid.NewString(), time.Now().UTC()
	return g, nil
}

func (g *NativeAdmissionGuard) Observation() (NativeAdmissionObservation, error) {
	var out NativeAdmissionObservation
	if g == nil || !g.enabled {
		return out, ErrNativeAdmission
	}
	root, err := filepath.EvalSymlinks(g.cfg.ProjectionDirectory)
	if err != nil {
		return out, ErrNativeAdmission
	}
	revision, err := filepath.EvalSymlinks(filepath.Join(root, "..data"))
	if err != nil || !strings.HasPrefix(revision, root+string(filepath.Separator)) {
		return out, ErrNativeAdmission
	}
	read := func(name string) ([]byte, error) { return nativeReadBounded(filepath.Join(revision, name)) }
	values := map[string]string{}
	for _, name := range []string{"uid", "namespace", "name"} {
		raw, err := read(name)
		if err != nil {
			return out, ErrNativeAdmission
		}
		values[name] = string(raw)
	}
	if !nativeUUID(values["uid"]) || !nativeIdentity(values["namespace"]) || !nativeIdentity(values["name"]) {
		return out, ErrNativeAdmission
	}
	out = NativeAdmissionObservation{SchemaVersion: 2, Namespace: values["namespace"], PodName: values["name"], PodUID: values["uid"], ImageDigest: g.cfg.ImageDigest, LaneRosterSHA256: g.roster, ProcessNonce: g.nonce, ObservedAt: time.Now().UTC(), State: "waiting_projection"}
	raw, err := read("challenge")
	if err != nil {
		return out, ErrNativeAdmission
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		var challenge NativeAdmissionChallenge
		if nativeAdmissionDecode(raw, &challenge) != nil {
			out.State = "invalid_projection"
		} else {
			base := challenge.NativeTerminationChallenge
			base.SchemaVersion = NativeTerminationSchemaVersion
			switch {
			case challenge.SchemaVersion != 2 || !validNativeChallenge(base, out.ObservedAt) || challenge.PodUID != out.PodUID || challenge.Namespace != out.Namespace || challenge.PodName != out.PodName || challenge.ImageDigest != g.cfg.ImageDigest || challenge.LaneRosterSHA256 != g.roster:
				out.State = "invalid_projection"
			case challenge.ProcessNonce != g.nonce:
				out.State = "foreign_process_projection"
			case challenge.IssuedAt.Before(g.bootedAt):
				out.State = "invalid_projection"
			default:
				digest := sha256.Sum256(raw)
				out.Challenge, out.ChallengeSHA256, out.State = &challenge, hex.EncodeToString(digest[:]), "projection_observed"
			}
		}
	}
	current, err := filepath.EvalSymlinks(filepath.Join(root, "..data"))
	if err != nil || current != revision {
		return NativeAdmissionObservation{}, ErrNativeAdmission
	}
	g.mu.Lock()
	if out.Challenge != nil {
		if g.originHash != "" && g.originHash != out.ChallengeSHA256 {
			out.Challenge, out.ChallengeSHA256, out.State = nil, "", "origin_changed"
		} else {
			g.originHash = out.ChallengeSHA256
		}
	}
	opened := g.opened
	g.mu.Unlock()
	if g.group.Snapshot().Draining {
		out.State = "draining"
	} else if opened && out.Challenge != nil {
		out.State = "roots_open"
	}
	return out, nil
}

func nativeAdmissionDecode(raw []byte, out *NativeAdmissionChallenge) error {
	allowed := map[string]bool{"schema_version": true, "namespace": true, "pod_name": true, "pod_uid": true, "workload_uid": true, "container_name": true, "image_digest": true, "intent_generation": true, "drain_nonce": true, "issued_at": true, "lane_roster_sha256": true, "process_nonce": true}
	d := json.NewDecoder(bytes.NewReader(raw))
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return ErrNativeAdmission
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || !allowed[key] || seen[key] {
			return ErrNativeAdmission
		}
		seen[key] = true
		if d.Decode(new(json.RawMessage)) != nil {
			return ErrNativeAdmission
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || len(seen) != len(allowed) || d.Decode(new(any)) != io.EOF || json.Unmarshal(raw, out) != nil {
		return ErrNativeAdmission
	}
	return nil
}

// Cancellation returns from this synchronous waiter. It neither marks an
// unstarted worker inactive nor substitutes for the consumer's shutdown joins.
func (g *NativeAdmissionGuard) WaitForProjection(ctx context.Context) error {
	if g == nil {
		return ErrNativeAdmission
	}
	if !g.enabled {
		return nil
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		observation, err := g.Observation()
		if err == nil && observation.Challenge != nil && observation.State != "draining" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// The service owner calls this only after actual startup acknowledgements.
// It takes no caller receipt, Pod input, permission flag or grant.
func (g *NativeAdmissionGuard) OpenRootAdmission() error {
	if g == nil {
		return ErrNativeAdmission
	}
	if !g.enabled {
		return nil
	}
	out, err := g.Observation()
	if err != nil || out.Challenge == nil || out.State == "draining" {
		return ErrNativeAdmission
	}
	snapshot := g.group.Snapshot()
	if snapshot.Draining {
		return ErrNativeAdmission
	}
	for _, state := range snapshot.Lanes {
		if state == Pending || state == Failed {
			return ErrNativeAdmission
		}
	}
	g.mu.Lock()
	g.opened = true
	g.mu.Unlock()
	return nil
}

func (g *NativeAdmissionGuard) RootsOpen() bool {
	if g == nil {
		return false
	}
	if !g.enabled {
		return true
	}
	out, err := g.Observation()
	return err == nil && out.State == "roots_open"
}

// Apply only to external roots, never required descendants or cleanup.
func (g *NativeAdmissionGuard) WrapRoot(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.RootsOpen() {
			http.Error(w, "native admission unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
}

func (g *NativeAdmissionGuard) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || !g.enabled {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 || len(r.Header.Values(NativeAdmissionKeyHeader)) != 1 || len(r.Header.Get(NativeAdmissionKeyHeader)) != len(g.key) || subtle.ConstantTimeCompare([]byte(r.Header.Get(NativeAdmissionKeyHeader)), []byte(g.key)) != 1 {
			http.Error(w, "native admission denied", http.StatusForbidden)
			return
		}
		out, err := g.Observation()
		if err != nil {
			http.Error(w, "native admission unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
}

type NativeAdmissionTerminationReceipt struct {
	NativeAdmissionChallenge
	JoinedAt      time.Time        `json:"joined_at"`
	Lanes         map[string]State `json:"lanes"`
	RootAdmission string           `json:"root_admission"`
}

// Schema one remains unchanged when the new admission feature is disabled.
// Schema two binds this actual main process nonce and its ever-opened gate.
// "never_opened" does not invent startup or admission for future workers.
func (g *NativeAdmissionGuard) WriteTerminationReceipt() (bool, error) {
	if g == nil {
		return false, ErrNativeAdmission
	}
	if !g.enabled {
		return WriteNativeTerminationReceiptFromEnvironment(g.group)
	}
	snapshot := g.group.Snapshot()
	if !snapshot.Draining || !snapshot.Drained {
		return false, ErrNativeTerminationReceipt
	}
	for _, state := range snapshot.Lanes {
		if state != Done && state != Inactive {
			return false, ErrNativeTerminationReceipt
		}
	}
	out, err := g.Observation()
	if err != nil || out.Challenge == nil {
		return false, ErrNativeTerminationReceipt
	}
	g.mu.Lock()
	opened := g.opened
	g.mu.Unlock()
	rootState := "never_opened"
	if opened {
		rootState = "previously_opened"
	}
	receipt := NativeAdmissionTerminationReceipt{NativeAdmissionChallenge: *out.Challenge, JoinedAt: time.Now().UTC(), Lanes: snapshot.Lanes, RootAdmission: rootState}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw)+1 > NativeTerminationMaximumBytes {
		return false, ErrNativeTerminationReceipt
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(g.cfg.MessageFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return false, ErrNativeTerminationReceipt
	}
	n, writeErr := file.Write(raw)
	if writeErr == nil && n != len(raw) {
		writeErr = io.ErrShortWrite
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return false, ErrNativeTerminationReceipt
	}
	return true, nil
}
