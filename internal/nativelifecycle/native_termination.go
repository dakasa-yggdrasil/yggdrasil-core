package lifecycle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

const NativeTerminationSchemaVersion = 1
const NativeTerminationMaximumBytes = 4096
const NativeTerminationMaximumGeneration int64 = 9007199254740991

var ErrNativeTerminationReceipt = errors.New("native termination receipt unavailable")

// NativeTerminationChallenge is an operator-bound, projected-file challenge.
// It is not a business/provider quiescence or useful-capacity declaration.
type NativeTerminationChallenge struct {
	SchemaVersion    int       `json:"schema_version"`
	Namespace        string    `json:"namespace"`
	PodName          string    `json:"pod_name"`
	PodUID           string    `json:"pod_uid"`
	WorkloadUID      string    `json:"workload_uid"`
	ContainerName    string    `json:"container_name"`
	ImageDigest      string    `json:"image_digest"`
	IntentGeneration int64     `json:"intent_generation"`
	DrainNonce       string    `json:"drain_nonce"`
	IssuedAt         time.Time `json:"issued_at"`
	LaneRosterSHA256 string    `json:"lane_roster_sha256"`
}

// NativeTerminationReceipt must also be matched to current kubelet termination
// status and a retained exact Pod/container identity by the protected observer.
// The file alone never establishes that the process or Pod has terminated.
type NativeTerminationReceipt struct {
	NativeTerminationChallenge
	JoinedAt time.Time        `json:"joined_at"`
	Lanes    map[string]State `json:"lanes"`
}

type NativeTerminationConfig struct {
	// ProjectionDirectory contains one Kubernetes downward API projection:
	// ..data, uid, namespace, name and challenge. A single ..data revision is
	// resolved before reads; partial/deleted revisions fail closed.
	ProjectionDirectory string
	// ImageDigest is a fixed boot declaration, not a dynamic annotation env.
	// The observer separately verifies the actual native container image ID.
	ImageDigest string
	MessageFile string
}

// NativeTerminationRosterSHA256 fingerprints sorted declared lane names using
// their compact JSON array. Lane states and scrape availability are not inputs.
func NativeTerminationRosterSHA256(names []string) (string, error) {
	if len(names) == 0 || len(names) > MaxLanes {
		return "", ErrNativeTerminationReceipt
	}
	ordered := append([]string(nil), names...)
	sort.Strings(ordered)
	for i, name := range ordered {
		if !namePattern.MatchString(name) || (i > 0 && ordered[i-1] == name) {
			return "", ErrNativeTerminationReceipt
		}
	}
	raw, err := json.Marshal(ordered)
	if err != nil {
		return "", ErrNativeTerminationReceipt
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

// WriteNativeTerminationReceiptFromEnvironment is explicitly default-noop.
// The dynamic challenge and Pod identity are read from projected files at full
// completion, never captured from annotation-derived env at process startup.
func WriteNativeTerminationReceiptFromEnvironment(group *Group) (bool, error) {
	dir := os.Getenv("NATIVE_TERMINATION_PROJECTION_DIR")
	if dir == "" {
		return false, nil
	}
	message := os.Getenv("NATIVE_TERMINATION_MESSAGE_FILE")
	if message == "" {
		message = "/dev/termination-log"
	}
	return WriteNativeTerminationReceipt(group, NativeTerminationConfig{
		ProjectionDirectory: dir,
		ImageDigest:         os.Getenv("NATIVE_TERMINATION_IMAGE_DIGEST"),
		MessageFile:         message,
	})
}

// WriteNativeTerminationReceipt requires a closed actual-return roster. A
// Failed lane remains failure and cannot produce the successful local receipt.
// Native observers still require current Terminated exit zero, matching image,
// challenge, UID, container identity and timestamps before finalizer release.
func WriteNativeTerminationReceipt(group *Group, cfg NativeTerminationConfig) (bool, error) {
	if cfg.ProjectionDirectory == "" {
		return false, nil
	}
	if group == nil || !filepath.IsAbs(cfg.ProjectionDirectory) || !filepath.IsAbs(cfg.MessageFile) || !nativeImageDigest(cfg.ImageDigest) {
		return false, ErrNativeTerminationReceipt
	}
	snapshot := group.Snapshot()
	if !snapshot.Draining || !snapshot.Drained {
		return false, ErrNativeTerminationReceipt
	}
	names := make([]string, 0, len(snapshot.Lanes))
	for name, state := range snapshot.Lanes {
		if state != Done && state != Inactive {
			return false, ErrNativeTerminationReceipt
		}
		names = append(names, name)
	}
	roster, err := NativeTerminationRosterSHA256(names)
	if err != nil {
		return false, err
	}
	// Kubernetes swaps ..data atomically. Read one revision instead of mixing
	// uid/name/namespace/challenge through independently changing file links.
	revision, err := filepath.EvalSymlinks(filepath.Join(cfg.ProjectionDirectory, "..data"))
	if err != nil {
		return false, ErrNativeTerminationReceipt
	}
	root, err := filepath.EvalSymlinks(cfg.ProjectionDirectory)
	if err != nil || !strings.HasPrefix(revision, root+string(filepath.Separator)) {
		return false, ErrNativeTerminationReceipt
	}
	read := func(name string) ([]byte, error) {
		return nativeReadBounded(filepath.Join(revision, name))
	}
	challengeRaw, err := read("challenge")
	if err != nil {
		return false, ErrNativeTerminationReceipt
	}
	var challenge NativeTerminationChallenge
	decoder := json.NewDecoder(bytes.NewReader(challengeRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&challenge) != nil || decoder.Decode(new(any)) != io.EOF || !nativeUniqueObject(challengeRaw) {
		return false, ErrNativeTerminationReceipt
	}
	now := time.Now().UTC()
	if !validNativeChallenge(challenge, now) || challenge.ImageDigest != cfg.ImageDigest || challenge.LaneRosterSHA256 != roster {
		return false, ErrNativeTerminationReceipt
	}
	for name, expected := range map[string]string{"uid": challenge.PodUID, "namespace": challenge.Namespace, "name": challenge.PodName} {
		value, err := read(name)
		if err != nil || string(value) != expected {
			return false, ErrNativeTerminationReceipt
		}
	}
	receipt := NativeTerminationReceipt{NativeTerminationChallenge: challenge, JoinedAt: now, Lanes: snapshot.Lanes}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw)+1 > NativeTerminationMaximumBytes {
		return false, ErrNativeTerminationReceipt
	}
	raw = append(raw, '\n')
	file, err := os.OpenFile(cfg.MessageFile, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
	if err != nil {
		return false, ErrNativeTerminationReceipt
	}
	written, writeErr := file.Write(raw)
	if writeErr == nil && written != len(raw) {
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

func nativeReadBounded(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > NativeTerminationMaximumBytes {
		return nil, ErrNativeTerminationReceipt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrNativeTerminationReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(file, NativeTerminationMaximumBytes+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(raw) > NativeTerminationMaximumBytes {
		return nil, ErrNativeTerminationReceipt
	}
	return raw, nil
}

func nativeImageDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func nativeIdentity(value string) bool {
	if value == "" || len(value) > 253 || strings.TrimSpace(value) != value {
		return false
	}
	for _, ch := range value {
		if ch < '!' || ch > '~' || ch == '/' || ch == '\\' {
			return false
		}
	}
	return true
}

func nativeUUID(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func validNativeChallenge(c NativeTerminationChallenge, now time.Time) bool {
	if c.SchemaVersion != NativeTerminationSchemaVersion || !nativeUUID(c.PodUID) || !nativeUUID(c.WorkloadUID) || !nativeUUID(c.DrainNonce) || c.IntentGeneration < 1 || c.IntentGeneration > NativeTerminationMaximumGeneration || c.IssuedAt.IsZero() || c.IssuedAt.After(now) || !nativeImageDigest(c.ImageDigest) || len(c.LaneRosterSHA256) != 64 || c.LaneRosterSHA256 != strings.ToLower(c.LaneRosterSHA256) {
		return false
	}
	if _, err := hex.DecodeString(c.LaneRosterSHA256); err != nil {
		return false
	}
	return nativeIdentity(c.Namespace) && nativeIdentity(c.PodName) && nativeIdentity(c.ContainerName)
}

// The challenge is a closed flat object. Duplicate keys are ambiguous even
// when their values happen to agree and must never become an identity proof.
func nativeUniqueObject(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return false
	}
	canonical := map[string]bool{
		"schema_version": true, "namespace": true, "pod_name": true, "pod_uid": true,
		"workload_uid": true, "container_name": true, "image_digest": true,
		"intent_generation": true, "drain_nonce": true, "issued_at": true,
		"lane_roster_sha256": true,
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		name, ok := token.(string)
		if err != nil || !ok || !canonical[name] || seen[name] {
			return false
		}
		seen[name] = true
		if decoder.Decode(new(any)) != nil {
			return false
		}
	}
	closing, err := decoder.Token()
	return err == nil && closing == json.Delim('}')
}
