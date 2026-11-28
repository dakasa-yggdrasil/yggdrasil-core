package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
)

// These are immutable publication identities, not observations of a running
// process. A native Pod read must still supply an allowed actual imageID.
type nativeReadinessPublishedImage struct {
	Image, SourceCommit string
	RuntimeDigests      []string
}

// The exact receipt SHA belongs to protected process configuration. The
// operator first receives/verifies normal publication through its real CI and
// registry sources; this offline loader does not authenticate GitHub or turn
// an arbitrary JSON assertion into a publisher attestation.
func nativeReadinessLoadPublishedImage(path, rawSHA, expectedImage, expectedSource, kind string) (nativeReadinessPublishedImage, error) {
	raw, err := nativeReadinessReadFile(path, 1<<20, false)
	if err != nil {
		return nativeReadinessPublishedImage{}, errNativeReadinessRun
	}
	return nativeReadinessParsePublishedImage(raw, rawSHA, expectedImage, expectedSource, kind)
}

func nativeReadinessParsePublishedImage(raw []byte, rawSHA, expectedImage, expectedSource, kind string) (nativeReadinessPublishedImage, error) {
	var zero nativeReadinessPublishedImage
	h := sha256.Sum256(raw)
	source, err := hex.DecodeString(expectedSource)
	if len(raw) == 0 || len(raw) > 1<<20 || !nativeReadinessSHA(rawSHA) || hex.EncodeToString(h[:]) != rawSHA || err != nil || len(source) != 20 || hex.EncodeToString(source) != expectedSource || !nativeReadinessPinnedImage(expectedImage) {
		return zero, errNativeReadinessRun
	}
	switch kind {
	case "core":
		return nativeReadinessParseCorePublication(raw, expectedImage, expectedSource)
	case "probe":
		return nativeReadinessParseProbePublication(raw, expectedImage, expectedSource)
	}
	return zero, errNativeReadinessRun
}

type nativeReadinessPublishedProbePlatform struct {
	Head                       string `json:"head"`
	EventSHA                   string `json:"event_sha"`
	Architecture               string `json:"architecture"`
	ImageID                    string `json:"image_id"`
	BinarySHA256               string `json:"binary_sha256"`
	BinaryBytes                int64  `json:"binary_bytes"`
	CleanBuildVCS              bool   `json:"clean_buildvcs"`
	NetworkDisabledRefusalExit int    `json:"network_disabled_refusal_exit"`
	ProductionPathQualified    *bool  `json:"production_path_qualified"`
	Image                      string `json:"image"`
	Digest                     string `json:"digest"`
	RunID                      string `json:"run_id"`
	RunAttempt                 string `json:"run_attempt"`
}

// This is the actual normal-publication.json schema emitted by the probe
// workflow. A PR's qualified.json or a single platform build is insufficient.
func nativeReadinessParseProbePublication(raw []byte, image, source string) (nativeReadinessPublishedImage, error) {
	var zero nativeReadinessPublishedImage
	var receipt struct {
		Schema             int                                     `json:"schema"`
		SourceCommit       string                                  `json:"source_commit"`
		EventSHA           string                                  `json:"event_sha"`
		RunID              string                                  `json:"run_id"`
		RunAttempt         string                                  `json:"run_attempt"`
		Image              string                                  `json:"image"`
		IndexDigest        string                                  `json:"index_digest"`
		Tags               []string                                `json:"tags"`
		Platforms          []nativeReadinessPublishedProbePlatform `json:"platforms"`
		TagReadbackMatches bool                                    `json:"tag_readback_matches"`
		LiveAdoption       *bool                                   `json:"live_adoption"`
	}
	if capacity.DecodeNativeProbeResourceJSON(raw, &receipt) != nil || receipt.Schema != 1 || receipt.SourceCommit != source || receipt.EventSHA != source || !nativeReadinessPositiveID(receipt.RunID) || !nativeReadinessPositiveID(receipt.RunAttempt) || receipt.Image+"@"+receipt.IndexDigest != image || !nativeReadinessImageDigest(receipt.IndexDigest) || !nativeReadinessNormalTags(receipt.Tags, source) || !receipt.TagReadbackMatches || receipt.LiveAdoption == nil || *receipt.LiveAdoption || len(receipt.Platforms) != 2 {
		return zero, errNativeReadinessRun
	}
	out := nativeReadinessPublishedImage{Image: image, SourceCommit: source, RuntimeDigests: []string{receipt.IndexDigest}}
	seen := map[string]bool{}
	for _, p := range receipt.Platforms {
		if p.Architecture != "amd64" && p.Architecture != "arm64" || seen[p.Architecture] || p.Head != source || p.EventSHA != source || p.Image != receipt.Image || p.RunID != receipt.RunID || p.RunAttempt != receipt.RunAttempt || !nativeReadinessImageDigest(p.Digest) || !nativeReadinessImageDigest(p.ImageID) || !nativeReadinessSHA(p.BinarySHA256) || p.BinaryBytes < 1 || p.BinaryBytes > 512<<20 || !p.CleanBuildVCS || p.NetworkDisabledRefusalExit != 1 || p.ProductionPathQualified == nil || *p.ProductionPathQualified {
			return zero, errNativeReadinessRun
		}
		seen[p.Architecture] = true
		out.RuntimeDigests = append(out.RuntimeDigests, p.Digest, p.ImageID)
	}
	if receipt.Platforms[0].Digest == receipt.Platforms[1].Digest || receipt.Platforms[0].ImageID == receipt.Platforms[1].ImageID {
		return zero, errNativeReadinessRun
	}
	return out, nil
}

// Core's existing normal publisher provides its verified index, ordered
// platform children, original CI log and build-record receipts. This operator
// receiving schema deliberately has no invented per-binary SHA field. The
// API-worker entrypoint is the same image's symlink to yggdrasil-core.
func nativeReadinessParseCorePublication(raw []byte, image, source string) (nativeReadinessPublishedImage, error) {
	var zero nativeReadinessPublishedImage
	var receipt struct {
		Schema       int      `json:"schema"`
		Stage        string   `json:"stage"`
		SourceCommit string   `json:"source_commit"`
		Conclusion   string   `json:"conclusion"`
		Image        string   `json:"image"`
		IndexDigest  string   `json:"index_digest"`
		RunID        int64    `json:"run_id"`
		JobID        int64    `json:"job_id"`
		ObservedAt   string   `json:"observed_at"`
		PromotedTags []string `json:"promoted_tags"`
		OriginalLog  struct {
			Path   string `json:"path"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"original_log"`
		PublisherBuildRecord struct {
			APIDigest   string `json:"API_digest"`
			ActualMagic string `json:"actual_magic"`
			ArtifactID  int64  `json:"artifact_id"`
			Bytes       int64  `json:"bytes"`
			Name        string `json:"name"`
			Path        string `json:"path"`
			SHA256      string `json:"sha256"`
		} `json:"publisher_build_record"`
		Steps []struct {
			Number      int    `json:"number"`
			Name        string `json:"name"`
			Status      string `json:"status"`
			Conclusion  string `json:"conclusion"`
			StartedAt   string `json:"started_at"`
			CompletedAt string `json:"completed_at"`
		} `json:"steps"`
		Verification struct {
			BinarySource string   `json:"native_binary_Source_and_clean_buildvcs_per_platform"`
			ChildDigests []string `json:"platform_child_digests_in_original_pull_order"`
			Platforms    []string `json:"platforms"`
			TagReadback  string   `json:"tag_readback"`
		} `json:"verification"`
		Limitations []string `json:"limitations"`
	}
	if capacity.DecodeNativeProbeResourceJSON(raw, &receipt) != nil || receipt.Schema != 1 || !strings.HasPrefix(receipt.Stage, "MAIN") || !strings.HasSuffix(receipt.Stage, "_NORMAL_SOURCE_PUBLISHER_ORIGINAL_RECEIVED") || receipt.Conclusion != "success" || receipt.SourceCommit != source || receipt.Image != image || !strings.HasSuffix(image, "@"+receipt.IndexDigest) || !nativeReadinessImageDigest(receipt.IndexDigest) || receipt.RunID < 1 || receipt.JobID < 1 || !nativeReadinessNormalTags(receipt.PromotedTags, source) || receipt.OriginalLog.Bytes < 1 || !nativeReadinessSHA(receipt.OriginalLog.SHA256) || receipt.PublisherBuildRecord.ArtifactID < 1 || receipt.PublisherBuildRecord.Bytes < 1 || !nativeReadinessSHA(receipt.PublisherBuildRecord.SHA256) || receipt.PublisherBuildRecord.APIDigest != "sha256:"+receipt.PublisherBuildRecord.SHA256 || !strings.HasPrefix(receipt.PublisherBuildRecord.ActualMagic, "gzip") {
		return zero, errNativeReadinessRun
	}
	v := receipt.Verification
	if v.BinarySource != "verified_by_successful_original_CI_step" || !strings.HasPrefix(v.TagReadback, "successful_original_CI_promotion_step;") || len(v.Platforms) != 2 || v.Platforms[0] != "linux/amd64" || v.Platforms[1] != "linux/arm64" || len(v.ChildDigests) != 2 || !nativeReadinessImageDigest(v.ChildDigests[0]) || !nativeReadinessImageDigest(v.ChildDigests[1]) || v.ChildDigests[0] == v.ChildDigests[1] {
		return zero, errNativeReadinessRun
	}
	verify, promote := 0, 0
	for _, s := range receipt.Steps {
		if s.Name == "Verify published binaries and source revision" {
			if s.Status != "completed" || s.Conclusion != "success" {
				return zero, errNativeReadinessRun
			}
			verify++
		}
		if s.Name == "Promote verified digest to release tags" {
			if s.Status != "completed" || s.Conclusion != "success" {
				return zero, errNativeReadinessRun
			}
			promote++
		}
	}
	if verify != 1 || promote != 1 {
		return zero, errNativeReadinessRun
	}
	return nativeReadinessPublishedImage{Image: image, SourceCommit: source, RuntimeDigests: []string{receipt.IndexDigest, v.ChildDigests[0], v.ChildDigests[1]}}, nil
}

func nativeReadinessImageDigest(s string) bool {
	return strings.HasPrefix(s, "sha256:") && nativeReadinessSHA(strings.TrimPrefix(s, "sha256:"))
}
func nativeReadinessPositiveID(s string) bool {
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == s
}
func nativeReadinessNormalTags(tags []string, source string) bool {
	return len(source) == 40 && len(tags) == 2 && tags[0] == "edge" && tags[1] == "sha-"+source[:7]
}
