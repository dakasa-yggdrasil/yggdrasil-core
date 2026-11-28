package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// These are schema fixtures, not receipts of an actual publisher or a live
// qualification. Operational adoption must receive the real artifact bytes.
func nativeReadinessPublicationFixture(kind string) (map[string]any, string, string) {
	source := strings.Repeat("a", 40)
	index := "sha256:" + strings.Repeat("b", 64)
	base := "example.invalid/normal-publisher/" + kind
	image := base + "@" + index
	if kind == "probe" {
		platforms := []any{}
		for i, arch := range []string{"amd64", "arm64"} {
			platforms = append(platforms, map[string]any{"head": source, "event_sha": source, "architecture": arch, "image_id": "sha256:" + strings.Repeat(string(rune('c'+i)), 64), "binary_sha256": strings.Repeat("e", 64), "binary_bytes": 12345, "clean_buildvcs": true, "network_disabled_refusal_exit": 1, "production_path_qualified": false, "image": base, "digest": "sha256:" + strings.Repeat([]string{"f", "1"}[i], 64), "run_id": "123", "run_attempt": "1"})
		}
		return map[string]any{"schema": 1, "source_commit": source, "event_sha": source, "run_id": "123", "run_attempt": "1", "image": base, "index_digest": index, "tags": []any{"edge", "sha-" + source[:7]}, "platforms": platforms, "tag_readback_matches": true, "live_adoption": false}, image, source
	}
	return map[string]any{"schema": 1, "stage": "MAIN_FIXTURE_NORMAL_SOURCE_PUBLISHER_ORIGINAL_RECEIVED", "source_commit": source, "conclusion": "success", "image": image, "index_digest": index, "run_id": 123, "job_id": 456, "observed_at": "2026-11-28T06:00:00Z", "promoted_tags": []any{"edge", "sha-" + source[:7]}, "original_log": map[string]any{"path": "fixture-original.log", "bytes": 12345, "sha256": strings.Repeat("c", 64)}, "publisher_build_record": map[string]any{"API_digest": "sha256:" + strings.Repeat("d", 64), "actual_magic": "gzip; original API bytes preserved, not assumed ZIP", "artifact_id": 789, "bytes": 12345, "name": "fixture.dockerbuild", "path": "fixture.dockerbuild", "sha256": strings.Repeat("d", 64)}, "steps": []any{map[string]any{"number": 9, "name": "Verify published binaries and source revision", "status": "completed", "conclusion": "success", "started_at": "fixture", "completed_at": "fixture"}, map[string]any{"number": 10, "name": "Promote verified digest to release tags", "status": "completed", "conclusion": "success", "started_at": "fixture", "completed_at": "fixture"}}, "verification": map[string]any{"native_binary_Source_and_clean_buildvcs_per_platform": "verified_by_successful_original_CI_step", "platform_child_digests_in_original_pull_order": []any{"sha256:" + strings.Repeat("e", 64), "sha256:" + strings.Repeat("f", 64)}, "platforms": []any{"linux/amd64", "linux/arm64"}, "tag_readback": "successful_original_CI_promotion_step; fixture only"}, "limitations": []any{"Source publication only"}}, image, source
}

func nativeReadinessImageFixtureBytes(t *testing.T, receipt map[string]any) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(raw)
	return raw, hex.EncodeToString(h[:])
}

func TestNativeReadinessImagesUseExactNormalReceiptsAndActualChildIdentities(t *testing.T) {
	for _, kind := range []string{"core", "probe"} {
		t.Run(kind, func(t *testing.T) {
			j, image, source := nativeReadinessPublicationFixture(kind)
			raw, sha := nativeReadinessImageFixtureBytes(t, j)
			out, err := nativeReadinessParsePublishedImage(raw, sha, image, source, kind)
			if err != nil || out.Image != image || out.SourceCommit != source {
				t.Fatal("normal receipt refused", out, err)
			}
			want := 3
			if kind == "probe" {
				want = 5
			}
			if len(out.RuntimeDigests) != want {
				t.Fatal("missing actual publication identities")
			}
			for _, digest := range out.RuntimeDigests {
				if !nativeReadinessRuntimeImage("containerd://"+digest, out.RuntimeDigests) || !nativeReadinessRuntimeImage("docker-pullable://example.invalid/alias@"+digest, out.RuntimeDigests) {
					t.Fatal("actual pinned runtime ID refused")
				}
			}
			if nativeReadinessRuntimeImage("containerd://sha256:"+strings.Repeat("9", 64), out.RuntimeDigests) {
				t.Fatal("unpublished child accepted")
			}
		})
	}
}

func TestNativeReadinessImagesRefuseChangedSourceRawBytesAndPRQualifications(t *testing.T) {
	for _, kind := range []string{"core", "probe"} {
		t.Run(kind, func(t *testing.T) {
			j, image, source := nativeReadinessPublicationFixture(kind)
			raw, sha := nativeReadinessImageFixtureBytes(t, j)
			for _, mode := range []string{"raw_sha", "source", "image", "kind", "duplicate_field", "PR_source"} {
				t.Run(mode, func(t *testing.T) {
					body := append([]byte(nil), raw...)
					expectedSHA, expectedImage, expectedSource, expectedKind := sha, image, source, kind
					switch mode {
					case "raw_sha":
						expectedSHA = strings.Repeat("8", 64)
					case "source":
						expectedSource = strings.Repeat("7", 40)
					case "image":
						expectedImage = "example.invalid/other@sha256:" + strings.Repeat("b", 64)
					case "kind":
						expectedKind = "unrecognized"
					case "duplicate_field":
						body = append(body[:len(body)-1], []byte(`,"schema":1}`)...)
						h := sha256.Sum256(body)
						expectedSHA = hex.EncodeToString(h[:])
					case "PR_source":
						var changed map[string]any
						_ = json.Unmarshal(raw, &changed)
						if kind == "probe" {
							changed["event_sha"] = strings.Repeat("6", 40)
						} else {
							changed["stage"] = "PR_QUALIFICATION_ONLY"
						}
						body, expectedSHA = nativeReadinessImageFixtureBytes(t, changed)
					}
					if _, err := nativeReadinessParsePublishedImage(body, expectedSHA, expectedImage, expectedSource, expectedKind); err == nil {
						t.Fatal("unqualified image receipt accepted")
					}
				})
			}
		})
	}
}

func TestNativeReadinessProbeImagesRequireBothPublishedAndQualifiedPlatforms(t *testing.T) {
	for _, mode := range []string{"missing_platform", "duplicate_arch", "mixed_run", "dirty_binary", "unqualified_binary", "no_refusal", "not_published", "wrong_tag", "missing_negative_bound"} {
		t.Run(mode, func(t *testing.T) {
			j, image, source := nativeReadinessPublicationFixture("probe")
			platforms := j["platforms"].([]any)
			p := platforms[0].(map[string]any)
			switch mode {
			case "missing_platform":
				j["platforms"] = platforms[:1]
			case "duplicate_arch":
				platforms[1].(map[string]any)["architecture"] = "amd64"
			case "mixed_run":
				p["run_id"] = "124"
			case "dirty_binary":
				p["clean_buildvcs"] = false
			case "unqualified_binary":
				p["binary_sha256"] = ""
			case "no_refusal":
				p["network_disabled_refusal_exit"] = 0
			case "not_published":
				delete(p, "digest")
			case "wrong_tag":
				j["tag_readback_matches"] = false
			case "missing_negative_bound":
				delete(p, "production_path_qualified")
			}
			raw, sha := nativeReadinessImageFixtureBytes(t, j)
			if _, err := nativeReadinessParsePublishedImage(raw, sha, image, source, "probe"); err == nil {
				t.Fatal("incomplete publication accepted")
			}
		})
	}
}

func TestNativeReadinessCoreImagesKeepRealReceivingEvidenceAndNoInventedBinaryHash(t *testing.T) {
	for _, mode := range []string{"missing_child", "bad_log", "bad_artifact_digest", "missing_verify", "failed_promotion", "bad_source_statement", "invented_binary_sha"} {
		t.Run(mode, func(t *testing.T) {
			j, image, source := nativeReadinessPublicationFixture("core")
			v := j["verification"].(map[string]any)
			switch mode {
			case "missing_child":
				v["platform_child_digests_in_original_pull_order"] = []any{"sha256:" + strings.Repeat("e", 64)}
			case "bad_log":
				j["original_log"].(map[string]any)["sha256"] = ""
			case "bad_artifact_digest":
				j["publisher_build_record"].(map[string]any)["API_digest"] = "sha256:" + strings.Repeat("1", 64)
			case "missing_verify":
				j["steps"] = j["steps"].([]any)[1:]
			case "failed_promotion":
				j["steps"].([]any)[1].(map[string]any)["conclusion"] = "failure"
			case "bad_source_statement":
				v["native_binary_Source_and_clean_buildvcs_per_platform"] = "configured_claim"
			case "invented_binary_sha":
				j["binary_sha256"] = strings.Repeat("2", 64)
			}
			raw, sha := nativeReadinessImageFixtureBytes(t, j)
			if _, err := nativeReadinessParsePublishedImage(raw, sha, image, source, "core"); err == nil {
				t.Fatal("missing or invented receiving evidence accepted")
			}
		})
	}
}
