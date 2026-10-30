//go:build linux && nativequalification

package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/capacity"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
	"github.com/google/uuid"
)

func TestSourceRecoveryHistoricalPreregistration(t *testing.T) {
	for _, mode := range []string{"expired_original", "wrong_grant", "wrong_prereg", "wrong_policy", "wrong_checksum", "wrong_workflow", "wrong_slot", "wrong_generation", "wrong_fence", "wrong_source", "wrong_binding", "wrong_namespace", "corrupt_record", "corrupt_binding", "database_failure"} {
		t.Run(mode, func(t *testing.T) {
			f := guestOriginalStorageRecords(t)
			source := strings.Repeat("a", 40)
			profile := &f.binding.ProfileManifest
			profile.Profile = capacity.GuestQualificationProfile
			profile.CoverageClass = "native_qualification_subset"
			profile.OwnerSourceCommit = strings.Repeat("b", 40)
			profile.OwnerBinarySHA256 = strings.Repeat("c", 64)
			profile.Writers = []model.CapacityGuestProtectedWriterDefinition{{
				ID: capacity.GuestQualificationWriter, SourceCommit: profile.OwnerSourceCommit,
				BinarySHA256: profile.OwnerBinarySHA256, CgroupRelativePath: ".",
				CommandSHA256: capacity.GuestRetirementSHA(struct {
					Executable  string   `json:"executable"`
					Args        []string `json:"args"`
					SourceClass string   `json:"source_class"`
				}{"/usr/local/libexec/yggdrasil-guest-protected-runtime-owner", []string{"--qualification-original-writer"}, "native_qemu_qualification"}),
				HandleContractSHA256: capacity.GuestRetirementSHA(struct{ Writer, Workers, Connections, Withdraw string }{capacity.GuestQualificationWriter, "original-child-Wait+stderr-EOF-Close", "original-stdout-EOF-Close+stdin-Close", "same-original-child-operation-bound-ACK"}),
			}}
			f.binding.EvidenceClass = "native_qemu_qualification"
			f.binding.CoreAuthoritySourceCommit = source
			f.binding.Members[0].Slot = 1
			f.binding.ProfileManifestSHA256 = capacity.GuestRetirementSHA(*profile)
			f.pre.ProfileManifestSHA256 = f.binding.ProfileManifestSHA256
			f.pre.CoreSourceCommit, f.pre.Slot = source, 1
			policyBinding := f.binding
			p := model.CapacityPolicySpec{GuestRetirementBinding: &policyBinding, Profiles: []model.CapacityProfile{{Name: profile.Profile, Provider: "native-qemu"}}}
			spec, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			policy := model.Manifest{ID: uuid.MustParse(f.pre.PolicyID), Kind: "capacity_policy", Checksum: f.pre.PolicyChecksum, Metadata: model.ManifestMetadata{Namespace: "source-recovery-test"}, Spec: spec}
			workflowID := uuid.MustParse(f.pre.WorkflowID)
			grantID, preregID, slot, generation, fence := f.pre.OriginalCreateGrantID, f.pre.PreregistrationID, 1, f.pre.Generation, f.pre.Fence
			switch mode {
			case "wrong_grant":
				grantID = uuid.NewString()
			case "wrong_prereg":
				preregID = uuid.NewString()
			case "wrong_policy":
				policy.ID = uuid.New()
			case "wrong_checksum":
				policy.Checksum = strings.Repeat("e", 64)
			case "wrong_workflow":
				workflowID = uuid.New()
			case "wrong_slot":
				slot = 2
			case "wrong_generation":
				generation++
			case "wrong_fence":
				fence++
			case "wrong_source":
				source = strings.Repeat("d", 40)
			case "wrong_binding":
				p.GuestRetirementBinding.MutationBindingName = "other"
				policy.Spec, err = json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
			}
			wire, _ := json.Marshal(f.pre)
			binding, _ := json.Marshal(f.binding)
			if mode == "corrupt_binding" {
				binding = []byte("invalid")
			}
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if mode != "wrong_slot" {
				mock.ExpectBegin()
				lookup := mock.ExpectQuery("SELECT m.namespace,m.environment,m.domain,m.dimension").WithArgs(preregID)
				if mode == "database_failure" {
					lookup.WillReturnError(errors.New("database unavailable"))
					mock.ExpectRollback()
				} else {
					lookup.WillReturnRows(sqlmock.NewRows([]string{"namespace", "environment", "domain", "dimension"}).AddRow("source-recovery-test", "ci", "vm", "members"))
					mock.ExpectExec("SELECT pg_advisory_xact_lock").WillReturnResult(sqlmock.NewResult(0, 1))
					mock.ExpectQuery("SELECT original_wire,binding_wire").WithArgs(preregID).WillReturnRows(sqlmock.NewRows([]string{"original_wire", "binding_wire", "consistent"}).AddRow(wire, binding, mode != "corrupt_record"))
					if mode != "corrupt_record" && mode != "corrupt_binding" {
						mock.ExpectQuery("SELECT clock_timestamp").WillReturnRows(sqlmock.NewRows([]string{"clock_timestamp"}).AddRow(time.Now().UTC()))
					}
					if mode == "expired_original" || mode == "wrong_namespace" {
						namespace := "source-recovery-test"
						if mode == "wrong_namespace" {
							namespace = "foreign"
						}
						mock.ExpectQuery("SELECT namespace FROM public.capacity_mutation_grants").WithArgs(grantID).WillReturnRows(sqlmock.NewRows([]string{"namespace"}).AddRow(namespace))
					}
					if mode == "expired_original" {
						mock.ExpectCommit()
					} else {
						mock.ExpectRollback()
					}
				}
			}
			got, err := (CapacityStore{DB: db}).readSourceRecoveryHistoricalPreregistration(context.Background(), policy, workflowID, grantID, preregID, slot, generation, fence, source)
			if mode == "expired_original" {
				if err != nil || got.PreregistrationID != f.pre.PreregistrationID || !got.OriginalDeadline.Before(time.Now()) {
					t.Fatal("expired original historical read failed")
				}
			} else if err == nil || got.PreregistrationID != "" {
				t.Fatal("foreign or corrupt historical read accepted")
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
