package addons

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/workflowdispatchlock"
	"github.com/dakasa-yggdrasil/yggdrasil-core/model"
)

func setBlockingWorkflowDispatchPolicy(t *testing.T) {
	t.Helper()
	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`)
}

func unsetAddonEnvForTest(t *testing.T, name string) {
	t.Helper()
	value, configured := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
	t.Cleanup(func() {
		if configured {
			if err := os.Setenv(name, value); err != nil {
				t.Errorf("restore %s: %v", name, err)
			}
			return
		}
		if err := os.Unsetenv(name); err != nil {
			t.Errorf("restore unset %s: %v", name, err)
		}
	})
}

func TestScheduledWorkflowLockReturnsBeforeScheduleStateIsRead(t *testing.T) {
	setBlockingWorkflowDispatchPolicy(t)
	err := processScheduledWorkflow(
		context.Background(),
		nil,
		nil,
		nil,
		"manifest-id",
		"dakasa",
		"scheduled-mutation",
		&model.WorkflowScheduleTriggerSpec{CronExpression: "* * * * *"},
		time.Now().UTC(),
	)
	if err != nil {
		t.Fatalf("locked scheduled workflow returned error: %v", err)
	}
}

func TestMatchedEventLockReturnsBeforeDedupMarkerIsReadOrWritten(t *testing.T) {
	setBlockingWorkflowDispatchPolicy(t)
	err := processMatchedTrigger(
		context.Background(),
		nil,
		nil,
		nil,
		nil,
		eventTriggerWorkflow{manifestID: "manifest-id", namespace: "dakasa", name: "event-mutation"},
		model.Event{},
	)
	if !errors.Is(err, workflowdispatchlock.ErrLocked) {
		t.Fatalf("error = %v, want ErrLocked", err)
	}
}

func TestHeimdallInboxLockReturnsBeforeInboxClaim(t *testing.T) {
	setBlockingWorkflowDispatchPolicy(t)
	runHeimdallInboxDispatcherPass(context.Background(), nil, nil, nil)
}

func TestReactorDispatcherPausedByEnforcedOrInvalidPolicy(t *testing.T) {
	for _, config := range []string{
		`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
		`{`,
	} {
		t.Setenv(workflowdispatchlock.EnvName, config)
		if !workflowDispatchLockPaused() {
			t.Fatalf("config %q did not pause lock-sensitive startup workers", config)
		}
	}

	t.Setenv(workflowdispatchlock.EnvName, `{"mode":"off","allowed_workflows":[]}`)
	if workflowDispatchLockPaused() {
		t.Fatal("off policy paused lock-sensitive startup workers")
	}
}

func TestReconcilerDoesNotStartWhileExternalMutationIsLocked(t *testing.T) {
	for _, config := range []string{
		`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
		`{`,
	} {
		t.Setenv(workflowdispatchlock.EnvName, config)
		if err := bootstrapReconciler(context.Background(), nil); err != nil {
			t.Fatalf("config %q reconciler bootstrap error = %v", config, err)
		}
	}
}

func TestProvisionerDoesNotStartWhileExternalMutationIsLocked(t *testing.T) {
	for _, config := range []string{
		`{"mode":"enforce","allowed_workflows":[{"namespace":"dakasa","name":"fixed-unlock"}]}`,
		`{`,
	} {
		t.Setenv(workflowdispatchlock.EnvName, config)
		if err := bootstrapProvisioner(context.Background(), nil); err != nil {
			t.Fatalf("config %q provisioner bootstrap error = %v", config, err)
		}
	}
}

func TestFirstRunBootstrapIsNoOpWhenLockIsEnforcedAndBootstrapIsUnset(t *testing.T) {
	setBlockingWorkflowDispatchPolicy(t)
	for _, envName := range []string{
		envBootstrapAdminUsername,
		envBootstrapAdminPassword,
		envBootstrapAdminEmail,
		envBootstrapAdminDisplayName,
		envBootstrapManifestsPath,
	} {
		unsetAddonEnvForTest(t, envName)
	}

	if err := bootstrapFirstRun(context.Background(), nil); err != nil {
		t.Fatalf("unset first-run bootstrap under lock returned error: %v", err)
	}
}

func TestFirstRunBootstrapRejectsConfiguredInputWhenLockIsEnforced(t *testing.T) {
	for _, envName := range []string{
		envBootstrapAdminUsername,
		envBootstrapAdminPassword,
		envBootstrapAdminEmail,
		envBootstrapAdminDisplayName,
		envBootstrapManifestsPath,
	} {
		envName := envName
		t.Run(envName, func(t *testing.T) {
			setBlockingWorkflowDispatchPolicy(t)
			for _, bootstrapEnvName := range []string{
				envBootstrapAdminUsername,
				envBootstrapAdminPassword,
				envBootstrapAdminEmail,
				envBootstrapAdminDisplayName,
				envBootstrapManifestsPath,
			} {
				unsetAddonEnvForTest(t, bootstrapEnvName)
			}
			t.Setenv(envName, "")

			err := bootstrapFirstRun(context.Background(), nil)
			if err == nil || !strings.Contains(err.Error(), envName) {
				t.Fatalf("bootstrap error = %v, want configured env %s even when empty", err, envName)
			}
		})
	}
}
