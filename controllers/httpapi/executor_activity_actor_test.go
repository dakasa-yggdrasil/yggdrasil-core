package httpapi

import (
	"context"
	"testing"
)

func TestExecutorActivityIngressAcceptsOnlyAuthenticatedMachineActor(t *testing.T) {
	base := context.Background()
	valid := executorActivityIdentity{PrincipalID: "agent-a", ConfiguredID: "agent-a", SubjectID: "agent-a", SubjectType: "service"}
	if executorActivityContext(base, valid) == base {
		t.Fatal("authenticated machine identity not carried")
	}
	for _, id := range []executorActivityIdentity{{}, {PrincipalID: "forged-input"}, {PrincipalID: "agent-a", ConfiguredID: "agent-b"}, {PrincipalID: "agent-a", ConfiguredID: "agent-a", SubjectID: "agent-a", SubjectType: "service", Legacy: true}, {PrincipalID: "agent-a", ConfiguredID: "agent-a", SubjectID: "agent-a", SubjectType: "collaborator"}} {
		if executorActivityContext(base, id) != base {
			t.Fatal("unverified/legacy identity carried")
		}
	}
}
