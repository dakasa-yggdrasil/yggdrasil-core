package message

import (
	"context"
	"fmt"

	contractdocs "github.com/dakasa-yggdrasil/yggdrasil-core/docs/contracts"
	amqp "github.com/rabbitmq/amqp091-go"
)

type rpcContractSpec struct {
	Family      string
	RequestDef  string
	ResponseDef string
	Label       string
}

var (
	integrationExecuteContract = rpcContractSpec{
		Family:      contractdocs.FamilyIntegrationAdapterV1,
		RequestDef:  "adapterExecuteIntegrationRequest",
		ResponseDef: "adapterExecuteIntegrationResponse",
		Label:       "integration execute",
	}
	generateInstallationContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "generateInstallationRequest",
		ResponseDef: "generateInstallationResponse",
		Label:       "installation generate",
	}
	reconcileInstallationContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "reconcileInstallationRequest",
		ResponseDef: "reconcileInstallationResponse",
		Label:       "installation reconcile",
	}
	discoverInstallationStateContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "discoverInstallationStateRequest",
		ResponseDef: "discoverInstallationStateResponse",
		Label:       "installation state discover",
	}
	declarativeApplyContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "declarativeApplyRequest",
		ResponseDef: "declarativeApplyResponse",
		Label:       "target declarative apply",
	}
	observeObjectsContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "observeObjectsRequest",
		ResponseDef: "observeObjectsResponse",
		Label:       "target observe objects",
	}
	declarativeDeleteContract = rpcContractSpec{
		Family:      contractdocs.FamilyProductInstallationAdapterV1,
		RequestDef:  "declarativeDeleteRequest",
		ResponseDef: "declarativeDeleteResponse",
		Label:       "target declarative delete",
	}
)

func callContractRPC(
	ctx context.Context,
	conn *amqp.Connection,
	queue string,
	contract rpcContractSpec,
	request any,
	response any,
) error {
	if err := contractdocs.Validate(contract.Family, contract.RequestDef, request); err != nil {
		return fmt.Errorf("validate %s request: %w", contract.Label, err)
	}
	if err := callRabbitRPC(ctx, conn, queue, request, response); err != nil {
		return err
	}
	if response != nil && contract.ResponseDef != "" {
		if err := contractdocs.Validate(contract.Family, contract.ResponseDef, response); err != nil {
			return fmt.Errorf("validate %s response: %w", contract.Label, err)
		}
	}
	return nil
}
