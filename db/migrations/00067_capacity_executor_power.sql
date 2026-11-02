-- +goose Up
-- Explicit power variants reuse the existing ledgers. These indexes supplement
-- transaction locks; no retention job may delete unknown sends or adoptions.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_executor_power_resource_idx
 ON public.capacity_resource_slots (resource_id)
 WHERE slot_record->>'authority_kind'='ec2_operator_adoption_v1';
CREATE UNIQUE INDEX IF NOT EXISTS capacity_executor_power_command_idx
 ON public.capacity_mutation_grants ((grant_record->>'command_id'))
 WHERE grant_record->>'authority_kind'='ec2_power_v1';
CREATE UNIQUE INDEX IF NOT EXISTS capacity_executor_power_open_adoption_idx
 ON public.capacity_mutation_grants ((grant_record->>'adoption_id'))
 WHERE grant_record->>'authority_kind'='ec2_power_v1' AND state IN ('issued','redeemed','settled');
-- Legacy AWS slot records lack independently verified account/region. Refuse
-- ambiguous overlap conservatively by EC2 instance ID across adapter instances.
-- Existing duplicate legacy IDs cause migration failure, requiring operator review.
CREATE UNIQUE INDEX IF NOT EXISTS capacity_executor_power_vm_overlap_idx
 ON public.capacity_resource_slots ((CASE
   WHEN slot_record->>'authority_kind'='ec2_operator_adoption_v1'
     THEN slot_record->'resource'->>'instance_id'
   ELSE resource_id END))
 WHERE slot_record->>'authority_kind'='ec2_operator_adoption_v1'
    OR resource_id ~ '^i-[a-f0-9]{17}$';
-- +goose Down
-- Intentionally retain custody records and replay protection; rollback needs a
-- separately reviewed disposal procedure after all original sends are resolved.
SELECT 1;
