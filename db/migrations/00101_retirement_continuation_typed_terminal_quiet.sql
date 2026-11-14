-- +goose Up
-- Retained M98/M99 terminal originals remain unacknowledged. Only their
-- authenticated immutable receipts may satisfy the existing dispatch barrier.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL)))
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_installed_provision_timeout_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='installed_timeout_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.installed_provision_timeout_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire) IS TRUE)
  AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_preaction_plan_dispositions d JOIN public.workflow_runs terminal_run ON terminal_run.id=d.run_id
   WHERE d.job_id=j.id AND d.run_id=j.run_id AND j.state='preaction_plan_disposed' AND j.finalization_ack_at IS NULL AND j.updated_at=d.recorded_at
   AND d.original_record=convert_from(d.original_wire,'UTF8')::jsonb
   AND (to_jsonb(j)-ARRAY['state','updated_at'])=(convert_from(d.original_dispatch_wire,'UTF8')::jsonb-ARRAY['state','updated_at'])
   AND terminal_run.status='failed' AND to_jsonb(terminal_run)=convert_from(d.original_run_wire,'UTF8')::jsonb
   AND public.preaction_failed_plan_valid(d.original_record,d.original_dispatch_wire,d.original_run_wire,d.original_intent_wire,d.members_wire,d.evidence_wire) IS TRUE))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.retirement_forward_continuation_quiet(r jsonb, own uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
 SELECT (SELECT count(*)=1 FROM public.capacity_dispatch_jobs j WHERE j.run_id=own AND j.state='started' AND j.started_at IS NOT NULL AND j.returned_at IS NULL AND j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' AND j.realm=r->>'namespace' AND j.environment=r->>'environment' AND j.domain=r->>'domain' AND j.dimension=r->>'dimension')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.run_id IS DISTINCT FROM own AND (j.envelope::jsonb#>>'{workflow,id}'=r#>>'{original,Request,intent,workflow_id}' OR (j.envelope::jsonb#>>'{workflow,namespace}',j.envelope::jsonb#>>'{workflow,name}')=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (j.state IS NULL OR j.state NOT IN('returned','prestart_rejected','failed_disposed','native_denied_disposed','enrolled_failed_disposed','abandoned_disposed','finalization_lost_disposed','unknown_maintenance_disposed','http_maintenance_disposed') OR (j.state='returned' AND (j.returned_at IS NULL OR j.finalization_ack_at IS NULL))))
 AND NOT EXISTS(SELECT 1 FROM public.workflow_runs w WHERE w.id<>own AND (w.workflow_id IN(SELECT id FROM public.manifests WHERE kind='workflow' AND (namespace,name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) OR (w.workflow_namespace,w.workflow_name)=(SELECT namespace,name FROM public.manifests WHERE id=(r#>>'{original,Request,intent,workflow_id}')::uuid)) AND (coalesce(w.status,'') NOT IN('succeeded','failed','cancelled') OR w.finished_at IS NULL))
 AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.original_disposition_id IS NULL AND g.failed_original_disposition_id IS NULL AND g.native_denied_disposition_id IS NULL AND g.enrolled_failed_disposition_id IS NULL AND (g.integration_instance_id::text,g.scope_checksum,g.profile_name)=(r#>>'{original,Request,intent,tuple,integration_instance_id}',r#>>'{original,Request,intent,tuple,scope_checksum}',r#>>'{original,Request,intent,tuple,profile}') AND g.state IN('issued','redeemed','settled','compensating') AND g.id::text<>r->>'destroy_grant_id')
 AND NOT EXISTS(SELECT 1 FROM public.capacity_guest_notify_canary_challenges c WHERE c.policy_id=(r#>>'{original,Request,intent,policy_id}')::uuid AND c.original_deadline>clock_timestamp())
$$;
-- +goose StatementEnd
