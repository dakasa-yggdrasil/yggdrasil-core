-- +goose Up
-- Transfer only a closed, read-free cleanup claim. Applied106/107 and all
-- original rows stay immutable; every successor needs its own fresh evidence.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_event() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; previous public.capacity_witnessed_unenrolled_expansion_cleanup_events;
 claim public.capacity_witnessed_unenrolled_expansion_cleanup_events; intent_doc jsonb; doc jsonb:=NEW.original_record; r jsonb:=NEW.original_record->'evidence';
 child public.capacity_mutation_grants; prepared public.capacity_witnessed_unenrolled_expansion_cleanup_events; qualified_return public.capacity_witnessed_unenrolled_expansion_cleanup_events; read_doc jsonb; count_rows bigint; actual_now timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=NEW.cleanup_id FOR UPDATE;
 IF public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed expansion parent original changed'; END IF;
 SELECT count(*) INTO count_rows FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id;
 IF NEW.sequence<>count_rows+1 OR NEW.recorded_at>actual_now+interval '1 second'
 OR EXISTS(SELECT 1 FROM jsonb_object_keys(doc) k WHERE k<>ALL(ARRAY['schema','cleanup_id','sequence','stage','run_id','generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id','evidence','recorded_at']))
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event sequence or closed fields refused'; END IF;
 SELECT * INTO previous FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id ORDER BY sequence DESC LIMIT 1;
 IF previous.recorded_at>NEW.recorded_at THEN RAISE EXCEPTION 'witnessed expansion event time order refused'; END IF;
 IF previous.stage='terminal' THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal is closed'; END IF;
 SELECT ci.intent INTO STRICT intent_doc FROM public.capacity_intents ci WHERE ci.namespace=a.namespace AND ci.environment=a.environment AND ci.domain=a.domain AND ci.dimension=a.dimension FOR UPDATE;
 IF NEW.stage='requested' THEN
  IF NEW.sequence<>1 OR NEW.run_id IS NOT NULL OR intent_doc ? 'witnessed_unenrolled_expansion_cleanup_id'
  OR encode(sha256(convert_to(intent_doc::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion requested original refused'; END IF;
  RETURN NEW;
 END IF;
 IF intent_doc->>'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR intent_doc#>>'{decision,reason}' IS DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion typed current frame required'; END IF;
 IF NEW.stage='claimed' THEN
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'number' OR doc->>k !~ '^[1-9][0-9]*$')
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['run_id','lease_owner','executor_id']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'string' OR COALESCE(doc->>k,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR doc->>k='00000000-0000-0000-0000-000000000000')
  OR jsonb_typeof(doc->'lease_expires_at') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'witnessed expansion closed claim ownership required'; END IF;
  IF (intent_doc->>'lease_expires_at')::timestamptz>=actual_now OR NEW.run_id IS NULL
  OR (doc->>'generation')::bigint IS DISTINCT FROM (intent_doc->>'generation')::bigint
  OR (doc->>'fencing_token')::bigint IS DISTINCT FROM (intent_doc->>'fencing_token')::bigint+1
  OR (doc->>'lease_expires_at')::timestamptz<=actual_now
  OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
   WHERE j.run_id=NEW.run_id AND j.state='started' AND j.returned_at IS NULL AND j.finalization_ack_at IS NULL
   AND w.status='running' AND w.finished_at IS NULL AND j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension
   AND j.envelope::jsonb#>>'{workflow,id}'=a.original_record->>'workflow_id' AND j.envelope::jsonb#>>'{workflow,checksum}'=a.original_record->>'workflow_checksum'
   AND j.envelope::jsonb#>>'{policy,id}'=a.policy_id::text AND j.envelope::jsonb#>>'{policy,checksum}'=a.policy_checksum)
  OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension AND j.run_id IS DISTINCT FROM NEW.run_id AND j.id<>a.job_id AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion genuine new claim refused'; END IF;
  -- A closed claim with no READ or mutation can transfer custody only. The
  -- successor still needs its own real survivor proof and fresh native READ.
  IF previous.stage='claimed' THEN
   IF (previous.sequence=count_rows AND count_rows>=2 AND NEW.run_id<>previous.run_id
    AND previous.original_record->'generation'=intent_doc->'generation'
    AND previous.original_record->'fencing_token'=intent_doc->'fencing_token'
    AND previous.original_record->'lease_owner'=intent_doc->'lease_owner'
    AND previous.original_record->'executor_id'=intent_doc->'lease_executor_id'
    AND previous.original_record->'lease_expires_at'=intent_doc->'lease_expires_at'
    AND (previous.original_record->>'lease_expires_at')::timestamptz<actual_now
    AND previous.original_record->>'child_grant_id'=a.child_grant_id::text
    AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e
      LEFT JOIN public.capacity_witnessed_unenrolled_expansion_cleanup_events prior ON prior.cleanup_id=e.cleanup_id AND prior.sequence=e.sequence-1
      WHERE e.cleanup_id=a.id AND (
       encode(sha256(e.original_wire),'hex') IS DISTINCT FROM e.event_sha256
       OR convert_from(e.original_wire,'UTF8')::jsonb IS DISTINCT FROM e.original_record
       OR e.original_record->>'schema' IS DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup_v1'
       OR e.original_record->>'cleanup_id' IS DISTINCT FROM a.id::text
       OR e.original_record->>'child_grant_id' IS DISTINCT FROM a.child_grant_id::text
       OR e.original_record ? 'evidence' OR e.recorded_at>actual_now
       OR (e.original_record->>'generation')::bigint IS DISTINCT FROM (a.original_record->>'original_generation')::bigint
       OR (e.original_record->>'fencing_token')::bigint IS DISTINCT FROM (a.original_record->>'original_fencing_token')::bigint+e.sequence-1
       OR e.sequence=1 AND(e.stage<>'requested' OR e.run_id IS NOT NULL)
       OR e.sequence>1 AND(e.stage<>'claimed' OR e.run_id IS NULL OR prior.sequence IS NULL OR e.recorded_at<prior.recorded_at)
       OR e.sequence>2 AND(prior.stage<>'claimed' OR e.run_id=prior.run_id OR (prior.original_record->>'lease_expires_at')::timestamptz>=e.recorded_at)))
    AND (SELECT count(DISTINCT e.run_id) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='claimed')=count_rows-1
    AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id OR g.grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text)
    AND (SELECT count(*) FROM public.capacity_dispatch_jobs j WHERE j.run_id=previous.run_id)=1
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
      WHERE j.run_id=previous.run_id AND j.state='returned' AND j.return_status='failed'
      AND j.returned_at>=previous.recorded_at AND j.finalization_ack_at>=j.returned_at AND j.finalization_ack_at<=actual_now
      AND w.status='failed' AND w.started_at=j.started_at AND w.finished_at=j.returned_at
      AND(w.workflow_id IS NULL OR w.workflow_id=(a.original_record->>'workflow_id')::uuid)
      AND j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension
      AND j.envelope::jsonb#>>'{workflow,id}'=a.original_record->>'workflow_id' AND j.envelope::jsonb#>>'{workflow,checksum}'=a.original_record->>'workflow_checksum'
      AND j.envelope::jsonb#>>'{policy,id}'=a.policy_id::text AND j.envelope::jsonb#>>'{policy,checksum}'=a.policy_checksum)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion claimed-only continuation refused'; END IF;
   RETURN NEW;
  END IF;
  -- Pre-DELETE continuation closes only the exact successful original read.
  -- That old read is never qualified/restamped; its successor needs a NEW read.
  IF previous.stage='inventory_returned' THEN
   SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
   SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-1;
   r:=previous.original_record->'evidence';read_doc:=r->'read';
   IF (prepared.stage='inventory_prepared' AND prepared.sequence=claim.sequence+1 AND previous.sequence=prepared.sequence+1
    AND previous.run_id=claim.run_id AND prepared.run_id=claim.run_id AND NEW.run_id<>claim.run_id
    AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id']) key WHERE prepared.original_record->key IS DISTINCT FROM claim.original_record->key OR previous.original_record->key IS DISTINCT FROM claim.original_record->key)
    AND claim.original_record->>'child_grant_id'=a.child_grant_id::text
    AND (claim.original_record->>'lease_expires_at')::timestamptz<actual_now
    AND claim.recorded_at<=prepared.recorded_at AND prepared.recorded_at<=previous.recorded_at AND previous.recorded_at<=actual_now
    AND read_doc=prepared.original_record->'evidence' AND (read_doc->>'claim_sequence')::bigint=claim.sequence
    AND (read_doc->>'issued_at_core')::timestamptz>=prepared.recorded_at
    AND (read_doc->>'original_deadline_core')::timestamptz<=(claim.original_record->>'lease_expires_at')::timestamptz
    AND (r->>'returned_at_core')::timestamptz<=previous.recorded_at
    AND public.witnessed_expansion_inventory_return_valid107(r,a.original_record,(SELECT spec FROM public.manifests WHERE id=a.policy_id))
    AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id OR g.grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text)
    AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage IN('issued','possible_send'))
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=claim.run_id AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=previous.recorded_at)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion predelete original read continuation refused'; END IF;
   RETURN NEW;
  END IF;
  -- Failed raw custody remains a failure. A contiguous authenticated read
  -- from this same old owner anchors only a NEW read after real ACK/expiry.
  IF previous.stage='absence_returned' THEN
   SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
   SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-1;
   SELECT * INTO STRICT qualified_return FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-2;
   r:=previous.original_record->'evidence';read_doc:=r->'read';
   IF (prepared.stage='absence_prepared' AND qualified_return.stage IN('pending_absence','absence_complete') AND qualified_return.sequence>claim.sequence
    AND qualified_return.run_id=claim.run_id AND prepared.run_id=claim.run_id AND previous.run_id=claim.run_id
    AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token','lease_owner','executor_id','lease_expires_at']) key WHERE qualified_return.original_record->key IS DISTINCT FROM claim.original_record->key OR prepared.original_record->key IS DISTINCT FROM claim.original_record->key OR previous.original_record->key IS DISTINCT FROM claim.original_record->key)
    AND qualified_return.recorded_at>=claim.recorded_at AND prepared.recorded_at>=qualified_return.recorded_at AND previous.recorded_at>=prepared.recorded_at AND previous.recorded_at<=actual_now
    AND public.witnessed_expansion_absence_read_valid106(qualified_return.original_record->'evidence',a.original_record)
    AND (qualified_return.original_record#>>'{evidence,read,claim_sequence}')::bigint=claim.sequence
    AND ((qualified_return.stage='pending_absence' AND qualified_return.original_record#>>'{evidence,pending}'='true' AND qualified_return.original_record#>>'{evidence,complete}'='false') OR (qualified_return.stage='absence_complete' AND qualified_return.original_record#>>'{evidence,pending}'='false' AND qualified_return.original_record#>>'{evidence,complete}'='true'))
    AND jsonb_typeof(r)='object' AND (SELECT count(*) FROM jsonb_object_keys(r))=12
    AND r-ARRAY['schema','read','read_wire','receipt','receipt_wire','status','started_at_core','returned_at_core','call_failed','original_context_failed','pending','complete']='{}'::jsonb
    AND r->>'schema'='witnessed_unenrolled_expansion_native_return_v1' AND r->>'status'=''
    AND r->>'call_failed'='true' AND r->>'original_context_failed'='true' AND r->>'pending'='false' AND r->>'complete'='false'
    AND jsonb_typeof(r->'call_failed')='boolean' AND jsonb_typeof(r->'original_context_failed')='boolean' AND jsonb_typeof(r->'pending')='boolean' AND jsonb_typeof(r->'complete')='boolean'
    AND jsonb_typeof(read_doc)='object' AND (SELECT count(*) FROM jsonb_object_keys(read_doc))=9
    AND read_doc-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']='{}'::jsonb
    AND read_doc=prepared.original_record->'evidence' AND convert_from(decode(r->>'read_wire','base64'),'UTF8')::jsonb=read_doc
    AND read_doc->>'schema'='witnessed_unenrolled_expansion_native_read_v1' AND read_doc->>'kind'='absence'
    AND read_doc->>'read_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND read_doc->>'read_id'<>'00000000-0000-0000-0000-000000000000'
    AND read_doc->>'read_id'<>qualified_return.original_record#>>'{evidence,read,read_id}'
    AND read_doc->>'cleanup_id'=a.id::text AND read_doc->>'child_grant_id'=a.child_grant_id::text
    AND read_doc->>'admission_sha256'=a.admission_sha256 AND (read_doc->>'claim_sequence')::bigint=claim.sequence
    AND r->'receipt'=qualified_return.original_record#>'{evidence,receipt}'
    AND convert_from(decode(r->>'receipt_wire','base64'),'UTF8')::jsonb=r->'receipt'
    AND (read_doc->>'original_deadline_core')::timestamptz>(read_doc->>'issued_at_core')::timestamptz
    AND (read_doc->>'original_deadline_core')::timestamptz<=(read_doc->>'issued_at_core')::timestamptz+interval '5 seconds'
    AND (read_doc->>'original_deadline_core')::timestamptz<=(claim.original_record->>'lease_expires_at')::timestamptz
    AND (r->>'started_at_core')::timestamptz>=(read_doc->>'issued_at_core')::timestamptz
    AND (r->>'started_at_core')::timestamptz<(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz>=(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz<=previous.recorded_at
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=claim.run_id AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=previous.recorded_at)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion deadline read continuation refused'; END IF;
   previous:=qualified_return;
  END IF;
  IF previous.stage<>'requested' AND(previous.stage NOT IN('pending_absence','absence_complete') OR public.witnessed_expansion_absence_read_valid106(previous.original_record->'evidence',a.original_record) IS NOT TRUE
   OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events c JOIN public.capacity_dispatch_jobs j ON j.run_id=c.run_id JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE c.cleanup_id=a.id AND c.stage='claimed' AND c.sequence=(SELECT max(sequence) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed') AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read continuation lacks closed old owner'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
 IF NEW.run_id IS DISTINCT FROM claim.run_id OR doc->>'generation' IS DISTINCT FROM claim.original_record->>'generation'
 OR doc->>'fencing_token' IS DISTINCT FROM claim.original_record->>'fencing_token' OR doc->>'lease_owner' IS DISTINCT FROM claim.original_record->>'lease_owner'
 OR doc->>'executor_id' IS DISTINCT FROM claim.original_record->>'executor_id' OR doc->>'lease_expires_at' IS DISTINCT FROM claim.original_record->>'lease_expires_at'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event owner mismatch'; END IF;
 IF NEW.stage IN('inventory_returned','absence_returned') THEN
  SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage=split_part(NEW.stage,'_',1)||'_prepared' AND original_record#>>'{evidence,read_id}'=r#>>'{read,read_id}';
  IF prepared.original_record->'evidence' IS DISTINCT FROM r->'read'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events prior_return WHERE prior_return.cleanup_id=a.id AND prior_return.stage=NEW.stage AND prior_return.original_record#>>'{evidence,read,read_id}'=r#>>'{read,read_id}')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion actual read return mismatch'; END IF;
  RETURN NEW; -- Failed/late raw custody is retained, never authority.
 END IF;
 IF (claim.original_record->>'lease_expires_at')::timestamptz<=actual_now
 OR (intent_doc->>'fencing_token')::bigint IS DISTINCT FROM (doc->>'fencing_token')::bigint
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion stale owner'; END IF;
 IF NEW.stage IN('issued','possible_send','terminal') THEN
  IF (SELECT COALESCE(jsonb_agg(s.slot_record-ARRAY['observed_at','receipt_ref'] ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE (s.namespace,s.environment,s.domain,s.dimension)=(a.namespace,a.environment,a.domain,a.dimension) AND s.resource_id<>'')
   IS DISTINCT FROM (SELECT jsonb_agg(v-ARRAY['observed_at','receipt_ref'] ORDER BY ord) FROM jsonb_array_elements(convert_from(decode(a.original_record->>'survivor_roster_wire','base64'),'UTF8')::jsonb) WITH ORDINALITY x(v,ord))
  THEN RAISE EXCEPTION 'witnessed expansion original survivor identities changed'; END IF;
  -- Same actual enrolled survivors, same new owner, fresh physical read and
  -- accepted source canary publish/read. No old target/witness is synthesized.
  IF (SELECT count(*) FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'')<>(a.original_record->>'survivor_count')::integer
  OR EXISTS(SELECT 1 FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'' AND(
    slotrow.slot<1 OR slotrow.slot>=a.slot OR ((slotrow.slot_record->>'observed_at')::timestamptz BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now+interval '5 seconds') IS NOT TRUE
    OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments enrollment
      JOIN public.capacity_guest_notify_canary_challenges rc ON rc.preregistration_id=enrollment.preregistration_id AND rc.phase='read'
      JOIN public.capacity_guest_notify_canary_returns rr ON rr.challenge_id=rc.id AND rr.outcome='accepted'
      JOIN public.capacity_guest_notify_canary_challenges pc ON pc.id=rc.record_challenge_id AND pc.phase='publish'
      JOIN public.capacity_guest_notify_canary_returns pr ON pr.challenge_id=pc.id AND pr.outcome='accepted'
      WHERE enrollment.enrollment_record#>>'{statement,tuple,resource_id}'=slotrow.resource_id
      AND enrollment.enrollment_record#>>'{statement,tuple,resource_created_at}'=slotrow.slot_record->>'resource_created_at'
      AND rc.policy_id=a.policy_id AND rc.workflow_id=(a.original_record->>'workflow_id')::uuid
      AND rc.generation=(claim.original_record->>'generation')::bigint AND rc.fence=(claim.original_record->>'fencing_token')::bigint
      AND rc.lease_owner=claim.original_record->>'lease_owner' AND rc.executor_id=claim.original_record->>'executor_id'
      AND pc.policy_id=rc.policy_id AND pc.generation=rc.generation AND pc.fence=rc.fence AND pc.lease_owner=rc.lease_owner AND pc.executor_id=rc.executor_id
      AND rc.original_record->>'usage_class'=CASE WHEN NEW.stage='terminal' THEN 'after_retirement_floor' ELSE 'before_retirement_floor' END
      AND pc.original_record->>'usage_class'=rc.original_record->>'usage_class'
      AND rc.recorded_at>CASE WHEN NEW.stage='terminal' THEN (SELECT max(recorded_at) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='absence_complete' AND sequence>claim.sequence) ELSE claim.recorded_at END
      AND pc.recorded_at>claim.recorded_at AND rr.recorded_at>=rc.recorded_at AND pr.recorded_at>=pc.recorded_at
      AND rr.recorded_at BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now)))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion fresh real survivor floor refused'; END IF;
 END IF;
 IF NEW.stage IN('inventory_prepared','absence_prepared') THEN
  IF jsonb_typeof(r) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(r))<>9
  OR r-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']<>'{}'::jsonb
  OR EXISTS(SELECT 1 FROM jsonb_each(r) v WHERE v.value='null'::jsonb)
  OR jsonb_typeof(r->'claim_sequence') IS DISTINCT FROM 'number' OR r->>'claim_sequence' !~ '^[1-9][0-9]*$'
  OR r->>'schema' IS DISTINCT FROM 'witnessed_unenrolled_expansion_native_read_v1'
  OR COALESCE(r->>'read_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR r->>'read_id'='00000000-0000-0000-0000-000000000000'
  OR r->>'admission_sha256' IS DISTINCT FROM a.admission_sha256
  OR (r->>'original_deadline_core')::timestamptz>(claim.original_record->>'lease_expires_at')::timestamptz
  OR r->>'kind' IS DISTINCT FROM split_part(NEW.stage,'_',1) OR r->>'cleanup_id' IS DISTINCT FROM a.id::text OR r->>'child_grant_id' IS DISTINCT FROM a.child_grant_id::text
  OR (r->>'claim_sequence')::bigint IS DISTINCT FROM claim.sequence
  OR (r->>'original_deadline_core')::timestamptz<=(r->>'issued_at_core')::timestamptz OR (r->>'original_deadline_core')::timestamptz>(r->>'issued_at_core')::timestamptz+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events p WHERE p.cleanup_id=a.id AND p.stage=NEW.stage AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events q WHERE q.cleanup_id=a.id AND q.stage=split_part(NEW.stage,'_',1)||'_returned' AND q.original_record#>>'{evidence,read,read_id}'=p.original_record#>>'{evidence,read_id}'))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read preparation refused'; END IF;
  IF NEW.stage='inventory_prepared' AND EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id) THEN RAISE EXCEPTION 'witnessed unenrolled expansion inventory cannot rearm child'; END IF;
  IF NEW.stage='absence_prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id AND g.state='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') THEN RAISE EXCEPTION 'witnessed unenrolled expansion sealed destroy required'; END IF;
 ELSIF NEW.stage IN('inventory_qualified','pending_absence','absence_complete') THEN
  IF previous.stage<>(CASE WHEN NEW.stage='inventory_qualified' THEN 'inventory_returned' ELSE 'absence_returned' END)
  OR (previous.original_record->'evidence')-ARRAY['pending','complete'] IS DISTINCT FROM r-ARRAY['pending','complete']
  OR r->>'call_failed' IS DISTINCT FROM 'false' OR r->>'original_context_failed' IS DISTINCT FROM 'false'
  OR (r->>'returned_at_core')::timestamptz>=(r#>>'{read,original_deadline_core}')::timestamptz
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion qualified return lacks complete original'; END IF;
  IF NEW.stage='inventory_qualified' THEN
   IF public.witnessed_expansion_inventory_return_valid107(r,a.original_record,(SELECT spec FROM public.manifests WHERE id=a.policy_id)) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact original paid inventory required'; END IF;
   IF r->>'status' IS DISTINCT FROM 'dry_run' OR r#>>'{plan,server,id}' IS DISTINCT FROM a.original_record->>'resource_id'
   OR r#>>'{plan,server,created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
   OR r#>>'{plan,server,physical_spec_verified}' IS DISTINCT FROM 'true' OR r#>>'{plan,server,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion owned attached inventory required'; END IF;
  ELSE
   IF public.witnessed_expansion_absence_read_valid106(r,a.original_record) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed unenrolled expansion observer wrapper refused'; END IF;
   IF NEW.stage='absence_complete' AND(r->>'complete' IS DISTINCT FROM 'true' OR r->>'pending' IS DISTINCT FROM 'false' OR r#>>'{observation,server_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,billable_resources_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'true' OR jsonb_array_length(r#>'{observation,hold_reasons}') IS DISTINCT FROM 0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r#>'{observation,auxiliary_resources}') aux WHERE aux->>'absent' IS DISTINCT FROM 'true')) THEN RAISE EXCEPTION 'witnessed unenrolled expansion complete paid absence required'; END IF;
   IF NEW.stage='pending_absence' AND(r->>'pending' IS DISTINCT FROM 'true' OR r->>'complete' IS DISTINCT FROM 'false' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'false' OR jsonb_array_length(r#>'{observation,hold_reasons}') NOT BETWEEN 1 AND 3) THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact pending required'; END IF;
  END IF;
 ELSIF NEW.stage='issued' THEN
  IF previous.stage IS DISTINCT FROM 'inventory_qualified' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage IN('issued','possible_send'))
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text AND state='issued')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child issue is once'; END IF;
 ELSIF NEW.stage='possible_send' THEN
  IF previous.stage<>'issued' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion possible send is once'; END IF;
 ELSIF NEW.stage='terminal' THEN
  IF previous.stage IS DISTINCT FROM 'absence_complete' OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='absence_complete' AND e.sequence>claim.sequence AND public.witnessed_expansion_absence_read_valid106(e.original_record->'evidence',a.original_record))
  OR r->>'original_guest_success' IS DISTINCT FROM 'false' OR r->>'clean_cycle_credit' IS DISTINCT FROM 'false' OR r->>'serving_or_business_or_savings_authority' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal requires its real fresh paid absence'; END IF;
 ELSE RAISE EXCEPTION 'witnessed unenrolled expansion event stage refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd

-- +goose Down
-- A used custody transfer cannot lose its live guard through rollback.
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e
   JOIN public.capacity_witnessed_unenrolled_expansion_cleanup_events prior ON prior.cleanup_id=e.cleanup_id AND prior.sequence=e.sequence-1
   WHERE e.stage='claimed' AND prior.stage='claimed')
 THEN RAISE EXCEPTION 'used claimed-only cleanup recovery cannot be downgraded'; END IF;
END; $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.guard_witnessed_unenrolled_expansion_cleanup_event() RETURNS trigger LANGUAGE plpgsql SET timezone='UTC' AS $$
DECLARE a public.capacity_witnessed_unenrolled_expansion_cleanups; previous public.capacity_witnessed_unenrolled_expansion_cleanup_events;
 claim public.capacity_witnessed_unenrolled_expansion_cleanup_events; intent_doc jsonb; doc jsonb:=NEW.original_record; r jsonb:=NEW.original_record->'evidence';
 child public.capacity_mutation_grants; prepared public.capacity_witnessed_unenrolled_expansion_cleanup_events; qualified_return public.capacity_witnessed_unenrolled_expansion_cleanup_events; read_doc jsonb; count_rows bigint; actual_now timestamptz:=clock_timestamp();
BEGIN
 SELECT * INTO STRICT a FROM public.capacity_witnessed_unenrolled_expansion_cleanups WHERE id=NEW.cleanup_id FOR UPDATE;
 IF public.witnessed_unenrolled_expansion_parent_valid106(a.id) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed expansion parent original changed'; END IF;
 SELECT count(*) INTO count_rows FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id;
 IF NEW.sequence<>count_rows+1 OR NEW.recorded_at>actual_now+interval '1 second'
 OR EXISTS(SELECT 1 FROM jsonb_object_keys(doc) k WHERE k<>ALL(ARRAY['schema','cleanup_id','sequence','stage','run_id','generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id','evidence','recorded_at']))
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event sequence or closed fields refused'; END IF;
 SELECT * INTO previous FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=NEW.cleanup_id ORDER BY sequence DESC LIMIT 1;
 IF previous.recorded_at>NEW.recorded_at THEN RAISE EXCEPTION 'witnessed expansion event time order refused'; END IF;
 IF previous.stage='terminal' THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal is closed'; END IF;
 SELECT ci.intent INTO STRICT intent_doc FROM public.capacity_intents ci WHERE ci.namespace=a.namespace AND ci.environment=a.environment AND ci.domain=a.domain AND ci.dimension=a.dimension FOR UPDATE;
 IF NEW.stage='requested' THEN
  IF NEW.sequence<>1 OR NEW.run_id IS NOT NULL OR intent_doc ? 'witnessed_unenrolled_expansion_cleanup_id'
  OR encode(sha256(convert_to(intent_doc::text,'UTF8')),'hex') IS DISTINCT FROM a.original_record->>'original_intent_sha256'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion requested original refused'; END IF;
  RETURN NEW;
 END IF;
 IF intent_doc->>'witnessed_unenrolled_expansion_cleanup_id' IS DISTINCT FROM a.id::text
 OR intent_doc#>>'{decision,reason}' IS DISTINCT FROM 'witnessed_unenrolled_expansion_cleanup'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion typed current frame required'; END IF;
 IF NEW.stage='claimed' THEN
  IF EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'number' OR doc->>k !~ '^[1-9][0-9]*$')
  OR EXISTS(SELECT 1 FROM unnest(ARRAY['run_id','lease_owner','executor_id']) k WHERE jsonb_typeof(doc->k) IS DISTINCT FROM 'string' OR COALESCE(doc->>k,'') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' OR doc->>k='00000000-0000-0000-0000-000000000000')
  OR jsonb_typeof(doc->'lease_expires_at') IS DISTINCT FROM 'string'
  THEN RAISE EXCEPTION 'witnessed expansion closed claim ownership required'; END IF;
  IF (intent_doc->>'lease_expires_at')::timestamptz>=actual_now OR NEW.run_id IS NULL
  OR (doc->>'generation')::bigint IS DISTINCT FROM (intent_doc->>'generation')::bigint
  OR (doc->>'fencing_token')::bigint IS DISTINCT FROM (intent_doc->>'fencing_token')::bigint+1
  OR (doc->>'lease_expires_at')::timestamptz<=actual_now
  OR NOT EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id
   WHERE j.run_id=NEW.run_id AND j.state='started' AND j.returned_at IS NULL AND j.finalization_ack_at IS NULL
   AND w.status='running' AND w.finished_at IS NULL AND j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension
   AND j.envelope::jsonb#>>'{workflow,id}'=a.original_record->>'workflow_id' AND j.envelope::jsonb#>>'{workflow,checksum}'=a.original_record->>'workflow_checksum'
   AND j.envelope::jsonb#>>'{policy,id}'=a.policy_id::text AND j.envelope::jsonb#>>'{policy,checksum}'=a.policy_checksum)
  OR EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j WHERE j.realm=a.namespace AND j.environment=a.environment AND j.domain=a.domain AND j.dimension=a.dimension AND j.run_id IS DISTINCT FROM NEW.run_id AND j.id<>a.job_id AND(j.state IN('queued','started','unknown') OR j.state='returned' AND j.finalization_ack_at IS NULL))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion genuine new claim refused'; END IF;
  -- Pre-DELETE continuation closes only the exact successful original read.
  -- That old read is never qualified/restamped; its successor needs a NEW read.
  IF previous.stage='inventory_returned' THEN
   SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
   SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-1;
   r:=previous.original_record->'evidence';read_doc:=r->'read';
   IF (prepared.stage='inventory_prepared' AND prepared.sequence=claim.sequence+1 AND previous.sequence=prepared.sequence+1
    AND previous.run_id=claim.run_id AND prepared.run_id=claim.run_id AND NEW.run_id<>claim.run_id
    AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token','lease_owner','executor_id','lease_expires_at','child_grant_id']) key WHERE prepared.original_record->key IS DISTINCT FROM claim.original_record->key OR previous.original_record->key IS DISTINCT FROM claim.original_record->key)
    AND claim.original_record->>'child_grant_id'=a.child_grant_id::text
    AND (claim.original_record->>'lease_expires_at')::timestamptz<actual_now
    AND claim.recorded_at<=prepared.recorded_at AND prepared.recorded_at<=previous.recorded_at AND previous.recorded_at<=actual_now
    AND read_doc=prepared.original_record->'evidence' AND (read_doc->>'claim_sequence')::bigint=claim.sequence
    AND (read_doc->>'issued_at_core')::timestamptz>=prepared.recorded_at
    AND (read_doc->>'original_deadline_core')::timestamptz<=(claim.original_record->>'lease_expires_at')::timestamptz
    AND (r->>'returned_at_core')::timestamptz<=previous.recorded_at
    AND public.witnessed_expansion_inventory_return_valid107(r,a.original_record,(SELECT spec FROM public.manifests WHERE id=a.policy_id))
    AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id OR g.grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text)
    AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage IN('issued','possible_send'))
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=claim.run_id AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=previous.recorded_at)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion predelete original read continuation refused'; END IF;
   RETURN NEW;
  END IF;
  -- Failed raw custody remains a failure. A contiguous authenticated read
  -- from this same old owner anchors only a NEW read after real ACK/expiry.
  IF previous.stage='absence_returned' THEN
   SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
   SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-1;
   SELECT * INTO STRICT qualified_return FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND sequence=previous.sequence-2;
   r:=previous.original_record->'evidence';read_doc:=r->'read';
   IF (prepared.stage='absence_prepared' AND qualified_return.stage IN('pending_absence','absence_complete') AND qualified_return.sequence>claim.sequence
    AND qualified_return.run_id=claim.run_id AND prepared.run_id=claim.run_id AND previous.run_id=claim.run_id
    AND NOT EXISTS(SELECT 1 FROM unnest(ARRAY['generation','fencing_token','lease_owner','executor_id','lease_expires_at']) key WHERE qualified_return.original_record->key IS DISTINCT FROM claim.original_record->key OR prepared.original_record->key IS DISTINCT FROM claim.original_record->key OR previous.original_record->key IS DISTINCT FROM claim.original_record->key)
    AND qualified_return.recorded_at>=claim.recorded_at AND prepared.recorded_at>=qualified_return.recorded_at AND previous.recorded_at>=prepared.recorded_at AND previous.recorded_at<=actual_now
    AND public.witnessed_expansion_absence_read_valid106(qualified_return.original_record->'evidence',a.original_record)
    AND (qualified_return.original_record#>>'{evidence,read,claim_sequence}')::bigint=claim.sequence
    AND ((qualified_return.stage='pending_absence' AND qualified_return.original_record#>>'{evidence,pending}'='true' AND qualified_return.original_record#>>'{evidence,complete}'='false') OR (qualified_return.stage='absence_complete' AND qualified_return.original_record#>>'{evidence,pending}'='false' AND qualified_return.original_record#>>'{evidence,complete}'='true'))
    AND jsonb_typeof(r)='object' AND (SELECT count(*) FROM jsonb_object_keys(r))=12
    AND r-ARRAY['schema','read','read_wire','receipt','receipt_wire','status','started_at_core','returned_at_core','call_failed','original_context_failed','pending','complete']='{}'::jsonb
    AND r->>'schema'='witnessed_unenrolled_expansion_native_return_v1' AND r->>'status'=''
    AND r->>'call_failed'='true' AND r->>'original_context_failed'='true' AND r->>'pending'='false' AND r->>'complete'='false'
    AND jsonb_typeof(r->'call_failed')='boolean' AND jsonb_typeof(r->'original_context_failed')='boolean' AND jsonb_typeof(r->'pending')='boolean' AND jsonb_typeof(r->'complete')='boolean'
    AND jsonb_typeof(read_doc)='object' AND (SELECT count(*) FROM jsonb_object_keys(read_doc))=9
    AND read_doc-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']='{}'::jsonb
    AND read_doc=prepared.original_record->'evidence' AND convert_from(decode(r->>'read_wire','base64'),'UTF8')::jsonb=read_doc
    AND read_doc->>'schema'='witnessed_unenrolled_expansion_native_read_v1' AND read_doc->>'kind'='absence'
    AND read_doc->>'read_id' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    AND read_doc->>'read_id'<>'00000000-0000-0000-0000-000000000000'
    AND read_doc->>'read_id'<>qualified_return.original_record#>>'{evidence,read,read_id}'
    AND read_doc->>'cleanup_id'=a.id::text AND read_doc->>'child_grant_id'=a.child_grant_id::text
    AND read_doc->>'admission_sha256'=a.admission_sha256 AND (read_doc->>'claim_sequence')::bigint=claim.sequence
    AND r->'receipt'=qualified_return.original_record#>'{evidence,receipt}'
    AND convert_from(decode(r->>'receipt_wire','base64'),'UTF8')::jsonb=r->'receipt'
    AND (read_doc->>'original_deadline_core')::timestamptz>(read_doc->>'issued_at_core')::timestamptz
    AND (read_doc->>'original_deadline_core')::timestamptz<=(read_doc->>'issued_at_core')::timestamptz+interval '5 seconds'
    AND (read_doc->>'original_deadline_core')::timestamptz<=(claim.original_record->>'lease_expires_at')::timestamptz
    AND (r->>'started_at_core')::timestamptz>=(read_doc->>'issued_at_core')::timestamptz
    AND (r->>'started_at_core')::timestamptz<(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz>=(read_doc->>'original_deadline_core')::timestamptz
    AND (r->>'returned_at_core')::timestamptz<=previous.recorded_at
    AND EXISTS(SELECT 1 FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id WHERE j.run_id=claim.run_id AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at AND j.returned_at>=previous.recorded_at)) IS NOT TRUE
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion deadline read continuation refused'; END IF;
   previous:=qualified_return;
  END IF;
  IF previous.stage<>'requested' AND(previous.stage NOT IN('pending_absence','absence_complete') OR public.witnessed_expansion_absence_read_valid106(previous.original_record->'evidence',a.original_record) IS NOT TRUE
   OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events c JOIN public.capacity_dispatch_jobs j ON j.run_id=c.run_id JOIN public.workflow_runs w ON w.id=j.run_id
    WHERE c.cleanup_id=a.id AND c.stage='claimed' AND c.sequence=(SELECT max(sequence) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed') AND j.state='returned' AND j.return_status='failed' AND j.finalization_ack_at>=j.returned_at AND w.status='failed' AND w.finished_at=j.returned_at))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read continuation lacks closed old owner'; END IF;
  RETURN NEW;
 END IF;
 SELECT * INTO STRICT claim FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='claimed' ORDER BY sequence DESC LIMIT 1;
 IF NEW.run_id IS DISTINCT FROM claim.run_id OR doc->>'generation' IS DISTINCT FROM claim.original_record->>'generation'
 OR doc->>'fencing_token' IS DISTINCT FROM claim.original_record->>'fencing_token' OR doc->>'lease_owner' IS DISTINCT FROM claim.original_record->>'lease_owner'
 OR doc->>'executor_id' IS DISTINCT FROM claim.original_record->>'executor_id' OR doc->>'lease_expires_at' IS DISTINCT FROM claim.original_record->>'lease_expires_at'
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion event owner mismatch'; END IF;
 IF NEW.stage IN('inventory_returned','absence_returned') THEN
  SELECT * INTO STRICT prepared FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage=split_part(NEW.stage,'_',1)||'_prepared' AND original_record#>>'{evidence,read_id}'=r#>>'{read,read_id}';
  IF prepared.original_record->'evidence' IS DISTINCT FROM r->'read'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events prior_return WHERE prior_return.cleanup_id=a.id AND prior_return.stage=NEW.stage AND prior_return.original_record#>>'{evidence,read,read_id}'=r#>>'{read,read_id}')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion actual read return mismatch'; END IF;
  RETURN NEW; -- Failed/late raw custody is retained, never authority.
 END IF;
 IF (claim.original_record->>'lease_expires_at')::timestamptz<=actual_now
 OR (intent_doc->>'fencing_token')::bigint IS DISTINCT FROM (doc->>'fencing_token')::bigint
 THEN RAISE EXCEPTION 'witnessed unenrolled expansion stale owner'; END IF;
 IF NEW.stage IN('issued','possible_send','terminal') THEN
  IF (SELECT COALESCE(jsonb_agg(s.slot_record-ARRAY['observed_at','receipt_ref'] ORDER BY s.slot),'[]'::jsonb) FROM public.capacity_resource_slots s WHERE (s.namespace,s.environment,s.domain,s.dimension)=(a.namespace,a.environment,a.domain,a.dimension) AND s.resource_id<>'')
   IS DISTINCT FROM (SELECT jsonb_agg(v-ARRAY['observed_at','receipt_ref'] ORDER BY ord) FROM jsonb_array_elements(convert_from(decode(a.original_record->>'survivor_roster_wire','base64'),'UTF8')::jsonb) WITH ORDINALITY x(v,ord))
  THEN RAISE EXCEPTION 'witnessed expansion original survivor identities changed'; END IF;
  -- Same actual enrolled survivors, same new owner, fresh physical read and
  -- accepted source canary publish/read. No old target/witness is synthesized.
  IF (SELECT count(*) FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'')<>(a.original_record->>'survivor_count')::integer
  OR EXISTS(SELECT 1 FROM public.capacity_resource_slots slotrow WHERE slotrow.namespace=a.namespace AND slotrow.environment=a.environment AND slotrow.domain=a.domain AND slotrow.dimension=a.dimension AND slotrow.resource_id<>'' AND(
    slotrow.slot<1 OR slotrow.slot>=a.slot OR ((slotrow.slot_record->>'observed_at')::timestamptz BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now+interval '5 seconds') IS NOT TRUE
    OR NOT EXISTS(SELECT 1 FROM public.capacity_vm_original_enrollments enrollment
      JOIN public.capacity_guest_notify_canary_challenges rc ON rc.preregistration_id=enrollment.preregistration_id AND rc.phase='read'
      JOIN public.capacity_guest_notify_canary_returns rr ON rr.challenge_id=rc.id AND rr.outcome='accepted'
      JOIN public.capacity_guest_notify_canary_challenges pc ON pc.id=rc.record_challenge_id AND pc.phase='publish'
      JOIN public.capacity_guest_notify_canary_returns pr ON pr.challenge_id=pc.id AND pr.outcome='accepted'
      WHERE enrollment.enrollment_record#>>'{statement,tuple,resource_id}'=slotrow.resource_id
      AND enrollment.enrollment_record#>>'{statement,tuple,resource_created_at}'=slotrow.slot_record->>'resource_created_at'
      AND rc.policy_id=a.policy_id AND rc.workflow_id=(a.original_record->>'workflow_id')::uuid
      AND rc.generation=(claim.original_record->>'generation')::bigint AND rc.fence=(claim.original_record->>'fencing_token')::bigint
      AND rc.lease_owner=claim.original_record->>'lease_owner' AND rc.executor_id=claim.original_record->>'executor_id'
      AND pc.policy_id=rc.policy_id AND pc.generation=rc.generation AND pc.fence=rc.fence AND pc.lease_owner=rc.lease_owner AND pc.executor_id=rc.executor_id
      AND rc.original_record->>'usage_class'=CASE WHEN NEW.stage='terminal' THEN 'after_retirement_floor' ELSE 'before_retirement_floor' END
      AND pc.original_record->>'usage_class'=rc.original_record->>'usage_class'
      AND rc.recorded_at>CASE WHEN NEW.stage='terminal' THEN (SELECT max(recorded_at) FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='absence_complete' AND sequence>claim.sequence) ELSE claim.recorded_at END
      AND pc.recorded_at>claim.recorded_at AND rr.recorded_at>=rc.recorded_at AND pr.recorded_at>=pc.recorded_at
      AND rr.recorded_at BETWEEN actual_now-make_interval(secs=>(SELECT (spec->>'max_evidence_age_seconds')::integer FROM public.manifests WHERE id=a.policy_id)) AND actual_now)))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion fresh real survivor floor refused'; END IF;
 END IF;
 IF NEW.stage IN('inventory_prepared','absence_prepared') THEN
  IF jsonb_typeof(r) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(r))<>9
  OR r-ARRAY['schema','read_id','cleanup_id','kind','claim_sequence','admission_sha256','child_grant_id','issued_at_core','original_deadline_core']<>'{}'::jsonb
  OR EXISTS(SELECT 1 FROM jsonb_each(r) v WHERE v.value='null'::jsonb)
  OR jsonb_typeof(r->'claim_sequence') IS DISTINCT FROM 'number' OR r->>'claim_sequence' !~ '^[1-9][0-9]*$'
  OR r->>'schema' IS DISTINCT FROM 'witnessed_unenrolled_expansion_native_read_v1'
  OR COALESCE(r->>'read_id','') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
  OR r->>'read_id'='00000000-0000-0000-0000-000000000000'
  OR r->>'admission_sha256' IS DISTINCT FROM a.admission_sha256
  OR (r->>'original_deadline_core')::timestamptz>(claim.original_record->>'lease_expires_at')::timestamptz
  OR r->>'kind' IS DISTINCT FROM split_part(NEW.stage,'_',1) OR r->>'cleanup_id' IS DISTINCT FROM a.id::text OR r->>'child_grant_id' IS DISTINCT FROM a.child_grant_id::text
  OR (r->>'claim_sequence')::bigint IS DISTINCT FROM claim.sequence
  OR (r->>'original_deadline_core')::timestamptz<=(r->>'issued_at_core')::timestamptz OR (r->>'original_deadline_core')::timestamptz>(r->>'issued_at_core')::timestamptz+interval '5 seconds'
  OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events p WHERE p.cleanup_id=a.id AND p.stage=NEW.stage AND NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events q WHERE q.cleanup_id=a.id AND q.stage=split_part(NEW.stage,'_',1)||'_returned' AND q.original_record#>>'{evidence,read,read_id}'=p.original_record#>>'{evidence,read_id}'))
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion read preparation refused'; END IF;
  IF NEW.stage='inventory_prepared' AND EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id) THEN RAISE EXCEPTION 'witnessed unenrolled expansion inventory cannot rearm child'; END IF;
  IF NEW.stage='absence_prepared' AND NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants g WHERE g.id=a.child_grant_id AND g.state='settled' AND g.grant_record#>>'{settlement,outcome}'='accepted' AND g.grant_record#>>'{settlement,transport_completed}'='true' AND g.grant_record#>>'{settlement,auxiliary_inventory_complete}'='true') THEN RAISE EXCEPTION 'witnessed unenrolled expansion sealed destroy required'; END IF;
 ELSIF NEW.stage IN('inventory_qualified','pending_absence','absence_complete') THEN
  IF previous.stage<>(CASE WHEN NEW.stage='inventory_qualified' THEN 'inventory_returned' ELSE 'absence_returned' END)
  OR (previous.original_record->'evidence')-ARRAY['pending','complete'] IS DISTINCT FROM r-ARRAY['pending','complete']
  OR r->>'call_failed' IS DISTINCT FROM 'false' OR r->>'original_context_failed' IS DISTINCT FROM 'false'
  OR (r->>'returned_at_core')::timestamptz>=(r#>>'{read,original_deadline_core}')::timestamptz
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion qualified return lacks complete original'; END IF;
  IF NEW.stage='inventory_qualified' THEN
   IF public.witnessed_expansion_inventory_return_valid107(r,a.original_record,(SELECT spec FROM public.manifests WHERE id=a.policy_id)) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact original paid inventory required'; END IF;
   IF r->>'status' IS DISTINCT FROM 'dry_run' OR r#>>'{plan,server,id}' IS DISTINCT FROM a.original_record->>'resource_id'
   OR r#>>'{plan,server,created_at}' IS DISTINCT FROM a.original_record->>'resource_created_at'
   OR r#>>'{plan,server,physical_spec_verified}' IS DISTINCT FROM 'true' OR r#>>'{plan,server,auxiliary_inventory_complete}' IS DISTINCT FROM 'true'
   THEN RAISE EXCEPTION 'witnessed unenrolled expansion owned attached inventory required'; END IF;
  ELSE
   IF public.witnessed_expansion_absence_read_valid106(r,a.original_record) IS NOT TRUE THEN RAISE EXCEPTION 'witnessed unenrolled expansion observer wrapper refused'; END IF;
   IF NEW.stage='absence_complete' AND(r->>'complete' IS DISTINCT FROM 'true' OR r->>'pending' IS DISTINCT FROM 'false' OR r#>>'{observation,server_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,billable_resources_absent}' IS DISTINCT FROM 'true' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'true' OR jsonb_array_length(r#>'{observation,hold_reasons}') IS DISTINCT FROM 0 OR EXISTS(SELECT 1 FROM jsonb_array_elements(r#>'{observation,auxiliary_resources}') aux WHERE aux->>'absent' IS DISTINCT FROM 'true')) THEN RAISE EXCEPTION 'witnessed unenrolled expansion complete paid absence required'; END IF;
   IF NEW.stage='pending_absence' AND(r->>'pending' IS DISTINCT FROM 'true' OR r->>'complete' IS DISTINCT FROM 'false' OR r#>>'{observation,retirement_complete}' IS DISTINCT FROM 'false' OR jsonb_array_length(r#>'{observation,hold_reasons}') NOT BETWEEN 1 AND 3) THEN RAISE EXCEPTION 'witnessed unenrolled expansion exact pending required'; END IF;
  END IF;
 ELSIF NEW.stage='issued' THEN
  IF previous.stage IS DISTINCT FROM 'inventory_qualified' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage IN('issued','possible_send'))
  OR NOT EXISTS(SELECT 1 FROM public.capacity_mutation_grants WHERE id=a.child_grant_id AND grant_record->>'witnessed_unenrolled_expansion_cleanup_id'=a.id::text AND state='issued')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion child issue is once'; END IF;
 ELSIF NEW.stage='possible_send' THEN
  IF previous.stage<>'issued' OR EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events WHERE cleanup_id=a.id AND stage='possible_send')
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion possible send is once'; END IF;
 ELSIF NEW.stage='terminal' THEN
  IF previous.stage IS DISTINCT FROM 'absence_complete' OR NOT EXISTS(SELECT 1 FROM public.capacity_witnessed_unenrolled_expansion_cleanup_events e WHERE e.cleanup_id=a.id AND e.stage='absence_complete' AND e.sequence>claim.sequence AND public.witnessed_expansion_absence_read_valid106(e.original_record->'evidence',a.original_record))
  OR r->>'original_guest_success' IS DISTINCT FROM 'false' OR r->>'clean_cycle_credit' IS DISTINCT FROM 'false' OR r->>'serving_or_business_or_savings_authority' IS DISTINCT FROM 'false'
  THEN RAISE EXCEPTION 'witnessed unenrolled expansion terminal requires its real fresh paid absence'; END IF;
 ELSE RAISE EXCEPTION 'witnessed unenrolled expansion event stage refused'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
