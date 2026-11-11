#!/usr/bin/env python3
"""INERT G15/Core7-to-Core8 image maintenance with a distinct read-only AWS inventory observer.

No direct business/provider/Guest operation. The distinct normal-finish recovery scenario
authenticates closed failures for image maintenance only; it grants no business resume. Actual release, Root data/config and normal
G15 acceptance remain independent unbound prerequisites. No action on import.
"""
import argparse
import base64
import contextlib
import copy
import datetime
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
import types

SOURCE_BOUND = False
M97 = 'b90086284a3a9230ed7fb19e2348b8ca785f6172b819e1a08fc28d6e5c8d550f'
M97_FUNCTION_BODY_SHAS = {'guard_retirement_forward': '1f90291c1a8d1742f530c62d0cbf25ce33e66990a1045cb06571a793cb47cae0', 'retirement_forward_normal_finish_recovery_valid': '9813c29a5a449f41cd919cf6481e6c3e0ac9fc659ef1b76bc15308edacd24154'}

NORMAL_FINISH_SCHEMA = 'g15_normal_finish_recovery_image_maintenance_v1'
NORMAL_FINISH_CASE_SCHEMA = 'root_original_normal_finish_failed_case_v1'
NORMAL_FINISH_TARGET = {
    'retirement_request_id': '2c4f52ef-21d3-4f50-890a-34140caa79b4',
    'preregistration_id': '079677b7-fa87-4b8f-a2ff-3a87d33c0176',
    'run_id': 'f705fab4-e3f3-4529-baf8-4d60383caca7',
    'generation': 37, 'fence': 76,
    'lease_owner': '83b746d8-c9bb-4e94-bd20-80ad9da7da39',
    'executor_id': '4c394a88-d210-4a70-931c-a67ff39554e1',
}
ROOT_CORE7_SHA = '22c91f114e92a55fb0c38f96a4238f8a8eaf75f72d6175a90c553e466a1974d8'
M8_RETURN_SHA = 'c21e08fd33064b4a334eb623d94e5a526c00c026050430709656bd0c2955cdbe'
HISTORICAL_CORE6_SOURCE = '045176d16947555ccbc33a8b51635b08d2d9270e'
NORMAL_FINISH_SQL = "WITH request AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_intents\n WHERE id='2c4f52ef-21d3-4f50-890a-34140caa79b4'::uuid\n AND preregistration_id='079677b7-fa87-4b8f-a2ff-3a87d33c0176'::uuid\n), pre AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_provisioning_preregistrations\n WHERE id='079677b7-fa87-4b8f-a2ff-3a87d33c0176'::uuid\n), owners AS MATERIALIZED (\n SELECT w.* FROM public.capacity_dispatch_jobs j JOIN public.workflow_runs w ON w.id=j.run_id\n CROSS JOIN LATERAL (SELECT w.result#>'{steps,0,metadata}' AS metadata OFFSET 0) m\n WHERE j.realm='dakasa-production' AND j.environment='production' AND j.domain='notify'\n AND j.dimension='original_notify_aws_vm_members' AND\n (w.id='f705fab4-e3f3-4529-baf8-4d60383caca7'::uuid OR\n  (m.metadata->>'generation'='37'\n   AND m.metadata->>'fencing_token'='76'\n   AND m.metadata->>'lease_owner'='83b746d8-c9bb-4e94-bd20-80ad9da7da39'))\n), bindings AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_delete_bindings\n WHERE intent_id='2c4f52ef-21d3-4f50-890a-34140caa79b4'::uuid\n), snapshot(v) AS MATERIALIZED (SELECT jsonb_build_object(\n 'selected_runtime_source','21003808115d0b5cd62ae503ef16e65e13d4798f',\n 'target',jsonb_build_object('retirement_request_id','2c4f52ef-21d3-4f50-890a-34140caa79b4','preregistration_id','079677b7-fa87-4b8f-a2ff-3a87d33c0176'),\n 'current_intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'current_intent_pgtext',(SELECT i.intent::text FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'active_policies',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'version',p.version,'checksum',p.checksum,'spec',p.spec) ORDER BY p.version),'[]'::jsonb) FROM public.manifests p WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production' AND p.name='notify-aws-elastic-capacity' AND p.active),\n 'retirement_requests',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM request x),\n 'preregistrations',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM pre x),\n 'create_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb) FROM public.capacity_mutation_grants g JOIN pre ON pre.create_grant_id=g.id),\n 'retirement_contexts',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM public.capacity_guest_original_retirement_contexts x JOIN request r ON r.id=x.intent_id),\n 'caller_returns',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at),'[]'::jsonb) FROM public.capacity_guest_original_caller_returns x JOIN request r ON r.id=x.intent_id),\n 'original_returns',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.sequence),'[]'::jsonb) FROM public.capacity_vm_retirement_original_returns x JOIN request r ON r.id=x.intent_id),\n 'native_poweroff_reads',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id),'[]'::jsonb) FROM public.capacity_guest_original_native_poweroff_reads x JOIN request r ON r.id=x.intent_id),\n 'forward_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM public.capacity_guest_retirement_forwards x JOIN request r ON r.id=x.retirement_request_id),\n 'forward_reads',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM public.capacity_guest_retirement_forward_reads x JOIN request r ON r.id=x.retirement_request_id),\n 'delete_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM bindings x),\n 'destroy_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb) FROM public.capacity_mutation_grants g WHERE g.id IN(SELECT destroy_grant_id FROM bindings) OR (g.generation=37 AND g.grant_record#>>'{grant,capability}'=g.grant_record#>>'{binding,destroy_capability}' AND EXISTS(SELECT 1 FROM pre JOIN public.capacity_mutation_grants created ON created.id=pre.create_grant_id WHERE g.integration_instance_id=created.integration_instance_id AND g.scope_checksum=created.scope_checksum AND g.profile_name=created.profile_name AND g.slot=created.slot))),\n 'workflow_runs',(SELECT COALESCE(jsonb_agg(to_jsonb(w)||jsonb_build_object('run_wire',row_to_json(w)::text) ORDER BY w.id),'[]'::jsonb) FROM owners w),\n 'owning_dispatch_jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j)||jsonb_build_object('dispatch_wire',to_jsonb(j)::text) ORDER BY j.created_at,j.id),'[]'::jsonb) FROM public.capacity_dispatch_jobs j JOIN owners w ON w.id=j.run_id)\n)) SELECT jsonb_build_object('observed_at_pg',clock_timestamp(),'records',v,'records_wire',v::text,'records_sha256',encode(sha256(convert_to(v::text,'UTF8')),'hex')) FROM snapshot"
ROOT97_SHA = None
ROOT97_CURRENT_CORE_SOURCE = '21003808115d0b5cd62ae503ef16e65e13d4798f'
ROOT97_CURRENT_CORE_DIGEST = '311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce'
M97_FUNCTIONS = ('guard_retirement_forward', 'retirement_forward_normal_finish_recovery_valid')
CORE_R = None
NEW_DIGEST = None
SOURCE_PIN = None
TOOL_PINS = None
CONFIG_REF = None
G15_OPS_P = None
INVENTORY_SOURCE = None
INVENTORY_DIGEST = None
INVENTORY_CONFIG_DIGEST = None
REPAIR_HELPER_SHA256 = None
ROOT96_SHA = 'c44e5ef3554ee494001815358434119c31832977db90a44eb925097df137c9d6'
ROOT_CORE6_SHA = '20529efa40348fa53bc625ff665a1399733530e319ce1a007c9a2804e8bfc157'
M7_RETURN_SHA = 'e04f0d09bd55295664b7b7d2b62a8df4421d7b92089e360765ae4cddceb70c7c'
ROOT96_HISTORICAL_OPS_SOURCE = '33873025539cfb5691154fb8ded4fc4fd94eaf94'
ROOT96_HISTORICAL_BUSINESS_SOURCE = '045176d16947555ccbc33a8b51635b08d2d9270e'
ROOT96_HISTORICAL_AMD64_D = '85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876'
M95_MIGRATION_SHA = '50f2f1f712a91abf3ccd17d0fb2040d30b4bd2c6455268902e1452e922a94808'
M95_EVENT_BODY_SHA = '8830bda75d61322a993c0f5572268ed912e8816aab69abdfae4ccb264194a351'
CLEANUP_ID = '838331bb-fb7b-4ea3-9e67-3ffd3f539402'
CHILD_ID = 'e0059c6d-4773-4232-b047-f7561601f613'
CLEANUP_RUN = '6c23f323-f607-4015-9564-f676e8bc5d9d'
CHILD_COLUMN = 'failed_unwitnessed_expansion_cleanup_id'
SQL_DATA_REF = None
OLD_SOURCE = '21003808115d0b5cd62ae503ef16e65e13d4798f'
OLD_DIGEST = '311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce'
UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_POD = '7fdef85a-0df0-4db0-99e2-39d1cb64fb6b'
GENERATION = 280
# Exact full container/config identities are fresh Root data, never prefixes.
OLD_CONTAINER_ID = 'containerd://19a5ed4c87a28d4abbbd724248b3252d0be57c3e5fa1018c1d76f79f5e115d03'
OLD_IMAGE_CONFIG_DIGEST = 'sha256:c3432f11bbd59585bd2c6983ebf67fe269d5854681b824c18c64324db6156354'
A3_GRANT = 'c117f03f-27db-4da2-b990-c2729f98a46f'
A3_PRE = '4677b2cf-9cfa-4218-bc3d-930de13591a8'
A3_RUN = 'efad3324-4280-4928-b2e0-becc7eda08a9'
A3_JOB = '71001a02-6e60-4df1-aef7-b25cf9e07aa5'
A3_POLICY = 'ab057719-e52e-4549-8490-92766fafd24f'
A3_RESOURCE = 'i-074579943eddcf392'
A3_BIRTH = '2026-11-05T00:20:14Z'
A3_ACTION = '47557dad-d455-4e57-9af2-28e62b9e1b53'
A3_ATTEMPT = '661c977d-5dd6-4aec-a2ab-754b064c63bf'
A3_CREATOR = 'c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'
S1_RESOURCE = 'i-070b5767a35c7f0d5'
S1_BIRTH = '2026-11-03T01:17:18Z'
M94_MIGRATION_SHA = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'
M94_NEW_TRIGGERS = ('failed_unwitnessed_expansion_cleanup_event_guard', 'failed_unwitnessed_expansion_cleanup_grant_guard', 'failed_unwitnessed_expansion_cleanup_intent_guard', 'failed_unwitnessed_expansion_cleanup_admission', 'failed_unwitnessed_expansion_cleanup_immutable', 'failed_unwitnessed_expansion_cleanup_event_immutable')
M94_FUNCTIONS = ('guard_failed_unwitnessed_expansion_cleanup', 'failed_expansion_absence_read_valid', 'guard_failed_unwitnessed_expansion_cleanup_event', 'guard_failed_unwitnessed_expansion_cleanup_grant', 'guard_failed_unwitnessed_expansion_cleanup_intent', 'immutable_failed_unwitnessed_expansion_cleanup')
# Exact immutable Source metadata; future release/Root binding remains unbound.
M94_FINAL_SQL_SHA256 = '2850db98eddbfd629b98df879eb61266036d70210118e8e20289782d2b37a78c'
M94_FUNCTION_SPECS = {'guard_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'b0fe3b600ba0369096fdb300aad09d0d9501b31fb0df1d5edb025ea44c3afe70'}, 'failed_expansion_absence_read_valid': {'arguments': 'r jsonb, a jsonb', 'result': 'boolean', 'language': 'plpgsql', 'volatility': 's', 'config': None, 'body_sha256': '34b97c96e67ba85dcc11d44f023bde718acd2d6d3b5343f7da05420944408890'}, 'guard_failed_unwitnessed_expansion_cleanup_event': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '1a3da0cedfb6f77bbec3fd2f64195768ba72c0f4d321cd6a24007315d3b82b92'}, 'guard_failed_unwitnessed_expansion_cleanup_grant': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': 'fb640789db25deeab3a9fbf62e8694456b13a9aeb7e08cd089a301e6dc56a777'}, 'guard_failed_unwitnessed_expansion_cleanup_intent': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '318ae28c59482a05f78120d5bc7699725e5871285599b49d7783f2571c599a22'}, 'immutable_failed_unwitnessed_expansion_cleanup': {'arguments': '', 'result': 'trigger', 'language': 'plpgsql', 'volatility': 'v', 'config': None, 'body_sha256': '235d3654a225b91607eba3c84bdbf84be2ace3c8aaf64e65b44cba1e2947d584'}}
M94_INTENT_TRIGGER = 'failed_unwitnessed_expansion_cleanup_intent_guard'
M94_INTENT_TRIGGER_DEFINITION = 'CREATE TRIGGER failed_unwitnessed_expansion_cleanup_intent_guard BEFORE UPDATE ON public.capacity_intents FOR EACH ROW EXECUTE FUNCTION public.guard_failed_unwitnessed_expansion_cleanup_intent()'
DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/yggdrasil'
PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3Dyggdrasil'
KUBECONFIG = Path('/etc/rancher/k3s/k3s.yaml')
ROOT = Path('/var/lib/dakasa-core-rollout/g15pair')
OPLOCK = ROOT/'CORE-IMAGE-CAS.LOCK'
POLICY92_SQL_SHA = 'fa519e39989b31a7faa3c23358506992b057d6bf17ce2aad709dfe6fecd5c2c8'
CAP = 16 << 20
CHANGE_CAUSE = 'Root one Core7 to qualified Core8 image CAS; normal finish recovery, schema97'

EXPECTED_INHERITED_REFS = {'/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-ORIGINAL-CLOSING.JSONL': '42b5834830c09b9c4b044171c69c7c2d9d4aabe68223c4bbbc887162d3b61991',
 '/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-ORIGINAL-PREFIX.JSONL': '6240b7f21932747366be7ce5ce6778559b3a5b63594c6d521ba7c2ab293d55ca',
 '/var/lib/dakasa-capacity-network-recovery/100b6c2d207cb8e39a6b52839c7cddca65bd8e0dde90f86386cf57e686d05a92-QUALIFIED.PUBLIC.json': '21e4697326aa0e74b1e169a897870b10e4668328ca04d497900a2f297bc99a31',
 '/var/lib/dakasa-capacity-network-recovery/16318aeaf6613083dbbfa093d40e5c48e5a1704d41563a9b69e8fc47032f2af0-ORIGINAL-START-CALLER.PUBLIC.json': '0b6123e439384db4c8a484bc6d892269430ad1d0ef5a86a4897863835cfc19c1',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-000.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-001.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-002.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-003.PUBLIC': 'a5ae600dbc46ec7147d2d9eebf6332d802b88fddd666a636c69100041e8f664c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-004.PUBLIC': 'eab45a8f8f3ffa517ff2f69ec34788aecad0c0fa13b75905416f170174ae832a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-005.PUBLIC': '0c0c38cb4f58bc74626a88f11cb1d2fa9a99cf7914c8ecc8d07fdd76e48a49e4',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-006.PUBLIC': '9ad05fe413a30ab815daf199bad5affa8f5333adac0533e9f1adfeb61fbe475e',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-007.PUBLIC': '33ec2a8b760fc8be311d5c8c11677e06a4c5c23e4c9715838b43dbc1934e730a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-008.PUBLIC': '0e67570f63931bf4cd8e6a8c25adfa2d49e1c83778e0ea8ae37a83079a45524d',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-009.PUBLIC': '3b15998a1dfdcc7694406b238ec922ee18ac0245a8e82db538d3ae79050b45eb',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-010.PUBLIC': '7c57e0b8c8fde6b1e348f3529565c3db10de18730a3b0b0bf6c030a624d208e8',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-011.PUBLIC': '444a9a7809645adb806965188d2acc66b4baac2ac3709f96dccd5c4b84d78882',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-012.PUBLIC': '4a97f07c2a4c1a4093c4980916c5df080a6e6a03e374f1063b162464d4005a37',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-013.PUBLIC': '56662ef0bd85f39ef3acd8b7a0f081bafdbca1dbdcc9e68de184762a16696018',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-014.PUBLIC': 'b58c052f197a0c0965eec6f589ec6a98c1258799f0f0402f44a0255fcdd2f748',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-015.PUBLIC': '87000b3e7b94475084db03fcd5ec687818aa1aac8c9506837670b0be546b47b8',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-016.PUBLIC': '46c33d8621dc5a1a235ce881fea0ac167546a45fc0e9c3ff092b82247ec151b2',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-017.PUBLIC': 'b8e78b562498ff7b0802089c1d3d7f8b3543f2eacc26b328039be98aa526c623',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-018.PUBLIC': '5fbb03fb64fe747ff71f432939cb079b6167e10370656310f1933361f185ed31',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-019.PUBLIC': '740d7d3f97947a82657fbc52fc5b88496b9ca124952c2361c4d8d5457f42dbd0',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-020.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-021.PUBLIC': 'a5ae600dbc46ec7147d2d9eebf6332d802b88fddd666a636c69100041e8f664c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-022.PUBLIC': 'eab45a8f8f3ffa517ff2f69ec34788aecad0c0fa13b75905416f170174ae832a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-023.PUBLIC': '0c0c38cb4f58bc74626a88f11cb1d2fa9a99cf7914c8ecc8d07fdd76e48a49e4',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-024.PUBLIC': '9ad05fe413a30ab815daf199bad5affa8f5333adac0533e9f1adfeb61fbe475e',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-025.PUBLIC': '33ec2a8b760fc8be311d5c8c11677e06a4c5c23e4c9715838b43dbc1934e730a',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-026.PUBLIC': '0e67570f63931bf4cd8e6a8c25adfa2d49e1c83778e0ea8ae37a83079a45524d',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-027.PUBLIC': '415c3f6a7adcc100d3e6c81a03bacad35a35adc5cb936f5f783a97b569bc991b',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-028.PUBLIC': 'e85cdc89e63efa30a55bc82b76f12de66f67d1e80588278fde30b55a8e91e65f',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-029.PUBLIC': 'b3b18ab331ab9a438fe5c5b68296f8d7a85b0cd3c3c611151c9dfdcae555cc5c',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-READ-030.PUBLIC': 'b4e72700d714bafa9a32615b17c77891beb947d43d4513aadc5e933894cff731',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-651c798b400048929e705c00f8185931-FIRST-CURRENT15-RETURN.PUBLIC.json': 'c7ea2e766170be89868bb3bad661b448bcda458d587137e40bd019dc3ab5dcee',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-RECOVERY-16318aeaf6613083dbbfa093d40e5c48e5a1704d41563a9b69e8fc47032f2af0-POSSIBLE-START.PUBLIC.json': 'c135e28d51f47fbe04cd4ad1ac2869e15e974043998df6a08c9a35e00d42a865',
 '/var/lib/dakasa-capacity-network-recovery/da4532e3a6d1391f2d25947f0a326e8c4c6a1e133c3fd40a9a0a54e69c194972-QUALIFIED.PUBLIC.json': '5ddec8e4df310b344a8066984066f207e9e63b781d923ec8c94b95437ebf6564',
 '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-f75222a9f6ef4348842c653ebe3f1ac7-FIRST-CURRENT15-RETURN.PUBLIC.json': 'b98254514e5975fb2773212b912e9695b67f97a0fae5be152c3dde2934098931'}

EXPECTED_CURRENT_G8_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/d323cc228bec43596ac73c99cc473298896b8f2d88b06219aa69a549633925b3-QUALIFIED.PUBLIC.json': '68f5b3bcd33a9ab8e1ad29f3fdbf52a83166b694b81f5bce474e2fe85afecce3', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-a1826878088e4dbaa5e7adfb67cba5c6-FIRST-CURRENT15-RETURN.PUBLIC.json': 'e406648a4ecd503ff8231e5fde8d6969a091fe9327c4e8e0927815eb929711c4'}

EXPECTED_CURRENT_G9_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/eeb07b5f3d171544f5eddc02c4d0cbad6d07854bdf2958d697ef56d33c5e9c5c-QUALIFIED.PUBLIC.json': 'c3d6f4cac12d61e8ade4189012d065fff95e213f9cdc8edaeea757887234b16d', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-821ba94c6a3d4b32a22f022949691a1e-FIRST-CURRENT15-RETURN.PUBLIC.json': '2c18fb8de9ab3d1aeffd0302ac8d93f4797936ff6fb475e6f32061880ce17f56'}

class Hold(RuntimeError):
    pass

def need(ok, guard):
    if not ok:
        raise Hold(guard)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def read(path, cap=32 << 20, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1
             and (stat.S_IMODE(a.st_mode) == mode if mode is not None else not stat.S_IMODE(a.st_mode) & 0o022), 'ROOT_PRIVATE_STABLE_INPUT')
        rows, size = [], 0
        while True:
            row = os.read(fd, min(65536, cap + 1 - size))
            if not row:
                break
            size += len(row)
            need(size <= cap, 'BOUNDED_INPUT')
            rows.append(row)
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'UNCHANGED_FULL_INPUT')
        return b''.join(rows)
    finally:
        os.close(fd)

def full_id(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) is not None

def digest_value(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None and value != '0' * 64

def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()

def utc(value):
    need(type(value) is str and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})', value), 'ACTUAL_ZONED_TIMESTAMP')
    # Python before 3.11 accepts only 3/6 fractional digits; retain the raw wire
    # and parse its accepted 1..9 digits at datetime's microsecond precision.
    normalized = re.sub(r'\.(\d{1,9})(?=Z|[+-])', lambda match: '.' + (match.group(1) + '000000')[:6], value)
    return datetime.datetime.fromisoformat(normalized.replace('Z', '+00:00'))

def input_ref(C, ref):
    need(type(ref) is dict and set(ref) == {'path', 'sha256'} and type(ref['path']) is str
         and Path(ref['path']).is_absolute() and C.digest(ref['sha256']), 'CLOSED_PRIVATE_ORIGINAL_REF')
    raw = C.read(ref['path'], CAP, 0o600)
    need(sha(raw) == ref['sha256'], 'EXACT_PRIVATE_ORIGINAL_BYTES')
    return raw

def required_protected_refs():
    require_bound()
    out = dict(EXPECTED_INHERITED_REFS)
    for rows in (EXPECTED_CURRENT_G8_PROOF_REFS, EXPECTED_CURRENT_G9_PROOF_REFS):
        for path, pin in rows.items():
            need(path not in out and re.fullmatch('[a-f0-9]{64}', str(pin)), 'NO_ORIGINAL_REF_REPLACEMENT')
            out[path] = pin
    need(len(out) == 43, 'EXACT_ROOT_ACCEPTED_43_REF_UNION')
    return out

@contextlib.contextmanager
def operation_lock():
    fd = os.open(OPLOCK, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
             and stat.S_IMODE(s.st_mode) == 0o600, 'EXACT_EXISTING_OPERATION_MUTEX')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield (s.st_dev, s.st_ino)
        current = OPLOCK.lstat()
        need((current.st_dev, current.st_ino) == (s.st_dev, s.st_ino), 'SAME_OPERATION_MUTEX_INODE')
    finally:
        os.close(fd)

class API:
    """Exactly one HTTP request per call; no redirects, reconnect or retry.

    Credentials are read only from the exact private kubeconfig and held in RAM.
    The client certificate/key are loaded through anonymous Linux memfd, never
    emitted, written to evidence, or passed as command arguments.
    """
    def __init__(self, cut):
        need(KUBECONFIG.lstat().st_uid == 0 and stat.S_IMODE(KUBECONFIG.lstat().st_mode) == 0o600
             and not KUBECONFIG.is_symlink(), 'EXACT_PRIVATE_K3S_KUBECONFIG')
        input_pin = sha(read(KUBECONFIG, 1 << 20, 0o600))
        raw = cut.native(cut.KUBE + ['config', 'view', '--minify', '--raw', '-o', 'json'], 8, 1 << 20)
        need(raw.returncode == 0 and sha(read(KUBECONFIG, 1 << 20, 0o600)) == input_pin, 'LOCAL_KUBECONFIG_STABLE_READ_ZERO')
        config = cut.C.loads(raw.stdout)
        need(len(config['clusters']) == len(config['users']) == len(config['contexts']) == 1, 'ONE_LOCAL_K3S_CONTEXT')
        cluster, user = config['clusters'][0]['cluster'], config['users'][0]['user']
        need(set(cluster) == {'server', 'certificate-authority-data'} and cluster['server'] == 'https://127.0.0.1:6443'
             and set(user) == {'client-certificate-data', 'client-key-data'}, 'EXACT_LOOPBACK_K3S_MTLS_NO_EXEC_TOKEN_OR_PROXY')
        ctx = ssl.create_default_context(cadata=base64.b64decode(cluster['certificate-authority-data'], validate=True).decode())
        cert = base64.b64decode(user['client-certificate-data'], validate=True)
        key = base64.b64decode(user['client-key-data'], validate=True)
        fd = os.memfd_create('core-cas-client-mtls', os.MFD_CLOEXEC)
        try:
            os.fchmod(fd, 0o600)
            material = memoryview(cert + b'\n' + key)
            while material:
                n = os.write(fd, material)
                need(n > 0, 'FULL_PRIVATE_MEMFD_WRITE')
                material = material[n:]
            ctx.load_cert_chain('/proc/self/fd/' + str(fd))
        finally:
            os.close(fd)
        self.context = ctx

    def request(self, method, uri, body=None):
        need(method in ('GET', 'PATCH') and uri.startswith('/'), 'CLOSED_K3S_METHOD')
        conn = http.client.HTTPSConnection('127.0.0.1', 6443, context=self.context, timeout=12)
        try:
            headers = {'Accept': 'application/json'}
            if method == 'PATCH':
                headers['Content-Type'] = 'application/json-patch+json'
            conn.request(method, uri, body=body, headers=headers)
            response = conn.getresponse()
            raw = response.read((16 << 20) + 1)
            need(len(raw) <= 16 << 20, 'BOUNDED_API_RESPONSE')
            return response.status, raw, {'audit_id': response.getheader('Audit-Id'), 'date': response.getheader('Date')}
        finally:
            conn.close()

def api_read(api, C, run, name, uri):
    status, raw, headers = api.request('GET', uri)
    C.once(run / (name + '.json'), raw)
    C.once(run / (name + '.HTTP.json'), C.wire({'status': status, **headers}))
    need(status == 200, 'READ_ONLY_API_GET_200_' + name)
    return C.loads(raw)

def result_shape(before, after, C):
    expected_spec = copy.deepcopy(before['spec'])
    expected_spec['template']['spec']['containers'][0]['image'] = C.IMAGE_PREFIX + C.NEW_DIGEST
    need(after['apiVersion'] == before['apiVersion'] and after['kind'] == before['kind']
         and after['spec'] == expected_spec, 'FULL_SPEC_DIFF_ONLY_CORE_IMAGE')
    a, b = copy.deepcopy(before['metadata']), copy.deepcopy(after['metadata'])
    a['annotations']['dakasa.io/core-source-commit'] = CORE_R
    a['annotations']['kubernetes.io/change-cause'] = CHANGE_CAUSE
    for key in ('resourceVersion', 'generation', 'managedFields'):
        a.pop(key, None)
        b.pop(key, None)
    need(a == b and after['metadata']['uid'] == UID and after['metadata']['generation'] == GENERATION + 1,
         'ONLY_EXPLICIT_SOURCE_AND_CHANGE_CAUSE_METADATA_DIFF')

def query(cut,run,name,sql):
    body="BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL statement_timeout='3s'; SET LOCAL lock_timeout='500ms'; SET LOCAL timezone='UTC';\n"+sql+"\n;\nROLLBACK;\n"
    cut.C.once(run/(name+'.sql'),body.encode())
    cmd='PGOPTIONS="-c default_transaction_read_only=on -c statement_timeout=3000 -c lock_timeout=500 -c timezone=UTC" exec psql -XqAt -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d yggdrasil'
    start=datetime.datetime.now(datetime.timezone.utc).isoformat();mono=time.monotonic();code=None;out=b'';err=b'';timeout=False
    try:
        result=subprocess.run(cut.KUBE+['-n','dakasa','exec','-i','unified-database-0','--','sh','-c',cmd],input=body.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=8,check=False)
        out,err,code=result.stdout,result.stderr,result.returncode
    except subprocess.TimeoutExpired as e:out=e.stdout or b'';err=e.stderr or b'';timeout=True
    finally:
        cut.C.once(run/(name+'.stdout'),out);cut.C.once(run/(name+'.stderr'),err)
        cut.C.once(run/(name+'.RETURN.json'),cut.C.wire({'started_at':start,'ended_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'elapsed_seconds':time.monotonic()-mono,'returncode':code,'timed_out':timeout}))
    need(code==0 and not timeout and not err and len(out)<=CAP,'COMPLETE_READONLY_SQL_RETURN_ZERO');return cut.C.loads(out)

def closed_g15_return_path(path, state):
    # Lexical normal-G15 namespace check precedes directory and file access.
    need(path.name == 'RETURN.json' and path.parent.parent == ROOT == state
         and path.parent.name.startswith('swap-once-'),
         'CLOSED_G15_NORMAL_RETURN_NAMESPACE_BEFORE_IO')


def accepted_guardian(cut,returned):
    require_bound()
    C=cut.C;actual=cut.physical_identity(C.GUARD,cut.guardian_argv(C.NEW_SOURCE,SOURCE_PIN))
    need(actual==returned['result']['guardian'],'SAME_ACTUAL_G15_GUARDIAN_LIFETIME');return actual


def g15_acceptance(cut, folder, manifest, returned, run):
    require_bound()
    C = cut.C
    need(set(returned)=={'schema','status','result','automatic_replay','Guest_or_Core_business_authority'}and returned['schema']=='g15_pair_swap_return_v1'and returned['status']=='CONFIG_SWAP_OK'and returned['automatic_replay']is False and returned['Guest_or_Core_business_authority']is False,'ACTUAL_CLOSED_G15_SWAP_RETURN')
    result = returned['result']
    need(result['source_commit'] == manifest['source_commit'] and result['source_R'] == CORE_R and result['amd64_D'] == C.NEW_DIGEST
         and result['new_guardian_source_sha256'] == SOURCE_PIN and result['controller_config_sha256'] == C.HEAD_CONFIG_SHA
         and result['independent_current15'] is True and result['all_inherited_budget_and_original_refs_unchanged'] is True
         and result['Core_Cold_Hub_or_provider_mutation'] is False
         and all(v == 0 for v in result['conservative_per_role_gap_seconds'].values()), 'QUALIFIED_G15_RETURN_EXACT_P_R_D_AND_NO_ROLE_GAP')
    refs = manifest['protected_refs']
    need(len(refs) == len(required_protected_refs()) and len({r['path'] for r in refs}) == len(refs)
         and {r['path']:r['sha256'] for r in refs} == required_protected_refs(),
         'EXACT_INHERITED41_PLUS_ACTUAL_G9_FULL120_AND_OWN15_REFS')
    backend = cut.Backend(folder, manifest, '', run, {}, [], {})
    backend.files(successor=True)
    protected = backend.protected()
    C.once(run / 'PROTECTED-REFS-BEFORE.json', C.wire(protected))
    need(C.sha(C.read(C.NEW_STANDING, 32768, 0o600)) == result['standing_sha256'], 'EXACT_ACCEPTED_G15_STANDING')
    for key in ('controller', 'guardian'):
        C.identity(result[key])
    ctrl = cut.physical_identity(C.CTRL, cut.controller_argv(C.NEW_CONFIG))
    guard = accepted_guardian(cut, returned)
    need(ctrl == result['controller'] and guard == result['guardian'], 'SAME_ACCEPTED_G15_CONTROLLER_GUARDIAN')
    G = C.load_guardian(C.NEW_SOURCE, SOURCE_PIN)
    owner = G.Owner(SOURCE_PIN)
    full = owner.identity()
    need({k: full[k] for k in ctrl} == ctrl and owner.original_qualification_measurement(full) is not None, 'RECOMPUTED_ACTUAL_G15_FULL120_SAME_LIFETIME')
    full_path = C.LEDGER / (owner.key(full) + '-QUALIFIED.PUBLIC.json')
    own_path = C.LEDGER / (guard['boot_id'] + '-GUARDIAN-' + guard['InvocationID'] + '-FIRST-CURRENT15-RETURN.PUBLIC.json')
    for field, expected_path in (('actual_new_full120_ref', full_path), ('own_daemon_first_current15_ref', own_path)):
        ref = result[field]
        need(set(ref) == {'path', 'sha256'} and ref['path'] == str(expected_path)
             and C.sha(C.read(expected_path, 16 << 20, 0o600)) == ref['sha256'], 'SAME_G15_ACTUAL_ORIGINAL_QUALIFICATION_REF')
    own = C.loads(C.read(own_path, 16 << 20, 0o600))
    need(own['schema'] == 'Root_owning_finite512_current15_readonly_observation_v1' and own['source_sha256'] == SOURCE_PIN
         and own['standing_config_sha256'] == result['standing_sha256'] and own['identity'] == full
         and own['measurement']['qualified_15_seconds'] is True and own['measurement']['all_requested_rows_accounted_for'] is True
         and own['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'ACTUAL_G15_DAEMON_OWN15_NOT_ASSESSOR_SUBSTITUTE')
    observation, prefix, suffix, reads = owner.current15_readonly()
    # Raw observe() omits persist() envelope fields. Bind its real native
    # observation to the same authenticated Source/standing Owner instead.
    need(observation['identity'] == full and owner.sha == SOURCE_PIN
         and C.sha(owner.raw_config) == result['standing_sha256']
         and observation['measurement']['qualified_15_seconds'] is True
         and observation['measurement']['all_requested_rows_accounted_for'] is True
         and observation['kernel']['all_four_backends_and_reverse_sources_positive'] is True, 'FRESH_INDEPENDENT_CURRENT15_ALL_FOUR')
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15-PREFIX.JSONL', prefix)
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15-CLOSING.JSONL', suffix)
    C.once(run / 'FRESH-INDEPENDENT-CURRENT15.json', C.wire({'observation': observation, 'native_read_count': len(reads)}))
    return backend, protected, ctrl, guard, time.monotonic()

def require_source_bound():
    need(SOURCE_BOUND is True and full_id(UID) and full_id(OLD_POD)
         and source(G15_OPS_P) and source(INVENTORY_SOURCE) and INVENTORY_SOURCE not in (A3_CREATOR,'d8cbbf48873d24439216f98c30afe2669a525b54') and digest_value(INVENTORY_DIGEST) and digest_value(INVENTORY_CONFIG_DIGEST) and re.fullmatch('[a-f0-9]{40}', str(CORE_R)) and CORE_R != OLD_SOURCE
         and digest_value(NEW_DIGEST) and NEW_DIGEST != OLD_DIGEST
         and digest_value(SOURCE_PIN) and type(TOOL_PINS) is dict
         and set(TOOL_PINS) == {'pair_change_contract.py', 'derive_g15pair_controller_config.py', 'derive_standing_config.py', 'g15cut.py'}
         and all(digest_value(v) for v in TOOL_PINS.values())
         and re.fullmatch('containerd://[a-f0-9]{64}', str(OLD_CONTAINER_ID))
         and re.fullmatch('sha256:[a-f0-9]{64}', str(OLD_IMAGE_CONFIG_DIGEST))
         and M94_MIGRATION_SHA == M94_FINAL_SQL_SHA256 and type(M94_NEW_TRIGGERS) is tuple and len(M94_NEW_TRIGGERS)>0
         and len(set(M94_NEW_TRIGGERS))==len(M94_NEW_TRIGGERS)
         and all(type(n) is str and re.fullmatch('[a-z_][a-z0-9_]*',n) for n in M94_NEW_TRIGGERS),
         'G15_RELEASE_READER_AND_FRESH_R6_PREIMAGES_NOT_BOUND')
    ref = SQL_DATA_REF
    need(type(ref) is dict and set(ref) == {'path', 'sha256'} and Path(ref['path']).is_absolute()
         and digest_value(ref['sha256']), 'CLOSED_ROOT_BOUND_INPUT_REF')
    need(SQL_DATA_REF['sha256'] == POLICY92_SQL_SHA, 'EXACT_UNMODIFIED_E70_QUERY_FACTORY')


def validated_config_ref(path, expected_sha256):
    # Lexical validation only: no resolve/stat/read, credential or native access.
    need(type(path) is str and path != '/' and '\x00' not in path
         and Path(path).is_absolute() and not path.startswith('//')
         and str(Path(path)) == path and '..' not in Path(path).parts
         and digest_value(expected_sha256), 'CLOSED_ROOT_RUNTIME_CONFIG_REF')
    return {'path': path, 'sha256': expected_sha256}


def require_bound():
    require_source_bound()
    need(type(CONFIG_REF) is dict and set(CONFIG_REF) == {'path', 'sha256'}, 'CLOSED_ROOT_BOUND_INPUT_REF')
    validated_config_ref(CONFIG_REF['path'], CONFIG_REF['sha256'])


def load_tools(folder):
    require_bound()
    for name, pin in TOOL_PINS.items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_REVIEWED_G14_TOOL')
    path = folder / 'tools/g15cut.py'
    module = types.ModuleType('reviewed_g14cut_for_core_cas')
    module.__file__ = str(path)
    exec(compile(read(path), str(path), 'exec'), module.__dict__)
    return module


def core_before(d, ps, C):
    need(C.OLD_DIGEST == OLD_DIGEST and C.OLD_CORE_SOURCE == OLD_SOURCE, 'EXACT_CURRENT_R6_AMD64_SOURCE')
    m, s = d['metadata'], d['status']
    need(d['apiVersion'] == 'apps/v1' and d['kind'] == 'Deployment' and m['namespace'] == 'dakasa'
         and m['name'] == 'yggdrasil' and m['uid'] == UID and m['generation'] == GENERATION
         and m['resourceVersion'].isdecimal() and not m.get('deletionTimestamp')
         and m['annotations']['dakasa.io/core-source-commit'] == OLD_SOURCE, 'EXACT_R6_UID_GENERATION_SOURCE')
    need(d['spec'].get('replicas', 1) == 1 and s['observedGeneration'] == GENERATION
         and all(s.get(k) == 1 for k in ('readyReplicas', 'updatedReplicas', 'availableReplicas'))
         and s.get('unavailableReplicas', 0) == 0
         and [(v['name'], v['image']) for v in d['spec']['template']['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_READY_SINGLE_R5_CORE')
    need(len(ps['items']) == 1, 'ONE_CURRENT_R5_POD')
    p = ps['items'][0]
    need(p['metadata']['uid'] == OLD_POD and not p['metadata'].get('deletionTimestamp')
         and p['status']['phase'] == 'Running' and len(p['status']['containerStatuses']) == 1
         and [(v['name'], v['image']) for v in p['spec']['containers']] == [('core', C.IMAGE_PREFIX + OLD_DIGEST)], 'EXACT_R5_POD_TUPLE')
    c = p['status']['containerStatuses'][0]
    need(c['name'] == 'core' and c['ready'] is True and c['restartCount'] == 0 and c.get('state', {}).get('running')
         and c['imageID'].rsplit(':', 1)[-1] == OLD_DIGEST and c['containerID'] == OLD_CONTAINER_ID, 'EXACT_R5_IMAGEID_CONTAINER_ZERO_RESTART')
    return {'deployment_uid': UID, 'generation': GENERATION, 'pod_uid': OLD_POD,
            'pod_name': p['metadata']['name'], 'pod_ip': p['status']['podIP'],
            'image': C.IMAGE_PREFIX + OLD_DIGEST, 'imageID': c['imageID'], 'containerID': c['containerID']}


def build_patch(before, C):
    return [
        {'op': 'test', 'path': '/metadata/uid', 'value': UID},
        {'op': 'test', 'path': '/metadata/resourceVersion', 'value': before['metadata']['resourceVersion']},
        {'op': 'test', 'path': '/metadata/generation', 'value': GENERATION},
        {'op': 'test', 'path': '/metadata/annotations', 'value': before['metadata']['annotations']},
        {'op': 'test', 'path': '/spec', 'value': before['spec']},
        {'op': 'replace', 'path': '/spec/template/spec/containers/0/image', 'value': C.IMAGE_PREFIX + C.NEW_DIGEST},
        {'op': 'add', 'path': '/metadata/annotations/dakasa.io~1core-source-commit', 'value': CORE_R},
        {'op': 'add', 'path': '/metadata/annotations/kubernetes.io~1change-cause', 'value': CHANGE_CAUSE},
    ]





def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) and value != '0' * 64

def source(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{40}', value) and value != '0' * 40

def closed(value, fields, guard):
    need(type(value) is dict and set(value) == set(fields.split()), guard)

def loads(raw):
    def unique(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'NO_DUPLICATE_JSON_KEY')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(Hold('FINITE_JSON_ONLY')))























def catalog94_projection(value):
    """Keep the entire immutable six-key93 projection; add only M94 catalog."""
    s = value['schema94']
    need(type(s) is dict and set(s) == {'tables','columns','constraints','indexes','triggers','functions'}
         and all(type(rows) is list for rows in s.values()), 'CLOSED_STABLE_SCHEMA94_CATALOG_ARRAYS')
    return {**catalog_projection(value), 'schema94':s}


def catalog94_select(legacy):
    old = catalog_select(legacy)
    tables = "to_regclass('public.capacity_failed_unwitnessed_expansion_cleanups'),to_regclass('public.capacity_failed_unwitnessed_expansion_cleanup_events'),'public.capacity_mutation_grants'::regclass,'public.capacity_intents'::regclass"
    functions = ','.join("'" + n + "'" for n in M94_FUNCTIONS)
    return "WITH old93(v) AS (" + old + ") SELECT jsonb_build_object('legacy',(SELECT v->'legacy' FROM old93),'supplement',(SELECT v->'supplement' FROM old93),'schema94',jsonb_build_object(" + """
'tables',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',format('%I.%I','public',c.relname),'kind',c.relkind,'persistence',c.relpersistence,'replica_identity',c.relreplident,'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity) ORDER BY format('%I.%I','public',c.relname)),'[]'::jsonb) FROM pg_class c WHERE c.oid IN(""" + tables + """)),
'columns',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=a.attrelid)),'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=a.attrelid)),a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN(""" + tables + """) AND a.attnum>0 AND NOT a.attisdropped),
'constraints',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=c.conrelid)),'name',c.conname,'type',c.contype,'validated',c.convalidated,'deferrable',c.condeferrable,'deferred',c.condeferred,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=c.conrelid)),c.conname),'[]'::jsonb) FROM pg_constraint c WHERE c.conrelid IN(""" + tables + """)),
'indexes',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indrelid)),'name',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indexrelid)),'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'unique',i.indisunique,'definition',pg_get_indexdef(i.indexrelid)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indrelid)),format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=i.indexrelid))),'[]'::jsonb) FROM pg_index i WHERE i.indrelid IN(""" + tables + """)),
'triggers',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=t.tgrelid)),'name',t.tgname,'enabled',t.tgenabled,'function',t.tgfoid::regprocedure::text,'definition',pg_get_triggerdef(t.oid,false)) ORDER BY format('%I.%I','public',(SELECT relname FROM pg_class WHERE oid=t.tgrelid)),t.tgname),'[]'::jsonb) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgrelid IN(""" + tables + """)),
'functions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'qualified_name',format('%I.%I',n.nspname,p.proname),'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'language',l.lanname,'volatility',p.provolatile,'config',p.proconfig,'body',p.prosrc,'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname IN(""" + functions + "))))"

LEGACY_CATALOG_SHA = 'c9d3664e43ef876a9a7a89c031bf75f761dbb0c70a664db2408058a6ce2431eb'

def workflow_busy_logical_index92_sql():
    """Closed complete busy predicate, including PostgreSQL's lossless casts."""
    predicates = (
        "(((COALESCE(status, ''::character varying))::text <> ALL ('{succeeded,failed,cancelled}'::text[])) OR (finished_at IS NULL))",
        "(((COALESCE(status, ''::character varying))::text <> ALL ((ARRAY['succeeded'::character varying, 'failed'::character varying, 'cancelled'::character varying])::text[])) OR (finished_at IS NULL))",
    )
    quoted = ','.join("'" + value.replace("'", "''") + "'" for value in predicates)
    return """COALESCE((SELECT i.indisvalid AND i.indisready AND i.indislive AND NOT i.indisunique
 AND i.indrelid='public.workflow_runs'::regclass AND i.indnkeyatts=3 AND i.indnatts=3
 AND i.indexprs IS NULL AND i.indpred IS NOT NULL AND a.amname='btree'
 AND pg_get_indexdef(i.indexrelid,1,false)='workflow_namespace'
 AND pg_get_indexdef(i.indexrelid,2,false)='workflow_name'
 AND pg_get_indexdef(i.indexrelid,3,false)='id'
 AND pg_get_expr(i.indpred,i.indrelid,false) IN (""" + quoted + """)
 FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid JOIN pg_am a ON a.oid=c.relam
 WHERE i.indexrelid=to_regclass('public.workflow_runs_busy_logical_idx')),false)"""

def catalog_sql(legacy, V):
    need(sha(legacy.encode()) == LEGACY_CATALOG_SHA and legacy.endswith(';\nCOMMIT;'), 'EXACT_REVIEWED_CATALOG_QUERY_OPERANDS')
    header, select = legacy.split('\nSELECT ', 1)
    select = select[:-len(';\nCOMMIT;')]
    return header + '\nWITH legacy AS (SELECT ' + select + ") SELECT jsonb_build_object('legacy',(SELECT * FROM legacy),'supplement',jsonb_build_object(" + """
'functions93',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'result',pg_get_function_result(p.oid),'language',l.lanname,'volatility',p.provolatile,'config',p.proconfig,'body',p.prosrc,'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='public' AND p.proname IN('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')),
'columns90_91',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',a.attrelid::regclass::text,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attrelid,a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid IN('public.capacity_guest_retirement_forwards'::regclass,'public.capacity_guest_retirement_forward_reads'::regclass,'public.capacity_dispatch_http_maintenance_dispositions'::regclass) AND a.attnum>0 AND NOT a.attisdropped),
'index92_definition',(SELECT pg_get_indexdef(to_regclass('public.workflow_runs_busy_logical_idx'))),
'index92_valid',""" + V.workflow_busy_logical_index92_sql() + """,
'old_records',jsonb_build_object(
 'forwards',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forwards x),
 'forward_reads',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id,stage),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_guest_retirement_forward_reads x),
 'http_dispositions',(SELECT jsonb_build_object('rows',count(*),'sha256',encode(digest(COALESCE(jsonb_agg(to_jsonb(x) ORDER BY id),'[]'::jsonb)::text,'sha256'),'hex')) FROM public.capacity_dispatch_http_maintenance_dispositions x))
));
COMMIT;"""


def catalog_projection(value):
    """Stable catalog identity; history, activity and ledger facts are separate."""
    v, s = value['legacy'], value['supplement']
    return {'catalog90': v['catalog90'], 'catalog91': v['catalog91'],
            **{key: s[key] for key in ('columns90_91','functions93','index92_valid','index92_definition')}}


def catalog_select(legacy):
    # Keep the shared SELECT byte-for-byte. Only the CAS reader's established
    # RR/RO3s/.5s/process8 transaction wrapper replaces the migration wrapper.
    whole = catalog_sql(legacy,types.SimpleNamespace(workflow_busy_logical_index92_sql=workflow_busy_logical_index92_sql))
    need(whole.endswith(';\nCOMMIT;') and '\nWITH legacy AS ' in whole,'CLOSED_COMMON_CATALOG_SELECT')
    return 'WITH '+whole.split('\nWITH ',1)[1][:-len(';\nCOMMIT;')]


INVENTORY_APP = 'integration-aws-inventory-readonly'
INVENTORY_DEP_URI = '/apis/apps/v1/namespaces/dakasa/deployments/'+INVENTORY_APP
INVENTORY_SVC_URI = '/api/v1/namespaces/dakasa/services/'+INVENTORY_APP
INVENTORY_PODS_URI = '/api/v1/namespaces/dakasa/pods?labelSelector=app%3D'+INVENTORY_APP
INVENTORY_IMAGE_PREFIX = '153828470928.dkr.ecr.sa-east-1.amazonaws.com/integration-aws@sha256:'


def expected_inventory_description():
    return {'schema':'aws_original_profile_inventory_readonly_describe_v1','provider':'aws-original-inventory-readonly','version':'1.0.0','source_commit':INVENTORY_SOURCE,'transport':'http_json','describe_endpoint':'/rpc/describe','execute_endpoint':'/rpc/execute','operation':'observe_original_profile_inventory','request_schema':'aws_original_profile_inventory_read_request_v1','return_schema':'aws_original_profile_inventory_read_return_v1','profile_producer_version':'1.65.5','profile_producer_source_commit':A3_CREATOR,'native_mutations':0,'normal_adapter_operations':False,'amqp_registered':False}


def inventory_description(raw):
    need(type(raw)is bytes and 0<len(raw)<=8192,'COMPLETE_BOUNDED_ORIGINAL_READER_HTTP_BODY')
    try:envelope=loads(raw)
    except (ValueError,TypeError,UnicodeError):raise Hold('COMPLETE_ORIGINAL_SDK_HTTP_JSON')from None
    closed(envelope,'content_type body','CLOSED_ORIGINAL_SDK_HTTP_REPLY_ENVELOPE')
    need(envelope['content_type']=='application/json' and type(envelope['body'])is str,'SDK_HTTP_JSON_BODY_NOT_PROJECTED_RPC_ORIGINAL')
    try:inner=base64.b64decode(envelope['body'],validate=True)
    except (ValueError,TypeError):raise Hold('SDK_HTTP_EXACT_BASE64_BODY')from None
    need(0<len(inner)<=8192 and base64.b64encode(inner).decode()==envelope['body'],'COMPLETE_CANONICAL_SDK_HTTP_BODY_BYTES')
    try:value=loads(inner)
    except (ValueError,TypeError,UnicodeError):raise Hold('COMPLETE_ORIGINAL_INNER_RPC_JSON')from None
    closed(value,'ok data','CLOSED_READONLY_DESCRIBE_TRANSPORT')
    need(value['ok']is True and value['data']==expected_inventory_description() and type(value['data']['native_mutations'])is int and value['data']['native_mutations']==0 and value['data']['normal_adapter_operations']is False and value['data']['amqp_registered']is False,'EXACT_DISTINCT_READONLY_OBSERVER_DESCRIPTION_NO_MUTATION_OR_NORMAL_ADAPTER')
    return value['data']


def inventory_objects(receipt, deployment, service, pods):
    """Same ready reader incarnation and fixed Service; no original provider call."""
    dm,ds=deployment['metadata'],deployment['spec'];state=deployment['status']
    labels={'app':INVENTORY_APP};image=INVENTORY_IMAGE_PREFIX+INVENTORY_DIGEST
    need(deployment['apiVersion']=='apps/v1' and deployment['kind']=='Deployment' and dm['namespace']=='dakasa' and dm['name']==INVENTORY_APP and dm['uid']==receipt['deployment_uid'] and not dm.get('deletionTimestamp') and ds['selector']=={'matchLabels':labels} and all(ds['template']['metadata']['labels'].get(k)==v for k,v in labels.items()) and ds.get('replicas',1)==1 and state['observedGeneration']==dm['generation'] and all(state.get(k)==1 for k in ('readyReplicas','updatedReplicas','availableReplicas')) and state.get('unavailableReplicas',0)==0,'CURRENT_QUALIFIED_READER_DEPLOYMENT_SINGLETON_READY')
    containers=ds['template']['spec']['containers'];need(len(containers)==1 and containers[0]['image']==image and not ds['template']['spec'].get('hostNetwork') and containers[0].get('command',['/app/integration-aws-inventory-readonly'])==['/app/integration-aws-inventory-readonly'] and not containers[0].get('args'),'DISTINCT_READONLY_BINARY_AND_IMMUTABLE_IMAGE_NOT_MUTATOR_OR_H7')
    sm,ss=service['metadata'],service['spec'];need(service['apiVersion']=='v1' and service['kind']=='Service' and sm['namespace']=='dakasa' and sm['name']==INVENTORY_APP and sm['uid']==receipt['service_uid'] and not sm.get('deletionTimestamp') and ss['type']=='ClusterIP' and ss['selector']==labels and len(ss['ports'])==1 and ss['ports'][0]['protocol']=='TCP' and ss['ports'][0]['port']==ss['ports'][0]['targetPort']==8081 and not ss.get('externalIPs') and not ss.get('externalName'),'EXACT_PRIVATE_READER_SERVICE_SELECTOR_8081_NO_EXTERNAL_ROUTE')
    address=ss['clusterIP'];need(type(address)is str and re.fullmatch(r'10\.43\.(?:0|[1-9][0-9]{0,2})\.(?:0|[1-9][0-9]{0,2})',address) and all(0<=int(x)<=255 for x in address.split('.')),'ACTUAL_FIXED_CLUSTERIP_RANGE_NO_CALLER_URL')
    need(type(pods)is dict and type(pods.get('items'))is list and len(pods['items'])==1 and not pods.get('metadata',{}).get('continue'),'COMPLETE_SOLE_READER_POD_CENSUS')
    pod=pods['items'][0];pm,ps,status=pod['metadata'],pod['spec'],pod['status'];cs=status['containerStatuses']
    need(pm['namespace']=='dakasa' and pm['uid']==receipt['pod_uid'] and pm.get('labels',{}).get('app')==INVENTORY_APP and not pm.get('deletionTimestamp') and status['phase']=='Running' and [x['status']for x in status.get('conditions',[])if x['type']=='Ready']==['True'] and not ps.get('hostNetwork') and len(ps['containers'])==len(cs)==1 and ps['containers'][0]['name']==containers[0]['name']==cs[0]['name'] and ps['containers'][0]['image']==image and cs[0]['ready']is True and cs[0].get('state',{}).get('running') and type(cs[0]['restartCount'])is int and cs[0]['restartCount']>=0 and cs[0]['containerID']==receipt['container_id'] and type(cs[0]['imageID'])is str and re.fullmatch(r'(?:(?:docker-pullable|containerd)://)?(?:153828470928\.dkr\.ecr\.sa-east-1\.amazonaws\.com/integration-aws@)?sha256:[a-f0-9]{64}',cs[0]['imageID']) and cs[0]['imageID'].rsplit(':',1)[-1]in(INVENTORY_DIGEST,INVENTORY_CONFIG_DIGEST),'SAME_ROOT_QUALIFIED_READER_POD_CONTAINER_AND_IMAGE_READY')
    owners=[x for x in pm.get('ownerReferences',[])if x.get('controller')is True];need(len(owners)==1 and owners[0]['kind']=='ReplicaSet' and re.fullmatch(INVENTORY_APP+'-[a-z0-9]{1,63}',owners[0]['name']),'READER_POD_HAS_FIXED_DEPLOYMENT_REPLICASET_NAME')
    return address


def deployment_ready_inputs(C, c):
    require_bound()
    normal = c.get('schema') == NORMAL_FINISH_SCHEMA
    oldref=c['acceptance_refs']['current_Core7_operational_acceptance' if normal else 'current_Core6_operational_acceptance'];need(oldref['sha256']==(ROOT_CORE7_SHA if normal else ROOT_CORE6_SHA),'IMMUTABLE_ACTUAL_CURRENT_CORE_ROOT9_PREIMAGE')
    previous=loads(input_ref(C,oldref));closed(previous,'schema reviewed_by_root status source amd64_D process_replacement_ref native_observation_ref controller_pair_ref qualified_image_and_deployment_verified','CLOSED_REAL_CORE6_ROOT9')
    need(previous['schema']=='root_core_retirement_observer_operational_acceptance_v1' and previous['reviewed_by_root']is True and previous['status']=='QUALIFIED_IMAGE_AND_DEPLOYMENT_VERIFIED' and previous['source']==(OLD_SOURCE if normal else HISTORICAL_CORE6_SOURCE) and previous['amd64_D']==(OLD_DIGEST if normal else ROOT96_HISTORICAL_AMD64_D) and previous['qualified_image_and_deployment_verified']is True and previous['controller_pair_ref']['sha256']==(M8_RETURN_SHA if normal else M7_RETURN_SHA),'ACTUAL_CURRENT_ACCEPTANCE_NOT_TARGET_OR_HISTORICAL_ROOT_ALIAS')
    for key in ('process_replacement_ref','native_observation_ref','controller_pair_ref'):input_ref(C,previous[key])
    receipt=loads(input_ref(C,c['acceptance_refs']['inventory_readonly_operational_acceptance']))
    closed(receipt,'schema reviewed_by_root status source amd64_D namespace deployment_uid service_uid pod_uid container_id provider version operation original_profile_source_commit original_refs','CLOSED_DISTINCT_READER_ROOT_ACCEPTANCE15')
    need(receipt['schema']=='root_aws_original_inventory_readonly_operational_acceptance_v1' and receipt['reviewed_by_root']is True and receipt['status']=='QUALIFIED_IMAGE_AND_DEPLOYMENT_VERIFIED' and receipt['source']==INVENTORY_SOURCE and receipt['amd64_D']==INVENTORY_DIGEST and receipt['namespace']=='dakasa' and all(full_id(receipt[k])for k in ('deployment_uid','service_uid','pod_uid')) and re.fullmatch('containerd://[a-f0-9]{64}',receipt['container_id']) and receipt['provider']=='aws-original-inventory-readonly' and receipt['version']=='1.0.0' and receipt['operation']=='observe_original_profile_inventory' and receipt['original_profile_source_commit']==A3_CREATOR,'ROOT_QUALIFIED_DISTINCT_READER_SOURCE_IMAGE_PROTOCOL_AND_INCARNATION')
    refs=receipt['original_refs'];closed(refs,'qualified_image source_ci deployment service pod describe health','SEVEN_REAL_READER_ORIGINAL_ROLES')
    raw={key:input_ref(C,value)for key,value in refs.items()}
    # Root's reviewed receipt attests image/CI qualification; heterogeneous
    # original payloads are retained/hash-checked, never qualified by length.
    manifest=loads(raw['qualified_image']);need(refs['qualified_image']['sha256']==INVENTORY_DIGEST and manifest['schemaVersion']==2 and manifest['mediaType']in('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json') and manifest['config']['digest']=='sha256:'+INVENTORY_CONFIG_DIGEST and type(manifest['config']['size'])is int and manifest['config']['size']>0 and type(manifest['layers'])is list and manifest['layers'],'QUALIFIED_PLATFORM_MANIFEST_LINKS_DISTINCT_RUNTIME_CONFIG_DIGEST')
    deployment,service,pod=(loads(raw[k])for k in ('deployment','service','pod'))
    inventory_objects(receipt,deployment,service,{'items':[pod]})
    inventory_description(raw['describe']);need(raw['health']==b'readonly observer up','ORIGINAL_READER_HEALTH_BODY')
    return receipt


def inventory_reader(api, C, run, label, receipt):
    require_bound()
    deployment=api_read(api,C,run,label+'-READER-DEPLOYMENT',INVENTORY_DEP_URI)
    service=api_read(api,C,run,label+'-READER-SERVICE',INVENTORY_SVC_URI)
    pods=api_read(api,C,run,label+'-READER-PODS',INVENTORY_PODS_URI)
    address=inventory_objects(receipt,deployment,service,pods)
    refs=receipt['original_refs']
    need(deployment['spec']==loads(input_ref(C,refs['deployment']))['spec'] and service['spec']==loads(input_ref(C,refs['service']))['spec'],'WHOLE_QUALIFIED_READER_DEPLOYMENT_AND_SERVICE_SPEC_UNCHANGED')
    for kind,method,uri,body in (('HEALTH','GET','/healthz',None),('DESCRIBE','POST','/rpc/describe',C.wire({'provider':'aws-original-inventory-readonly','expected_version':'1.0.0','expected_source_commit':INVENTORY_SOURCE}))):
        started=time.monotonic();deadline=started+2;conn=http.client.HTTPConnection(address,8081,timeout=2)
        try:
            conn.request(method,uri,body,{'Content-Type':'application/json','Accept':'application/json'})
            response=conn.getresponse();need(time.monotonic()<deadline,'READER_METADATA_ORIGINAL_TWO_SECOND_DEADLINE')
            if conn.sock is not None:conn.sock.settimeout(max(.001,deadline-time.monotonic()))
            raw=response.read(8193);need(len(raw)<=8192 and time.monotonic()<deadline,'COMPLETE_BOUNDED_READER_METADATA_RETURN')
            C.once(run/(label+'-READER-'+kind+'.original'),raw);C.once(run/(label+'-READER-'+kind+'.HTTP.json'),C.wire({'status':response.status,'bytes':len(raw),'sha256':sha(raw),'duration_seconds':time.monotonic()-started,'method':method,'uri':uri}))
            need(response.status==200,'ACTUAL_READER_METADATA_HTTP200')
            if kind=='HEALTH':need(raw==b'readonly observer up','CURRENT_READER_HEALTH_BODY')
            else:inventory_description(raw)
        finally:conn.close()
    return {'deployment_uid':receipt['deployment_uid'],'service_uid':receipt['service_uid'],'pod_uid':receipt['pod_uid'],'container_id':receipt['container_id'],'source':INVENTORY_SOURCE,'amd64_D':INVENTORY_DIGEST,'qualified_config_digest':INVENTORY_CONFIG_DIGEST,'spec_image':deployment['spec']['template']['spec']['containers'][0]['image'],'runtime_imageID':pods['items'][0]['status']['containerStatuses'][0]['imageID'],'runtime_image':pods['items'][0]['status']['containerStatuses'][0].get('image')}


def maintenance_inputs(C):
    require_bound();raw=input_ref(C,CONFIG_REF);c=loads(raw)
    if c.get('schema') == NORMAL_FINISH_SCHEMA:
        return maintenance_inputs97(C,c,raw)
    closed(c,'schema source_R amd64_D core_preimage pre_read_case schema_pins policy_state pre_read_preimage_ref schema94_catalog_ref schema95_catalog_ref prior93_history_ref prior94_history_ref legacy_catalog_sql_ref acceptance_refs schema96_catalog_ref prior95_history_ref','CLOSED16_PRE_READ96_MAINTENANCE')
    need(c['schema']in('g15_pre_read_continuation_image_maintenance_v1',LIVE_SCHEMA)and c['source_R']==CORE_R==C.SOURCE_R and c['amd64_D']==NEW_DIGEST==C.NEW_DIGEST and C.OLD_CORE_UID==UID and C.OLD_CORE_GENERATION==GENERATION and C.OLD_CORE_POD_UID==OLD_POD,'QUALIFIED_R7_AND_CURRENT_R6_PREIMAGE')
    p=c['core_preimage'];closed(p,'deployment_uid generation pod_uid container_id image_config_digest spec_sha256 annotations_sha256','CLOSED_CURRENT6_LIFETIME')
    need(p['deployment_uid']==UID and p['generation']==GENERATION and p['pod_uid']==OLD_POD and p['container_id']==OLD_CONTAINER_ID and p['image_config_digest']==OLD_IMAGE_CONFIG_DIGEST and all(digest_value(p[k])for k in ('spec_sha256','annotations_sha256')),'EXACT_ROOT_CURRENT6_WHOLE_SPEC_AND_ANNOTATIONS')
    closed(c['acceptance_refs'],'qualified_business_release business_Source_CI Root_Goose94_acceptance Root_Goose95_acceptance Root_Goose96_acceptance Root_separate_rollout_review current_Core6_operational_acceptance inventory_readonly_operational_acceptance','DISTINCT_CURRENT_CORE6_READER_TARGET_RELEASE_CI_AND_HISTORICAL_ROOTS')
    for r in c['acceptance_refs'].values():need(len(input_ref(C,r))>1,'ACTUAL_COMPLETE_PINNED_ACCEPTANCE_ORIGINAL')
    need(type(c['policy_state'])is dict and set(c['policy_state'])=={'aws','hetzner'}and all(type(v)is dict and set(v)=={'intent_identity','owned_slots','active_policies','policy_catalog_wire'}for v in c['policy_state'].values()),'BOTH_WHOLE_POLICY_ROSTERS_UNCHANGED')
    deployment_ready_inputs(C,c)
    validate_maintenance_scenario(c,C)
    sql=loads(input_ref(C,SQL_DATA_REF));need(sql['schema']=='fixed_policy_publication_schema92_SQL_data_v1'and set(sql['queries'])=={'original_notify_aws_vm_members','original_notify_hetzner_vm_members'},'EXACT_SOURCE_E70_QUERIES_WITHOUT_RECONSTRUCTION');return c,raw,sql


def schema96_facts(c, legacy, current, C):
    v,pins=legacy['schema_facts'],c['schema_pins'];versions=[0]+[x for x in range(1,97)if x!=40]
    need(current['legacy']['database']==v['database']=='yggdrasil'and current['legacy']['readonly']==v['readonly']=='on'and current['legacy']['latest_versions']==v['latest_versions']==versions and v['history_max_version']==96 and v['rows90']==v['rows91']==v['rows92']==1 and legacy['index89_valid']is True and legacy['index92_valid']is True,'EXACT96_HEAD_OLD_INDEXES_NO_SCHEMA_ALIAS')
    closed(pins,'complete_history_sha256 index92_definition_sha256 catalog90_91_sha256 schema94_catalog_sha256 schema95_catalog_sha256 schema96_catalog_sha256 constraint96_deparse_ref','CLOSED96_CATALOG_HISTORY_PINS')
    need(all(digest_value(pins[k])for k in pins if k!='constraint96_deparse_ref'),'REAL96_DIGEST_PINS')
    prior_raw=input_ref(C,c['prior95_history_ref']);prior=loads(prior_raw);full=loads(v['complete_history_wire'])
    need(loads(current['legacy']['complete_history_wire'])==full and len(full)==len(prior)+1 and [x for x in full if x['version_id']!=96]==prior and len([x for x in full if x['version_id']==96 and x['is_applied']is True])==1 and all(x['is_applied']is True for x in full)and sha(v['complete_history_wire'].encode())==pins['complete_history_sha256'],'SOLE96_WHOLE_PRIOR95_RAW_VALUES_PRESERVED')
    prior_catalog=loads(input_ref(C,c['schema95_catalog_ref']));actual=catalog94_projection(current);expected=loads(input_ref(C,c['schema96_catalog_ref']))
    need(actual==expected and sha(C.wire(actual))==pins['schema96_catalog_sha256']and sha(C.wire(prior_catalog))==pins['schema95_catalog_sha256']and sha(legacy['index92_definition'].encode())==pins['index92_definition_sha256']and sha(C.wire({'catalog90':v['catalog90'],'catalog91':v['catalog91']}))==pins['catalog90_91_sha256'],'ROOT96_EXACT_SEVEN_KEY_CATALOG_AND_CURRENT90_91_HASH')
    row=[x for x in actual['functions93']if x['name']==M96_FUNCTION];need(len(row)==1 and sha(row[0]['body'].encode())==M96_BODY_SHA,'EXACT_SOURCE96_PROSRC')
    catalog96_delta(prior_catalog,actual,row[0]['body'],constraint96_definition(prior_catalog,loads(input_ref(C,pins['constraint96_deparse_ref']))))
    need(all(v[k]==0 and current['legacy'][k]==0 for k in ('other_migrators_ddl','other_cic','ddl_locks')),'NO_OTHER_MIGRATOR_CIC_OR_DDL_LOCK')
    previous_ref=c['acceptance_refs']['Root_Goose95_acceptance'];need(previous_ref['sha256']==ROOT95_SHA,'IMMUTABLE_ROOT95_REF_NOT_RELABELED')
    previous_raw=input_ref(C,previous_ref);previous=loads(previous_raw)
    need(previous['catalog95_sha256']==pins['schema95_catalog_sha256']and previous['complete_history_sha256']==sha(prior_raw)and previous['prior94_history_sha256']==sha(input_ref(C,c['prior94_history_ref']))and sha(C.wire(loads(input_ref(C,c['schema94_catalog_ref']))))==pins['schema94_catalog_sha256'],'HISTORICAL95_AND94_REFS_REMAIN_EXACT')
    need(c['acceptance_refs']['Root_Goose96_acceptance']['sha256']==ROOT96_SHA,'IMMUTABLE_HISTORICAL_ROOT96_RECEIPT')
    r96=loads(input_ref(C,c['acceptance_refs']['Root_Goose96_acceptance']))
    root96_overlay(input_ref(C,c['acceptance_refs']['Root_Goose96_acceptance']),previous_raw,{'current_ops_source':ROOT96_HISTORICAL_OPS_SOURCE,'business_source':ROOT96_HISTORICAL_BUSINESS_SOURCE,'amd64_D':ROOT96_HISTORICAL_AMD64_D,'complete_history_sha256':pins['complete_history_sha256'],'prior95_history_sha256':sha(prior_raw),'catalog96_sha256':pins['schema96_catalog_sha256'],'index92_definition_sha256':pins['index92_definition_sha256'],'catalog90_91_sha256':pins['catalog90_91_sha256']},lambda r:input_ref(C,r))
    need(c['acceptance_refs']['Root_Goose94_acceptance']['sha256']=='3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4','IMMUTABLE_HISTORICAL94_ROOT')


def database_pre_read96(cut,run,c,sql,label):
    require_bound()
    if c.get('schema') == NORMAL_FINISH_SCHEMA:
        return database_normal_finish97(cut,run,c,sql,label)
    result={}
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        value=query(cut,run,label+'-'+provider.upper(),sql['queries'][key]);expected=c['policy_state'][provider]
        need(all(value[k]==expected[k]for k in ('intent_identity','owned_slots','active_policies','policy_catalog_wire')),'ALL_OTHER_POLICY_AND_ROSTER_BYTES_EXACT')
        lanes={k:value[k]for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','intent_count','intent_busy','pending_authority','forward_markers')}
        need(lanes==c['pre_read_case']['provider_lanes'][provider]and lanes['intent_count']==1 and all(type(lanes[k])is int and lanes[k]==0 for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries')),'EXACT_CURRENT_SOURCE_LANES_NO_GUESSED_QUIET')
        result[provider]=lanes
    scenario=c.get('schema','g15_pre_read_continuation_image_maintenance_v1')
    need(scenario in ('g15_pre_read_continuation_image_maintenance_v1',LIVE_SCHEMA),'EXPLICIT_CURRENT_DATABASE_SCENARIO')
    actual=query(cut,run,label+'-S8-PRE-READ',PRE_READ_SQL if scenario!=LIVE_SCHEMA else CURRENT_LIVE_SQL)
    if scenario==LIVE_SCHEMA:
        validate_current_live(actual,c['pre_read_case']);validate_terminal_s8(loads(input_ref(cut.C,c['pre_read_case']['historical_s8_ref'])))
    else:validate_pre_read96(actual,c['pre_read_case'])
    need(actual['records_wire']==loads(input_ref(cut.C,c['pre_read_preimage_ref']))['records_wire'],'WHOLE_S8_ORIGINAL_PREIMAGE_UNCHANGED')
    # Existing exact schema/history/index observations remain part of pre-PATCH admission.
    current=query(cut,run,label+'-SCHEMA96',catalog94_select(input_ref(cut.C,c['legacy_catalog_sql_ref']).decode()))
    first=query(cut,run,label+'-SOURCE-SCHEMA96',sql['queries']['original_notify_aws_vm_members'])
    schema96_facts(c,first,current,cut.C);return result





def global_marker(C):
    return ROOT/('CORE-IMAGE-R7-210-D311-TO-'+CORE_R+'-'+C.NEW_DIGEST+'-POSSIBLE.json')


def patch_once(api, C, run, wire, marker, observed):
    require_bound()
    """Both durable possible-send markers precede the only actual PATCH."""
    C.once(global_marker(C),C.wire(marker))
    C.once(run/'POSSIBLE-SEND.json',C.wire(marker))
    need(time.monotonic()-observed <= 15,'CURRENT15_STILL_FRESH_AFTER_DURABLE_MARKERS_NO_SEND')
    try:
        status, raw, headers = api.request('PATCH',DEP_URI+'?fieldManager=core-image-cas-once',wire)
        C.once(run/'PATCH-ACTUAL-RETURN.json',raw)
        C.once(run/'PATCH-ACTUAL-RETURN.HTTP.json',C.wire({'status':status,**headers}))
        need(status == 200,'ACTUAL_PATCH_NOT_ACKNOWLEDGED_200_NO_RETRY')
        return C.loads(raw)
    except Exception:
        # One forensic GET is permitted after possible-send. It cannot retry,
        # approve, roll back or claim rollout/business completion.
        try:
            api_read(api,C,run,'LOST-ACK-GET-ONLY',DEP_URI)
        except Exception:
            pass
        raise Hold('POSSIBLE_PATCH_RECONCILE_GET_ONLY_NO_RETRY') from None


def main():
    global CONFIG_REF
    require_source_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--package',required=True,type=Path)
    p.add_argument('--expected-ops-source',required=True)
    p.add_argument('--expected-manifest-sha256',required=True)
    p.add_argument('--g15-swap-return',required=True,type=Path)
    p.add_argument('--expected-g15-swap-return-sha256',required=True)
    p.add_argument('--evidence-dir',required=True,type=Path)
    p.add_argument('--config-ref-path',required=True)
    p.add_argument('--expected-config-sha256',required=True)
    p.add_argument('--execute-core-image-cas-once',action='store_true',required=True)
    a = p.parse_args()
    CONFIG_REF = validated_config_ref(a.config_ref_path, a.expected_config_sha256)
    require_bound()
    need(os.geteuid() == 0 and sys.platform == 'linux','ROOT_LINUX_BRAIN_ONLY')
    folder = a.package.absolute(); cut = load_tools(folder); C = cut.C
    c, original_config, sql = maintenance_inputs(C)
    folder, manifest = C.package(folder,a.expected_manifest_sha256)
    need(manifest['source_commit'] == a.expected_ops_source == G15_OPS_P and re.fullmatch('[a-f0-9]{40}',a.expected_ops_source)
         and manifest['files']['source/network_guardian.py'] == SOURCE_PIN and manifest['tools'] == TOOL_PINS,'EXACT_SEPARATELY_QUALIFIED_G15_OPERATIONAL_SOURCE')
    returned_path = a.g15_swap_return.absolute()
    closed_g15_return_path(returned_path, C.STATE)
    C.private_dir(returned_path.parent); returned_raw = C.read(returned_path,32<<20,0o600)
    need(sha(returned_raw) == a.expected_g15_swap_return_sha256 and digest_value(a.expected_g15_swap_return_sha256), 'EXACT_G15_RETURN_BYTES')
    returned = C.loads(returned_raw)
    need(returned_path.name=='RETURN.json'and returned_path.parent.parent==ROOT and returned_path.parent.name.startswith('swap-once-')and not (returned_path.parent/'HOLD.json').exists(),'EXACT_G15_NORMAL_SWAP_RETURN_NOT_OLD_REPAIR')
    swap_claim=C.loads(C.read(ROOT/('SWAP-'+a.expected_manifest_sha256+'-POSSIBLE.json'),32768,0o600))
    need(set(swap_claim)=={'schema','manifest_sha256','old_controller','old_guardian','run','automatic_replay'}and swap_claim['schema']=='g15_once_only_swap_claim_v1'and swap_claim['manifest_sha256']==a.expected_manifest_sha256 and swap_claim['old_controller']==manifest['expected_controller_identity']and swap_claim['old_guardian']==manifest['expected_guardian_identity']and swap_claim['run']==str(returned_path.parent)and swap_claim['automatic_replay']is False,'ACTUAL_G15_ONCE_CLAIM_AND_RETURN')
    run = a.evidence_dir.absolute()
    need(run.parent == ROOT and re.fullmatch('core-image-cas-[A-Za-z0-9_-]{1,96}',run.name),'CLOSED_NEW_CAS_EVIDENCE_DIRECTORY')
    C.private_dir(ROOT); C.private_dir(run,create=True)
    sent = False
    def interrupted(signum,_): raise Hold('SIGNAL_'+str(signum)+'_RECONCILE_NO_REPLAY')
    for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP,signal.SIGALRM): signal.signal(sig,interrupted)
    signal.alarm(120)
    try:
        with operation_lock() as inode:
            need(not global_marker(C).exists(),'NEW_R7_TO_R8_GLOBAL_ONCE_ALREADY_CLAIMED')
            C.once(run/'MAINTENANCE-INPUT.original.json',original_config)
            api = API(cut)
            before = api_read(api,C,run,'DEPLOYMENT-BEFORE',DEP_URI)
            pods = api_read(api,C,run,'PODS-BEFORE',PODS_URI); old_tuple = core_before(before,pods,C)
            need(sha(C.wire(before['spec'])) == c['core_preimage']['spec_sha256'] and sha(C.wire(before['metadata']['annotations'])) == c['core_preimage']['annotations_sha256'],'EXACT_ROOT_FULL_R7_PREIMAGE')
            lineage=C.loads(C.read(returned_path.parent/'BEFORE.json',32<<20,0o600))
            need(lineage['core']==old_tuple and lineage['controller']==manifest['expected_controller_identity']and lineage['guardian']==manifest['expected_guardian_identity']and lineage['protected_refs']==required_protected_refs(),'NEW_G15_BEFORE_IS_CURRENT_CORE7_AND_EXACT_PROTECTED_PREDECESSOR')
            wire = C.wire(build_patch(before,C)); C.once(run/'PATCH.json',wire)
            status, raw, headers = api.request('PATCH',DEP_URI+'?dryRun=All&fieldManager=core-image-cas-once',wire)
            C.once(run/'SERVER-DRYRUN.json',raw); C.once(run/'SERVER-DRYRUN.HTTP.json',C.wire({'status':status,**headers}))
            need(status == 200,'SERVER_DRYRUN_200'); result_shape(before,C.loads(raw),C)
            reader_receipt=deployment_ready_inputs(C,c)
            reader_before=inventory_reader(api,C,run,'BEFORE',reader_receipt)
            database_pre_read96(cut,run,c,sql,'BEFORE')
            backend, protected, ctrl, guard, observed = g15_acceptance(cut,folder,manifest,C.loads(returned_raw),run)
            need(protected == lineage['protected_refs'],'SAME43_ORIGINALS_AND_ONE_OF_THREE_BUDGET')
            fresh = api_read(api,C,run,'DEPLOYMENT-FRESH-PRESEND',DEP_URI)
            fresh_pods = api_read(api,C,run,'PODS-FRESH-PRESEND',PODS_URI)
            need(core_before(fresh,fresh_pods,C) == old_tuple and fresh['metadata']['resourceVersion'] == before['metadata']['resourceVersion']
                 and fresh['spec'] == before['spec'] and fresh['metadata']['annotations'] == before['metadata']['annotations'],'UNCHANGED_FULL_API_PREIMAGE_NO_REBASE')
            backend.files(successor=True)
            need(backend.protected() == protected and cut.physical_identity(C.CTRL,cut.controller_argv(C.NEW_CONFIG)) == ctrl
                 and accepted_guardian(cut,returned) == guard,'SAME_ACCEPTED_G15_LIFETIMES_IMMEDIATELY_BEFORE_PATCH')
            need(inventory_reader(api,C,run,'PRESEND',reader_receipt)==reader_before,'SAME_READER_INCARNATION_AT_PRESEND')
            database_pre_read96(cut,run,c,sql,'PRESEND')
            current_lock = OPLOCK.lstat()
            need((current_lock.st_dev,current_lock.st_ino) == inode and time.monotonic()-observed <= 15,'SAME_MUTEX_AND_FRESH_CURRENT15')
            marker = {'schema':'g15_R7_to_R8_core_image_possible_send_v1','at':now(),'method':'PATCH','uri':DEP_URI,
                'deployment_uid':UID,'generation':GENERATION,'resourceVersion':before['metadata']['resourceVersion'],
                'patch_sha256':sha(wire),'script_sha256':sha(read(__file__)),'manifest_sha256':a.expected_manifest_sha256,
                'G15_return_sha256':a.expected_g15_swap_return_sha256,'evidence_dir':str(run),'automatic_retry':False,
                'effects_may_have_happened_after_this_marker':True}
            sent = True; after = patch_once(api,C,run,wire,marker,observed); result_shape(before,after,C)
            # Image ACK is not runtime readiness or cycle credit. The already
            # normal-finish recovery may begin as soon as Core8 starts.
            result = {'schema':'g15_core_image_cas_return_v1','status':'PATCH_ACKNOWLEDGED_ACCEPTANCE_PENDING',
                'deployment_uid':UID,'generation':after['metadata']['generation'],'resourceVersion':after['metadata']['resourceVersion'],
                'old_pod_uid':OLD_POD,'Core_source':CORE_R,'image':C.IMAGE_PREFIX+C.NEW_DIGEST,'manifest_sha256':a.expected_manifest_sha256,
                'G15_return_sha256':a.expected_g15_swap_return_sha256,'patch_sha256':sha(wire),'automatic_retry':False,
                'new_pod_readiness_proven':False,'post_rollout_G15_and_E2E_acceptance_proven':False,'evidence_dir':str(run)}
            C.once(run/'RETURN.PUBLIC.json',C.wire(result))
        signal.alarm(0); print(C.wire(result).decode(),end='',flush=True)
    except Exception as error:
        signal.alarm(0)
        C.once(run/'HOLD.PUBLIC.json',C.wire({'schema':'g15_core_image_cas_HOLD_v1','error_class':type(error).__name__,
            'guard':str(error)[:160] if isinstance(error,(Hold,C.Hold)) else 'NATIVE_OR_EVIDENCE_FAILURE','possible_send':sent,
            'automatic_retry':False,'actual_api_GET_only_readback_required':sent}))
        raise SystemExit(20) from None




M96 = 'bd28596ba82cc1607ac1a732ec5c401ac5de6bcfba3035d91f1c3a2f0a42d88d'
M96_BODY_SHA = 'd8cba69410381611df09c6d5c8823310be2a989026e51ab46c9885ddfc05d9f3'
M96_FUNCTION = 'retirement_forward_continuation_valid'
ROOT95_SHA = 'b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d'

def raw_json_member(raw, wanted):
    """Return one exact JSON value token, retaining Go order/escapes/whitespace."""
    need(type(raw) is bytes and len(raw) <= 2<<20, 'BOUNDED_ORIGINAL_JSON_WIRE')
    loads(raw)  # Closed duplicate-key/finite JSON validation precedes slicing.
    text = raw.decode('utf-8'); decoder = json.JSONDecoder(); index = 0
    while index < len(text) and text[index] in ' \t\r\n': index += 1
    need(index < len(text) and text[index] == '{', 'ORIGINAL_JSON_OBJECT')
    index += 1
    while True:
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(index < len(text) and text[index] != '}', 'EXACT_REQUIRED_JSON_MEMBER')
        key, index = decoder.raw_decode(text, index)
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(type(key) is str and text[index] == ':', 'JSON_MEMBER_COLON')
        index += 1
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        begin = index; _, index = decoder.raw_decode(text, index)
        if key == wanted: return text[begin:index].encode('utf-8')
        while index < len(text) and text[index] in ' \t\r\n': index += 1
        need(index < len(text) and text[index] == ',', 'REQUIRED_MEMBER_BEFORE_OBJECT_END')
        index += 1

PRE_READ_TARGET = {'root_admission_id':'b8f529ca-43eb-4351-9ac3-a8774f90f562','failed_admission_id':'756a0af2-3ce3-4992-8fe2-116bb8da12cd','retirement_request_id':'87f9530e-0868-4538-98e7-96f241462c49','preregistration_id':'9cdb3d59-3085-4ecb-b384-49f47b2b03b4','destroy_grant_id':'c46345dc-a21f-4d7d-834b-e8e8f38b7643','failed_run_id':'ef121889-8828-4a8b-b821-873a13c15032','pending_read_id':'41de89ba-bec2-479a-87f6-cf5e4a602213','resource_id':'i-03d9ec5b7702b6ee6'}
PRE_READ_SQL = "-- Exact S8 pre-read continuation case; read-only snapshot, no authority or mutation.\n-- All reads/owners for this retirement are retained without success filtering.\nWITH f AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forwards\n WHERE retirement_request_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), r AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forward_reads\n WHERE retirement_request_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), recent_reads AS (\n SELECT * FROM r ORDER BY recorded_at DESC,id DESC,stage DESC LIMIT 6\n), bindings AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_delete_bindings\n WHERE intent_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid\n), last_scope_jobs AS MATERIALIZED (\n SELECT * FROM public.capacity_dispatch_jobs j\n WHERE j.realm='dakasa-production' AND j.environment='production'\n AND j.domain='notify' AND j.dimension='original_notify_aws_vm_members'\n ORDER BY j.created_at DESC,j.id DESC LIMIT 6\n), run_ids AS (\n SELECT DISTINCT CASE WHEN original_record->>'run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'\n   THEN (original_record->>'run_id')::uuid ELSE NULL::uuid END id FROM f\n), runs AS MATERIALIZED (\n SELECT w.* FROM public.workflow_runs w JOIN run_ids x ON w.id=x.id\n), owner_jobs AS (\n SELECT j.* FROM public.capacity_dispatch_jobs j JOIN runs w ON w.id=j.run_id\n), snapshot(v) AS (SELECT jsonb_build_object(\n 'observed_at_pg',clock_timestamp(),\n 'selected_runtime_source','045176d16947555ccbc33a8b51635b08d2d9270e',\n 'target',jsonb_build_object('parent_forward_id','b8f529ca-43eb-4351-9ac3-a8774f90f562',\n   'retirement_request_id','87f9530e-0868-4538-98e7-96f241462c49',\n   'preregistration_id','9cdb3d59-3085-4ecb-b384-49f47b2b03b4','resource_id','i-03d9ec5b7702b6ee6'),\n 'current_intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'current_intent_pgtext',(SELECT i.intent::text FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'active_policies',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'version',p.version,'checksum',p.checksum,'spec',p.spec) ORDER BY p.version),'[]'::jsonb)\n   FROM public.manifests p WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production'\n   AND p.name='notify-aws-elastic-capacity' AND p.active),\n 'forward_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM f x),\n 'retirement_contexts',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb)\n   FROM public.capacity_guest_original_retirement_contexts x WHERE x.intent_id='87f9530e-0868-4538-98e7-96f241462c49'::uuid),\n 'delete_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM bindings x),\n 'destroy_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb)\n   FROM public.capacity_mutation_grants g JOIN bindings b ON b.destroy_grant_id=g.id),\n 'read_counts',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.kind,x.stage),'[]'::jsonb)\n   FROM(SELECT kind,stage,count(*) rows,min(recorded_at) first_at,max(recorded_at) last_at FROM r GROUP BY kind,stage)x),\n 'own_read_count',(SELECT count(*) FROM r WHERE admission_id=(SELECT CASE WHEN i.intent#>>'{retirement_forward,id}' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN (i.intent#>>'{retirement_forward,id}')::uuid ELSE NULL::uuid END FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members')),\n 'all_read_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM r x),\n 'unreturned_prepared',(SELECT COALESCE(jsonb_agg(to_jsonb(p)||jsonb_build_object('wire_hex',encode(p.original_wire,'hex')) ORDER BY p.recorded_at,p.id),'[]'::jsonb)\n   FROM r p WHERE p.stage='prepared' AND NOT EXISTS(SELECT 1 FROM r v WHERE v.id=p.id AND v.stage='returned')),\n 'latest_reads_all_outcomes',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM recent_reads x),\n 'workflow_runs',(SELECT COALESCE(jsonb_agg(to_jsonb(w)||jsonb_build_object('run_wire',row_to_json(w)::text) ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'workflow_run_steps',(SELECT COALESCE(jsonb_agg(jsonb_build_object('run_id',w.id,'status',w.status,'finished_at',w.finished_at,'steps',w.result->'steps') ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'owning_dispatch_jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j)||jsonb_build_object('dispatch_wire',to_jsonb(j)::text) ORDER BY j.created_at,j.id),'[]'::jsonb) FROM owner_jobs j))) SELECT jsonb_build_object('observed_at_pg',clock_timestamp(),'records',(v-'observed_at_pg'),'records_wire',(v-'observed_at_pg')::text,'records_sha256',encode(sha256(convert_to((v-'observed_at_pg')::text,'UTF8')),'hex')) FROM snapshot"

def pre_read_wire(row, field='record_sha256'):
    raw=row['wire_hex'];need(type(raw)is str and re.fullmatch('(?:[0-9a-f]{2})+',raw),'EXACT_RETIREMENT_ORIGINAL_HEX')
    b=bytes.fromhex(raw);need(sha(b)==row[field] and loads(b)==row['original_record'],'EXACT_RETIREMENT_RAW_WIRE_SHA_RECORD');return b

def validate_pre_read96(v, case):
    OLD_SOURCE = HISTORICAL_CORE6_SOURCE
    """Current failed Core6 S8 owner; historical Pending/DELETE never gain authority."""
    closed(v,'observed_at_pg records records_wire records_sha256','CLOSED_S8_PRE_READ_SNAPSHOT')
    closed(case,'retirement_request_id failed_admission_id root_admission_id destroy_grant_id expected_records_sha256 provider_lanes current_runtime_source current_generation current_fencing_token current_failed_run_id current_lease_owner','CLOSED_CURRENT_S8_ROOT_OPERANDS11')
    for k in ('retirement_request_id','root_admission_id','destroy_grant_id'):
        need(case[k]==PRE_READ_TARGET[k],'EXACT_KNOWN_S8_'+k.upper())
    need(case['current_runtime_source']==OLD_SOURCE and type(case['current_generation'])is int and case['current_generation']==31 and type(case['current_fencing_token'])is int and case['current_fencing_token']>=55 and all(full_id(case[k])for k in ('failed_admission_id','current_failed_run_id','current_lease_owner')),'ACTUAL_ROOT_CURRENT_CORE6_EPOCH_NOT_HISTORICAL_R5')
    r=v['records'];need(type(v['records_wire'])is str and loads(v['records_wire'])==r and sha(v['records_wire'].encode())==v['records_sha256']==case['expected_records_sha256'],'WHOLE_PG_SNAPSHOT_WIRE_NOT_REENCODED')
    closed(r,'selected_runtime_source target current_intent current_intent_pgtext active_policies forward_rows retirement_contexts delete_bindings destroy_grants read_counts own_read_count all_read_rows unreturned_prepared latest_reads_all_outcomes workflow_runs workflow_run_steps owning_dispatch_jobs','CLOSED_COMPLETE_S8_RECORD_SET')
    need(r['selected_runtime_source']==case['current_runtime_source'] and r['target']=={'parent_forward_id':PRE_READ_TARGET['root_admission_id'],'retirement_request_id':PRE_READ_TARGET['retirement_request_id'],'preregistration_id':PRE_READ_TARGET['preregistration_id'],'resource_id':PRE_READ_TARGET['resource_id']},'CURRENT_CORE6_AND_IMMUTABLE_S8_TARGET')
    need(type(r['own_read_count'])is int and r['own_read_count']==0 and r['unreturned_prepared']==[] and type(r['all_read_rows'])is list and r['all_read_rows'],'ZERO_ANY_OWN_READ_NOT_LAST_SUCCESS_FILTER')
    rows=r['forward_rows'];need(type(rows)is list and len(rows)>=4 and len({(x['id'],x['stage'])for x in rows})==len(rows),'COMPLETE_UNIQUE_FORWARD_HISTORY_NO_FIXED_OLD_FENCE')
    for row in rows:
        pre_read_wire(row)
        record=row['original_record']
        need(record['id']==row['id'] and record['stage']==row['stage'] and utc(record['recorded_at'])==utc(row['recorded_at']) and record['root_admission_id']==PRE_READ_TARGET['root_admission_id'] and record['retirement_request_id']==PRE_READ_TARGET['retirement_request_id'] and record['preregistration_id']==PRE_READ_TARGET['preregistration_id'],'EVERY_STORED_FORWARD_RAW_ID_STAGE_AND_SCOPE')
    def one(ident,stage):
        found=[x for x in rows if x['id']==ident and x['stage']==stage]
        need(len(found)==1,'ONE_EXACT_FORWARD_STAGE');return found[0]
    anchor=one(PRE_READ_TARGET['root_admission_id'],'admitted');root_off=one(anchor['id'],'off_qualified');a=anchor['original_record']
    def pair(ident):
        admitted=one(ident,'admitted');requested=one(ident,'requested');p,q=admitted['original_record'],requested['original_record'];proof=p['continuation']
        closed(proof,'schema requesting_run_id failed_run_id failed_run_sha256 dispatch_id dispatch_sha256 destroy_grant_sha256 delete_eligibility_sha256 pending_read_id pending_read_sha256','CLOSED_RETAINED_CONTINUATION_PROOF10')
        need(p['mode']==q['mode']=='settled_absence_continuation' and p['stage']=='admitted' and q['stage']=='requested' and p['id']==q['id']==ident and p['root_admission_id']==q['root_admission_id']==anchor['id'] and p['parent_admission_id']==q['parent_admission_id'] and p['parent_admission_sha256']==q['parent_admission_sha256'] and proof==q['continuation'] and proof['schema']in('original_settled_absence_continuation_v1','original_settled_absence_pre_read_continuation_v1') and proof['pending_read_id']==PRE_READ_TARGET['pending_read_id'] and p['destroy_grant_id']==q['destroy_grant_id']==PRE_READ_TARGET['destroy_grant_id'] and p['run_id']==proof['requesting_run_id'] and full_id(p['run_id']) and q['run_id']=='','SAME_AUTHENTIC_REQUEST_AND_ADMITTED_READ_ONLY_OWNER')
        for key in ('root_admission_id','retirement_request_id','preregistration_id','prefix_sha256','original_caller_sha256','evidence','original'):
            need(p[key]==q[key]==a[key],'IMMUTABLE_ROOT_PREFIX_TUPLE_EVIDENCE_'+key.upper())
        need({k:x for k,x in p.items()if k not in ('stage','recorded_at','fence','lease_owner','executor_id','run_id')}=={k:x for k,x in q.items()if k not in ('stage','recorded_at','fence','lease_owner','executor_id','run_id')} and type(p['fence'])is int and type(q['fence'])is int and p['fence']==q['fence']+1 and type(p['generation'])is int and type(q['generation'])is int and type(a['generation'])is int and p['generation']==q['generation']==a['generation']==31 and utc(q['recorded_at'])<=utc(p['recorded_at']),'GENUINE_NEW_FENCE_WITHOUT_OLD_RECORD_REWRITE')
        return admitted,requested,p,q,proof
    parent,requested,p,q,proof=pair(case['failed_admission_id'])
    classic,classic_requested,classic_p,classic_q,classic_proof=pair(PRE_READ_TARGET['failed_admission_id'])
    need(classic_proof['schema']=='original_settled_absence_continuation_v1' and classic_p['run_id']==PRE_READ_TARGET['failed_run_id'] and classic_p['parent_admission_id']==root_off['id'] and classic_p['parent_admission_sha256']==root_off['record_sha256'],'EXACT_REAL_CLASSIC_ANCHOR_NOT_A_TYPED_VALUE_ALIAS')
    classics=[x for x in rows if x['stage']=='requested' and x['original_record'].get('continuation',{}).get('schema')=='original_settled_absence_continuation_v1' and x['original_record']['continuation'].get('pending_read_id')==PRE_READ_TARGET['pending_read_id']]
    need(len(classics)==1 and classics[0]['id']==classic['id'],'ONE_RETAINED_CLASSIC_PENDING_LINEAGE')
    def failed_proof(requested_record, inherited):
        runs=[x for x in r['workflow_runs']if x['id']==inherited['failed_run_id']];need(len(runs)==1,'ONE_REAL_PREVIOUS_FAILED_RUN');run=runs[0]
        jobs=[x for x in r['owning_dispatch_jobs']if x['id']==inherited['dispatch_id']and x['run_id']==run['id']];need(len(jobs)==1,'ONE_REAL_PREVIOUS_FAILED_ACK');job=jobs[0]
        raw=base64.b64decode(requested_record['failed_run'],validate=True)
        need(loads(run['run_wire'])=={k:x for k,x in run.items()if k!='run_wire'} and loads(job['dispatch_wire'])=={k:x for k,x in job.items()if k!='dispatch_wire'} and sha(raw)==inherited['failed_run_sha256']==sha(run['run_wire'].encode()) and loads(raw)==loads(run['run_wire']) and sha(job['dispatch_wire'].encode())==inherited['dispatch_sha256'] and run['status']==job['return_status']=='failed' and job['state']=='returned' and utc(run['finished_at'])==utc(job['returned_at'])<=utc(job['finalization_ack_at'])<=utc(requested_record['recorded_at']),'EXACT_PRIOR_FAILED_WORKFLOW_ACK_WIRE_NO_UNKNOWN')
        return run
    cursor=parent;seen=set()
    while cursor['id']!=classic['id']:
        need(cursor['id']not in seen,'ACYCLIC_TYPED_PRE_READ_LINEAGE');seen.add(cursor['id'])
        current_row,current_requested,cp,cq,continuation=pair(cursor['id'])
        need(continuation['schema']=='original_settled_absence_pre_read_continuation_v1','TYPED96_CURRENT_CONTINUATION_NOT_CLASSIC_ALIAS')
        previous=one(cp['parent_admission_id'],'admitted');previous_record=previous['original_record']
        need(previous['record_sha256']==cp['parent_admission_sha256'] and previous_record['mode']=='settled_absence_continuation' and continuation['failed_run_id']==previous_record['run_id'] and cp['fence']>previous_record['fence'] and utc(previous['recorded_at'])<utc(current_requested['recorded_at']) and all(continuation[k]==classic_proof[k]==previous_record['continuation'][k]for k in ('pending_read_id','pending_read_sha256','destroy_grant_sha256','delete_eligibility_sha256')) and not any(x['admission_id']==previous['id']for x in r['all_read_rows']),'SAME_IMMUTABLE_PARENT_PENDING_SDK_AND_ZERO_PREVIOUS_OWN_READS')
        failed_proof(cq,continuation);cursor=previous
    failed_proof(classic_q,classic_proof)
    current=r['current_intent']['intent'];need(loads(r['current_intent_pgtext'])==current and current['retirement_forward']['id']==parent['id'] and current['retirement_forward']['stage']=='admitted' and current['retirement_forward']['mode']=='settled_absence_continuation' and current['generation']==p['generation']==case['current_generation'] and current['fencing_token']==p['fence']==case['current_fencing_token'] and current['lease_owner']==p['lease_owner']==case['current_lease_owner'] and current['lease_executor_id']==p['executor_id'] and p['run_id']==case['current_failed_run_id'] and utc(current['lease_expires_at'])<=utc(v['observed_at_pg']) and current['phase']=='drained','EXACT_EXPIRED_CURRENT_FENCED_OWNER_NO_LEASE_EXTENSION')
    need(len(r['active_policies'])==1 and r['active_policies'][0]['id']==current['policy_id'] and r['active_policies'][0]['checksum']==current['policy_checksum'],'CURRENT_SINGLE_POLICY_NO_OLD_TRIAL_ALIAS')
    for row in r['all_read_rows']:pre_read_wire(row)
    need(not any(x['admission_id']==parent['id']for x in r['all_read_rows']),'NO_PREPARED_OR_RETURNED_OF_ANY_KIND_FOR_CURRENT_FAILED_OWNER')
    returned=[x for x in r['all_read_rows']if x['stage']=='returned'];need(returned,'ACTUAL_HISTORICAL_PENDING_REQUIRED');last=max(returned,key=lambda x:(utc(x['recorded_at']),x['id']))
    need(last['id']==proof['pending_read_id']==classic_proof['pending_read_id'] and last['record_sha256']==proof['pending_read_sha256']==classic_proof['pending_read_sha256'] and last['admission_id']==anchor['id'] and last['kind']=='absence','LATEST_ALL_OUTCOMES_IS_INHERITED_PENDING_NOT_IGNORED_RAW')
    prepared=[x for x in r['all_read_rows']if x['id']==last['id']and x['stage']=='prepared'];need(len(prepared)==1,'ONE_ACTUAL_PENDING_CHALLENGE');prepared=prepared[0];ret=last['original_record'];rd=ret['read']
    need(rd==prepared['original_record'] and rd['admission_id']==anchor['id'] and rd['admission_sha256']==anchor['record_sha256'] and rd['destroy_grant_id']==p['destroy_grant_id'] and rd['retirement_request_id']==p['retirement_request_id'] and rd['prefix_sha256']==p['prefix_sha256'] and rd['original_caller_sha256']==p['original_caller_sha256'] and rd['tuple']==p['original']['Request']['intent']['tuple'] and ret['status']=='observed' and ret['call_failed']is False and ret['original_context_failed']is False and 'plan'not in ret,'SAME_TIMELY_OBSERVED_ANCESTOR_PENDING_NOT_CURRENT_ABSENCE')
    need(utc(rd['issued_at_core'])<=utc(ret['started_at_core'])<=utc(ret['original_returned_at_core'])<utc(rd['original_deadline_core']) and (utc(rd['original_deadline_core'])-utc(rd['issued_at_core'])).total_seconds()<=5 and utc(anchor['recorded_at'])<=utc(last['recorded_at'])<utc(classic['recorded_at'])<=utc(parent['recorded_at']),'HISTORICAL_ORIGINAL_FIVE_SECOND_READ_CLOCK_NOT_RETIMED')
    need(len(r['destroy_grants'])==len(r['delete_bindings'])==1,'ONE_ORIGINAL_PAID_DESTROY_BINDING');g=r['destroy_grants'][0];b=r['delete_bindings'][0];record=g['grant_record'];grant=record['grant'];settlement=record['settlement']
    need(g['id']==grant['grant_id']==b['destroy_grant_id']==p['destroy_grant_id'] and g['state']==grant['state']=='settled' and all(g[k]is None for k in ('original_disposition_id','failed_original_disposition_id','native_denied_disposition_id','enrolled_failed_disposition_id','failed_unwitnessed_expansion_cleanup_id')) and sha(g['grant_pgtext'].encode())==proof['destroy_grant_sha256'] and loads(g['grant_pgtext'])==record and grant.get('compensation_of','')=='' and settlement['outcome']=='accepted' and settlement['transport_completed']is True and settlement['auxiliary_inventory_complete']is True and len(settlement['auxiliary_resources'])==2,'SAME_SETTLED_PAID_AUX2_NO_NEW_DELETE')
    raw=bytes.fromhex(b['wire_hex']);need(sha(raw)==b['eligibility_sha256']==proof['delete_eligibility_sha256'] and loads(raw)==b['original_eligibility_record'] and b['intent_id']==p['retirement_request_id'],'WHOLE_ORIGINAL_DELETE_ELIGIBILITY_WIRE')
    receipt=ret['original_destroy_receipt'];need(receipt['grant']==grant and receipt['attempt_id']==record['attempt_id'] and all(receipt[k]==settlement[k]for k in ('outcome','transport_completed','action_id','resource_id','resource_created_at','auxiliary_resources','auxiliary_inventory_complete')) and receipt['resource_id']==grant['expected_resource_id']==PRE_READ_TARGET['resource_id'] and receipt['resource_created_at']==grant['expected_resource_created_at'],'SAME_ORIGINAL_RECEIPT_GRANT_ATTEMPT_ACTION_BIRTH')
    sdk=settlement.get('original_provider_destroy_return');need(type(sdk)is dict and sdk['schema']=='aws_original_terminate_instances_return_v1'and sdk['provider']=='aws'and sdk['adapter_source_commit']=='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce'and type(sdk['response_status'])is int and sdk['response_status']==200 and sdk['grant_id']==g['id'] and sdk['attempt_id']==record['attempt_id'] and sdk['action_id']==settlement['action_id'] and sdk['request_sha256']==settlement['request_sha256']==grant['request_sha256'] and sdk['resource_id']==receipt['resource_id'] and sdk['resource_created_at']==receipt['resource_created_at'] and sdk.get('next_action_ids',[])==[] and utc(sdk['called_at'])<=utc(sdk['returned_at'])<utc(sdk['context_deadline'])<=utc(grant['expires_at']),'ACTUAL_IMMUTABLE_C34_TERMINATE200_WITH_ORIGINAL_CLOCK')
    observer=loads(base64.b64decode(ret['original_observer_return'],validate=True));closed(observer,'schema observer_source_commit original_adapter_source_commit read_id read_sha256 original_receipt_sha256 observation','CLOSED_GENUINE_H7_WRAPPER')
    need(observer['schema']=='original_settled_retirement_absence_read_return_v1' and observer['observer_source_commit']==ret['observer_source_commit']=='d8cbbf48873d24439216f98c30afe2669a525b54' and observer['original_adapter_source_commit']==rd['adapter_source_commit']=='c34e330d8b266bb88e29ae7cf7b01df6f9fd96ce' and observer['read_id']==rd['read_id']==prepared['id'] and observer['read_sha256']==prepared['record_sha256'] and observer['original_receipt_sha256']==sha(raw_json_member(bytes.fromhex(last['wire_hex']),'original_destroy_receipt')) and observer['observation']==ret['observation'],'EXACT_H7_ORIGINAL_CHALLENGE_AND_GO_RECEIPT_TOKEN_SHA')
    o=ret['observation'];need(o['destroy_grant_id']==g['id']and o['destroy_grant_state']=='settled'and o['id']==receipt['resource_id']and o['created_at']==receipt['resource_created_at']and o['original_outcome']=='accepted'and o['original_transport_completed']is True and o['auxiliary_inventory_complete']is True and o['billable_resources_absent']is False and o['retirement_complete']is False and not o.get('writer_quiescence_evidence',False)and not o.get('provider_fencing_evidence',False)and not o.get('invoice_reconciled',False)and 'billing_exposure'not in o and o.get('compensation_of','')=='','GENUINE_PENDING_NOT_COMPLETION_OR_AUTHORITY')
    lifecycle=o['aws_retirement_lifecycle'];state=lifecycle['ec2_state'];absent=state in ('terminated','not_found');need(lifecycle['schema']=='aws_original_terminate_and_native_absence_v1'and lifecycle['request_id']==receipt['action_id']and state in ('pending','running','stopping','stopped','shutting-down','terminated','not_found')and o['server_absent']is absent and o['server_absence_complete']is absent and (o.get('server_status','')==''if absent else o['server_status']==state)and o['next_actions']==[]and o.get('delete_action',{})in ({},{'known':False,'observed':False})and len(o['auxiliary_resources'])==2 and 1<=len(o['hold_reasons'])<=3 and len(set(o['hold_reasons']))==len(o['hold_reasons']),'EXACT_AWS_PENDING_LIFECYCLE_FULL_AUX_INVENTORY')
    holds=set(o['hold_reasons']);need(holds<=set(('instance_not_terminated','aws_ebs_volume_still_present','aws_network_interface_still_present')) and ('instance_not_terminated'in holds)!=absent,'NO_FAVORABLE_PENDING_HOLD_SUFFIX')
    for aux,paid in zip(o['auxiliary_resources'],receipt['auxiliary_resources']):need(aux['kind']==paid['kind']and aux['id']==paid['id']and type(aux['absent'])is bool and ((aux['kind']+'_still_present')in holds)!=aux['absent'],'EXACT_PAID_AUX_ID_AND_PENDING_STATUS')
    runs=r['workflow_runs'];jobs=r['owning_dispatch_jobs'];own=[w for w in runs if w['id']==p['run_id']];need(len(own)==1,'ONE_CURRENT_FAILED_RUN');w=own[0];j=[j for j in jobs if j['run_id']==w['id']];need(len(j)==1,'ONE_CURRENT_FAILED_DISPATCH');j=j[0]
    need(w['status']==j['return_status']=='failed'and j['state']=='returned'and utc(w['finished_at'])==utc(j['returned_at'])<=utc(j['finalization_ack_at'])<=utc(v['observed_at_pg'])and loads(w['run_wire'])=={k:x for k,x in w.items()if k!='run_wire'}and loads(j['dispatch_wire'])=={k:x for k,x in j.items()if k!='dispatch_wire'},'GENUINE_FAILED_SOURCE_RUN_ONE_FINAL_ACK_NO_UNKNOWN')
    env=loads(j['envelope']);need(env['workflow']['id']==p['original']['Request']['intent']['workflow_id']and w['metadata']['capacity_dispatch_job_id']==j['id']and w['metadata']['triggered_by']=='workflow_scheduler','ACTUAL_SCHEDULER_ENVELOPE_AND_OWNING_JOB')
    steps=w['result']['steps'];need(w['result']['status']=='failed'and len(steps)==7 and len({x['id']for x in steps})==7,'WHOLE_CLOSED_FAILED_SEVEN_STEP_RESULT');steps={x['id']:x for x in steps}
    need(steps['plan-original-guest']['status']=='succeeded'and steps['plan-original-guest']['metadata']['generation']==p['generation']and steps['plan-original-guest']['metadata']['fencing_token']==p['fence']and steps['plan-original-guest']['metadata']['lease_owner']==p['lease_owner']and steps['retire-original-guest']['status']=='succeeded'and steps['retire-original-guest']['metadata']['retirement_forward_id']==p['id']and steps['retire-original-guest']['metadata']['request_id']==p['retirement_request_id']and steps['finish-original-retirement']['status']=='failed'and all(steps[k]['status']=='skipped'for k in ('provision-original-notify','complete-original-provision','refresh-original-membership','complete-original-retirement')),'FAILED_PRE_READ_OWNER_FULL_ORDINARY_WORKFLOW_NO_REPLAY')
    historical=[x for x in runs if x['id']==classic_proof['failed_run_id']];need(len(historical)==1 and historical[0]['id']==a['run_id'],'ONE_ORIGINAL_ANCESTOR_FAILED_RUN');historical=historical[0]
    oldjob=[x for x in jobs if x['id']==classic_proof['dispatch_id']and x['run_id']==historical['id']];need(len(oldjob)==1,'ONE_ORIGINAL_ANCESTOR_ACK');oldjob=oldjob[0]
    failed_raw=base64.b64decode(classic_q['failed_run'],validate=True)
    need(sha(failed_raw)==classic_proof['failed_run_sha256']==sha(historical['run_wire'].encode()) and loads(failed_raw)==loads(historical['run_wire']) and sha(oldjob['dispatch_wire'].encode())==classic_proof['dispatch_sha256'] and historical['status']==oldjob['return_status']=='failed'and oldjob['state']=='returned'and utc(historical['finished_at'])==utc(oldjob['returned_at'])<=utc(oldjob['finalization_ack_at'])<=utc(classic_q['recorded_at'])and utc(ret['original_returned_at_core'])<=utc(oldjob['returned_at']),'HISTORICAL_PENDING_FAILED_RUN_AND_ACK_RAW_BYTES_NOT_NEW_AUTHORITY')
    eligibility=b['original_eligibility_record'];need(eligibility['schema']=='original_guest_partial_poweroff_delete_eligibility_v1'and eligibility['admission_id']==anchor['id']and eligibility['admission_sha256']==anchor['record_sha256']and g['generation']==record['generation']==a['generation']and record['fencing_token']==a['fence']and record['lease_owner']==a['lease_owner']and record['executor_id']==a['executor_id'],'ORIGINAL_PAID_DELETE_BOUND_TO_ACTUAL_ANCESTOR_EPOCH')
    return True

# INERT PURE SOURCE FRAGMENT. Closure: copy, need, sha; parent Source gate/refs remain unbound.
# expected96_check_definition is a SOURCE/data binding of the exact pg_get_constraintdef
# rendering from the complete pinned PG16 CI artifact; no result is invented here.
def catalog96_delta(prior95, actual96, source96_body, expected96_check_definition):
    need(type(expected96_check_definition)is str and expected96_check_definition and type(source96_body)is str,'BOUND_EXACT_M96_SOURCE_AND_CONSTRAINT_DEFINITION')
    need(set(prior95)==set(actual96)=={'catalog90','catalog91','columns90_91','functions93','index92_definition','index92_valid','schema94'},'SAME_COMPLETE_SEVEN_KEY_CATALOG_ABI')
    need(sha(source96_body.encode())=='d8cba69410381611df09c6d5c8823310be2a989026e51ab46c9885ddfc05d9f3','EXACT_PINNED_M96_UP_PROSRC')
    expected=copy.deepcopy(prior95)
    old=[x for x in expected['functions93']if x['name']=='retirement_forward_continuation_valid']; new=[x for x in actual96['functions93']if x['name']=='retirement_forward_continuation_valid']
    need(len(old)==len(new)==1 and all(old[0][k]==new[0][k]for k in ('name','arguments','result','language','volatility','config')),'ONE96_FUNCTION_HEADER_UNCHANGED')
    need(old[0]['body'] and old[0]['definition'].count(old[0]['body'])==1 and new[0]['body']==source96_body,'WHOLE96_SOURCE_PROSRC')
    old[0]['definition']=old[0]['definition'].replace(old[0]['body'],source96_body,1);old[0]['body']=source96_body
    before=[x for x in expected['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation93'];after=[x for x in actual96['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation96']
    need(len(before)==len(after)==1 and before[0]['validated']is True and after[0]['validated']is True and set(before[0])==set(after[0]) and {k:v for k,v in before[0].items()if k not in ('name','definition')}=={k:v for k,v in after[0].items()if k not in ('name','definition')} and after[0]['definition']==expected96_check_definition,'ONLY_EXACT96_PROOF_CONSTRAINT_REPLACEMENT')
    before[0]['name']='retirement_forward_continuation96';before[0]['definition']=expected96_check_definition
    need(expected==actual96,'ALL_OTHER_TABLE_COLUMN_CONSTRAINT_INDEX_TRIGGER_FUNCTION_BYTES_EXACT95')
    return actual96

def constraint96_definition(prior95, artifact):
    rows=[x for x in prior95['catalog90']['constraints']if x['table']=='capacity_guest_retirement_forwards'and x['name']=='retirement_forward_continuation93']
    need(len(rows)==1 and rows[0]['validated']is True,'ONE_ORIGINAL93_PROOF_CHECK')
    closed(artifact,'schema migration93_sha256 migration96_sha256 before_definition after scope Native_or_Job_qualification','CLOSED_ACTUAL_PG16_CI_CHECK_DEPARSE')
    actual=artifact['after'];closed(actual,'server_version server_version_num database definition validated old_constraint_rows','CLOSED_ACTUAL_PG16_CHECK96')
    need(artifact['schema']=='declared_M96_PG16_exact_Source_CHECK_deparse_v1'and artifact['migration93_sha256']=='cc2b2843d14d4183ea68d25dbb9b9b58d1a353044e6ebf46ece6b93778e937e9'and artifact['migration96_sha256']==M96 and artifact['before_definition']==rows[0]['definition']and artifact['scope']=='disposable minimum table CHECK only'and artifact['Native_or_Job_qualification']is False,'EXACT_SOURCE93_96_AND_PRIOR95_CHECK_NOT_NATIVE_QUALIFICATION')
    need(type(actual['server_version_num'])is int and 160000<=actual['server_version_num']<170000 and type(actual['server_version'])is str and actual['server_version']and type(actual['database'])is str and re.fullmatch('goose96_deparse_[0-9a-f]{32}',actual['database'])and actual['validated']is True and type(actual['old_constraint_rows'])is int and actual['old_constraint_rows']==0 and type(actual['definition'])is str and actual['definition'].startswith('CHECK (')and actual['definition']!=rows[0]['definition'],'ACTUAL_PG16_CI_CHECK96_DEPARSE_DATA_NOT_GUESSED')
    return actual['definition']

# INERT SOURCE FRAGMENT. Parent operator SOURCE_BOUND remains False until actual bindings.
# Closure: closed, need, source, digest_value, full_id, sha, loads; existing read_ref only.
def root96_overlay(receipt_raw, prior95_raw, pins, read_ref):
    need(sha(prior95_raw)=='b80ec307962a67b8a28722c8fbf88add02c25de08847253fbae7838de1c0153d','IMMUTABLE_ROOT95_WHOLE_ORIGINAL')
    previous=loads(prior95_raw); r=loads(receipt_raw)
    closed(r,'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration96_sha256 complete_history_sha256 prior95_history_sha256 catalog96_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs','ROOT96_CLOSED21')
    need(previous['schema']=='root_goose95_failed_expansion_read_continuation_acceptance_v1' and previous['reviewed_by_root']is True and previous['schema_after']==95,'ROOT95_REMAINS_HISTORICAL')
    need(r['schema']=='root_goose96_guest_retirement_pre_read_continuation_acceptance_v1' and r['reviewed_by_root']is True and r['schema_before']==95 and r['schema_after']==96,'ROOT96_DISTINCT_ACTUAL_OVERLAY')
    need(r['current_core_source']==previous['business_source']=='33a846d31a5b123b2c1141192671bc830bf6d9c8' and r['current_ops_source']==pins['current_ops_source'] and source(r['current_ops_source']) and r['business_source']==pins['business_source'] and source(r['business_source']) and r['amd64_D']==pins['amd64_D'] and digest_value(r['amd64_D']),'ROOT96_ACTUAL_CURRENT_G15_AND_R6_IMAGE_NOT_OLD95')
    need(r['migration96_sha256']=='bd28596ba82cc1607ac1a732ec5c401ac5de6bcfba3035d91f1c3a2f0a42d88d' and r['complete_history_sha256']==pins['complete_history_sha256'] and r['prior95_history_sha256']==previous['complete_history_sha256']==pins['prior95_history_sha256'] and r['catalog96_sha256']==pins['catalog96_sha256'] and r['index92_definition_sha256']==previous['index92_definition_sha256']==pins['index92_definition_sha256'] and r['catalog90_91_sha256']==pins['catalog90_91_sha256'],'ACTUAL96_RAW_HISTORY_AND_EXACT_CATALOG_PINS')
    need(full_id(r['job_uid']) and full_id(r['pod_uid']) and type(r['exit_code'])is int and r['exit_code']==0 and r['single_job_create']is True and type(r['provider_guest_core_mutations'])is int and r['provider_guest_core_mutations']==0 and r['old_records_and_sdk_preserved']is True,'ROOT96_SINGLE_JOB_NO_PROVIDER_OR_CORE_MUTATION')
    need(type(r['original_refs'])is dict and set(r['original_refs'])=={'migration_result','before_catalog','after_catalog','source_ci','qualified_image'},'ROOT96_EXACT_FIVE_ORIGINAL_ROLES')
    for ref in r['original_refs'].values():need(len(read_ref(ref))>1,'ROOT96_COMPLETE_PINNED_ORIGINAL')
    return r



# Separate image-only state class: old pre-read96 predicates remain unchanged.
LIVE_SCHEMA = 'g15_terminal_s8_current_live_image_maintenance_v1'
LIVE_CASE_SCHEMA = 'terminal_s8_and_current_live_failed_owner_v1'
LIVE_TARGET = {'retirement_request_id': 'f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0', 'admission_id': '998b93f5-2417-4524-8e05-731d63a302fc', 'preregistration_id': '5b76f9f4-79ee-49c5-8c5b-adb3c4be90e2', 'generation': 34, 'fence': 70, 'lease_owner': 'eaaec656-e5f5-4adc-b0b1-ff83f677d73d', 'executor_id': '77933b83-30df-4890-9fd8-6c3bbcc72c34', 'run_id': '05b185b8-d2be-4b01-a050-ac6eb7dc4508', 'dispatch_id': 'ae1a8697-e064-4ee7-a503-aa4886db59bb', 'slot': 5, 'resource_id': 'i-01d34a436a473d281', 'resource_created_at': '2026-11-10T15:29:12Z', 'destroy_grant_id': '5633594c-dc3a-4276-a314-fed77192dc0a'}
S8_TERMINAL_REF = {'path': '/var/lib/dakasa-core-rollout/s8-pre-read96-52a992b8-52eb-4108-a057-faf31eee7304/S8-STDOUT.original', 'sha256': '88a4e9b7cfc1a9c01c9c03ce060559e2176c9373279cab806abf021a08885ff9'}
S8_TERMINAL_TARGET = {'admission_id': '1528555b-fa58-46f3-910d-7c0684e82df6', 'record_sha256': '8ac7f6874518328bdc12d3d16ed657ca1f4e8ab718ecb479cb4caf6bb72e4993', 'native_absence_sha256': '4f20eb22d8a476cce41967a81c3919aebbbabfb9b2a0d8ab6887e2d6071cc8b8', 'terminal_intent_sha256': '487de10928b86b4fd73f656df2a1a88a16371eb235646d2cb7404225fe509523', 'run_id': '874d35c4-59e4-456b-bacc-a654a577ef45', 'read_id': 'f3c6eee8-02e0-4f06-bf76-4b7377d7cf21', 'generation': 31, 'fence': 65}
CURRENT_LIVE_SQL = "-- Exact S8 pre-read continuation case; read-only snapshot, no authority or mutation.\n-- All reads/owners for this retirement are retained without success filtering.\nWITH f AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forwards\n WHERE retirement_request_id='f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0'::uuid\n), r AS MATERIALIZED (\n SELECT * FROM public.capacity_guest_retirement_forward_reads\n WHERE retirement_request_id='f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0'::uuid\n), recent_reads AS (\n SELECT * FROM r ORDER BY recorded_at DESC,id DESC,stage DESC LIMIT 6\n), bindings AS MATERIALIZED (\n SELECT * FROM public.capacity_vm_retirement_delete_bindings\n WHERE intent_id='f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0'::uuid\n), last_scope_jobs AS MATERIALIZED (\n SELECT * FROM public.capacity_dispatch_jobs j\n WHERE j.realm='dakasa-production' AND j.environment='production'\n AND j.domain='notify' AND j.dimension='original_notify_aws_vm_members'\n ORDER BY j.created_at DESC,j.id DESC LIMIT 6\n), run_ids AS (\n SELECT DISTINCT CASE WHEN original_record->>'run_id' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'\n   THEN (original_record->>'run_id')::uuid ELSE NULL::uuid END id FROM f\n), runs AS MATERIALIZED (\n SELECT w.* FROM public.workflow_runs w JOIN run_ids x ON w.id=x.id\n), owner_jobs AS (\n SELECT j.* FROM public.capacity_dispatch_jobs j JOIN runs w ON w.id=j.run_id\n), snapshot(v) AS (SELECT jsonb_build_object(\n 'observed_at_pg',clock_timestamp(),\n 'selected_runtime_source','045176d16947555ccbc33a8b51635b08d2d9270e',\n 'target',jsonb_build_object('parent_forward_id','998b93f5-2417-4524-8e05-731d63a302fc',\n   'retirement_request_id','f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0',\n   'preregistration_id','5b76f9f4-79ee-49c5-8c5b-adb3c4be90e2','resource_id','i-01d34a436a473d281'),\n 'current_intent',(SELECT to_jsonb(i) FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'current_intent_pgtext',(SELECT i.intent::text FROM public.capacity_intents i WHERE i.namespace='dakasa-production'\n   AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members'),\n 'active_policies',(SELECT COALESCE(jsonb_agg(jsonb_build_object('id',p.id,'version',p.version,'checksum',p.checksum,'spec',p.spec) ORDER BY p.version),'[]'::jsonb)\n   FROM public.manifests p WHERE p.kind='capacity_policy' AND p.namespace='dakasa-production'\n   AND p.name='notify-aws-elastic-capacity' AND p.active),\n 'forward_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM f x),\n 'create_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb) FROM public.capacity_mutation_grants g WHERE g.id::text IN (SELECT x.original_record#>>'{original,Preregistration,original_create_grant_id}' FROM f x WHERE x.id='998b93f5-2417-4524-8e05-731d63a302fc'::uuid AND x.stage='admitted')),\n 'retirement_contexts',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb)\n   FROM public.capacity_guest_original_retirement_contexts x WHERE x.intent_id='f6b2cc3e-7405-49ed-b46a-b7e3351a8ba0'::uuid),\n 'delete_bindings',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex'))),'[]'::jsonb) FROM bindings x),\n 'destroy_grants',(SELECT COALESCE(jsonb_agg(to_jsonb(g)||jsonb_build_object('grant_pgtext',g.grant_record::text) ORDER BY g.id),'[]'::jsonb)\n   FROM public.capacity_mutation_grants g JOIN bindings b ON b.destroy_grant_id=g.id),\n 'read_counts',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY x.kind,x.stage),'[]'::jsonb)\n   FROM(SELECT kind,stage,count(*) rows,min(recorded_at) first_at,max(recorded_at) last_at FROM r GROUP BY kind,stage)x),\n 'own_read_count',(SELECT count(*) FROM r WHERE admission_id=(SELECT CASE WHEN i.intent#>>'{retirement_forward,id}' ~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$' THEN (i.intent#>>'{retirement_forward,id}')::uuid ELSE NULL::uuid END FROM public.capacity_intents i WHERE i.namespace='dakasa-production' AND i.environment='production' AND i.domain='notify' AND i.dimension='original_notify_aws_vm_members')),\n 'all_read_rows',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM r x),\n 'unreturned_prepared',(SELECT COALESCE(jsonb_agg(to_jsonb(p)||jsonb_build_object('wire_hex',encode(p.original_wire,'hex')) ORDER BY p.recorded_at,p.id),'[]'::jsonb)\n   FROM r p WHERE p.stage='prepared' AND NOT EXISTS(SELECT 1 FROM r v WHERE v.id=p.id AND v.stage='returned')),\n 'latest_reads_all_outcomes',(SELECT COALESCE(jsonb_agg(to_jsonb(x)||jsonb_build_object('wire_hex',encode(x.original_wire,'hex')) ORDER BY x.recorded_at,x.id,x.stage),'[]'::jsonb) FROM recent_reads x),\n 'workflow_runs',(SELECT COALESCE(jsonb_agg(to_jsonb(w)||jsonb_build_object('run_wire',row_to_json(w)::text) ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'workflow_run_steps',(SELECT COALESCE(jsonb_agg(jsonb_build_object('run_id',w.id,'status',w.status,'finished_at',w.finished_at,'steps',w.result->'steps') ORDER BY w.id),'[]'::jsonb) FROM runs w),\n 'owning_dispatch_jobs',(SELECT COALESCE(jsonb_agg(to_jsonb(j)||jsonb_build_object('dispatch_wire',to_jsonb(j)::text) ORDER BY j.created_at,j.id),'[]'::jsonb) FROM owner_jobs j))) SELECT jsonb_build_object('observed_at_pg',clock_timestamp(),'records',(v-'observed_at_pg'),'records_wire',(v-'observed_at_pg')::text,'records_sha256',encode(sha256(convert_to((v-'observed_at_pg')::text,'UTF8')),'hex')) FROM snapshot"


def forward_marker_data(p):
    return {k:p[k] for k in ('schema','id','retirement_request_id','preregistration_id','mode','stage','original_intent_sha256','original_generation','original_fence')}

def image_snapshot(value, expected):
    closed(value,'observed_at_pg records records_wire records_sha256','CLOSED_IMAGE_ONLY_CURRENT_SNAPSHOT')
    need(type(value['records_wire'])is str and loads(value['records_wire'])==value['records'] and sha(value['records_wire'].encode())==value['records_sha256']==expected,'WHOLE_IMAGE_ONLY_PG_WIRE_NOT_REENCODED')
    return value['records']

def one_frame(rows, ident, stage):
    found=[x for x in rows if x['id']==ident and x['stage']==stage]
    need(len(found)==1,'ONE_IMAGE_ONLY_IMMUTABLE_FORWARD_STAGE')
    row=found[0];pre_read_wire(row);p=row['original_record']
    need(p['id']==row['id'] and p['stage']==row['stage'] and utc(p['recorded_at'])==utc(row['recorded_at']),'EXACT_IMAGE_ONLY_FORWARD_RAW_COLUMNS')
    return row

def completed_owner(records, run_id, admission, succeeded=False):
    runs=[w for w in records['workflow_runs']if w['id']==run_id]
    jobs=[j for j in records['owning_dispatch_jobs']if j['run_id']==run_id]
    need(len(runs)==len(jobs)==1,'ONE_IMAGE_ONLY_ORIGINAL_OWNER_AND_ACK')
    w,j=runs[0],jobs[0];status='succeeded'if succeeded else'failed'
    need(loads(w['run_wire'])=={k:v for k,v in w.items()if k!='run_wire'} and loads(j['dispatch_wire'])=={k:v for k,v in j.items()if k!='dispatch_wire'} and w['status']==w['result']['status']==j['return_status']==status and j['state']=='returned' and utc(w['finished_at'])==utc(j['returned_at'])<=utc(j['finalization_ack_at']),'EXACT_IMAGE_ONLY_CLOSED_OWNER_RAW_AND_FINAL_ACK')
    need(w['metadata']['capacity_dispatch_job_id']==j['id'] and w['metadata']['triggered_by']=='workflow_scheduler' and loads(j['envelope'])['workflow']['id']==admission['original']['Request']['intent']['workflow_id'],'EXACT_IMAGE_ONLY_SCHEDULED_WORKFLOW_ENVELOPE')
    steps=w['result']['steps'];need(len(steps)==7 and len({x['id']for x in steps})==7,'EXACT_IMAGE_ONLY_SEVEN_STEPS')
    steps={x['id']:x for x in steps};plan=steps['plan-original-guest']
    need(plan['status']=='succeeded' and all(plan['metadata'][k]==admission[a]for k,a in (('generation','generation'),('fencing_token','fence'),('lease_owner','lease_owner'))) and steps['retire-original-guest']['status']=='succeeded' and steps['retire-original-guest']['metadata']['retirement_forward_id']==admission['id'] and steps['retire-original-guest']['metadata']['request_id']==admission['retirement_request_id'],'EXACT_IMAGE_ONLY_ORIGINAL_PLAN_AND_RETIRE')
    need(all(steps[k]['status']=='skipped'for k in ('provision-original-notify','complete-original-provision','refresh-original-membership')) and steps['finish-original-retirement']['status']==status and steps['complete-original-retirement']['status']==('succeeded'if succeeded else'skipped'),'NO_INVENTED_IMAGE_ONLY_BUSINESS_SUCCESS')
    return w,j

def paid_original_sdk(stored, tuple_, destroy):
    record=stored['grant_record'];g=record['grant'];s=record['settlement'];b=record['binding']
    key='original_provider_destroy_return'if destroy else'original_provider_create_return';sdk=s.get(key)
    need(loads(stored['grant_pgtext'])==record and stored['id']==g['grant_id'] and stored['state']==g['state'] and g['state']in(('settled','confirmed')if destroy else('confirmed',)) and g.get('compensation_of','')=='' and s['outcome']=='accepted' and s['transport_completed']is True and g['capability']==b['destroy_capability'if destroy else'ensure_capability'] and all(g[k]==b[a]for k,a in (('binding_name','name'),('integration_instance_id','integration_instance_id'),('scope_checksum','scope_checksum'),('profile_name','profile_name'))),'EXACT_IMAGE_ONLY_KNOWN_ORIGINAL_GRANT_BINDING')
    need(type(sdk)is dict and sdk['schema']==('aws_original_terminate_instances_return_v1'if destroy else'aws_original_run_instances_return_v1') and sdk['provider']=='aws' and sdk['adapter_source_commit']==b['original_provider_source_commit']==A3_CREATOR and type(sdk['response_status'])is int and sdk['response_status']==200 and digest_value(sdk['response_body_sha256']) and type(sdk['response_bytes'])is int and 2<=sdk['response_bytes']<=2<<20 and sdk['grant_id']==g['grant_id'] and sdk['attempt_id']==record['attempt_id'] and sdk['request_sha256']==g['request_sha256']==s['request_sha256'] and sdk['action_id']==s['action_id'] and sdk.get('next_action_ids')==s.get('next_action_ids',[])==[],'EXACT_IMAGE_ONLY_PAID_C34_SDK200')
    need(sdk['resource_id']==s['resource_id']==tuple_['resource_id'] and sdk['resource_created_at']==s['resource_created_at']==tuple_['resource_created_at'] and g['slot']==tuple_['slot'] and g['profile_name']==tuple_['profile'] and g['integration_instance_id']==tuple_['integration_instance_id'] and g['scope_checksum']==tuple_['scope_checksum'] and utc(sdk['called_at'])<=utc(sdk['returned_at'])<utc(sdk['context_deadline'])<=utc(g['expires_at']),'EXACT_IMAGE_ONLY_SDK_TARGET_AND_ORIGINAL_CLOCK')
    if destroy:
        need(g['expected_resource_id']==tuple_['resource_id'] and g['expected_resource_created_at']==tuple_['resource_created_at'] and s['auxiliary_inventory_complete']is True and len(s['auxiliary_resources'])==2 and {x['kind']for x in s['auxiliary_resources']}=={'aws_ebs_volume','aws_network_interface'},'EXACT_IMAGE_ONLY_PAID_DESTROY_AUX2')
    return record

def image_read_pair(records, read_id, admission):
    rows=records['all_read_rows'];prepared=[x for x in rows if x['id']==read_id and x['stage']=='prepared'];returned=[x for x in rows if x['id']==read_id and x['stage']=='returned']
    need(len(prepared)==len(returned)==1,'IMAGE_ONLY_ALL_READS_HAVE_REAL_CLOSED_PAIRS')
    p,r=prepared[0],returned[0];pre_read_wire(p);pre_read_wire(r);challenge=p['original_record'];reply=r['original_record']
    need(p['admission_id']==r['admission_id']==admission['id'] and p['kind']==r['kind']==challenge['kind'] and challenge==reply['read'] and challenge['read_id']==read_id and challenge['retirement_request_id']==admission['retirement_request_id'] and challenge['prefix_sha256']==admission['prefix_sha256'] and challenge['original_caller_sha256']==admission['original_caller_sha256'] and challenge['tuple']==admission['original']['Request']['intent']['tuple'] and challenge['adapter_source_commit']==A3_CREATOR,'IMAGE_ONLY_READ_CHALLENGE_FULL_SCOPE')
    need(utc(challenge['issued_at_core'])<=utc(reply['started_at_core'])<=utc(reply['original_returned_at_core']) and 0<(utc(challenge['original_deadline_core'])-utc(challenge['issued_at_core'])).total_seconds()<=5 and utc(p['recorded_at'])<=utc(r['recorded_at']) and type(reply['call_failed'])is bool and type(reply['original_context_failed'])is bool,'IMAGE_ONLY_ORIGINAL_READ_CLOCK_AND_CLOSED_RETURN')
    need((reply['status']=='observed' and reply['call_failed']is False and reply['original_context_failed']is False and utc(reply['original_returned_at_core'])<utc(challenge['original_deadline_core']))or(reply['status']=='' and reply['call_failed']is True),'IMAGE_ONLY_CLOSED_FAILURE_RETAINED_NEVER_QUALIFIED')
    return p,r

def validate_terminal_s8(value):
    OLD_SOURCE = HISTORICAL_CORE6_SOURCE
    r=image_snapshot(value,value['records_sha256']);target=S8_TERMINAL_TARGET
    terminal=one_frame(r['forward_rows'],target['admission_id'],'terminal');p=terminal['original_record']
    admitted=one_frame(r['forward_rows'],p['id'],'admitted');a=admitted['original_record']
    need(terminal['record_sha256']==target['record_sha256'] and p['actual_core_source']==OLD_SOURCE and p['generation']==target['generation'] and p['fence']==target['fence'] and p['root_admission_id']==PRE_READ_TARGET['root_admission_id'] and p['retirement_request_id']==PRE_READ_TARGET['retirement_request_id'] and p['destroy_grant_id']==PRE_READ_TARGET['destroy_grant_id'] and p['native_absence_sha256']==target['native_absence_sha256'] and p['terminal_intent_sha256']==target['terminal_intent_sha256'] and p['run_id']==target['run_id'] and p['admission_sha256']==admitted['record_sha256'],'PINNED_HISTORICAL_S8_TERMINAL_NOT_CURRENT_AUTHORITY')
    mask={'stage','recorded_at','admission_sha256','destroy_grant_id','native_absence_sha256','terminal_intent_sha256','terminal_intent_wire'}
    need({k:v for k,v in p.items()if k not in mask}=={k:v for k,v in a.items()if k not in mask},'EXACT_GO_TERMINAL_COPY_OF_SAME_ADMITTED_OWNER')
    raw=base64.b64decode(p['terminal_intent_wire'],validate=True);intent=loads(raw)
    need(sha(raw)==p['terminal_intent_sha256'] and intent['generation']==p['generation'] and intent['fencing_token']==p['fence'] and intent['phase']=='promoted' and not intent.get('lease_owner') and intent.get('lease_expires_at')is None and intent['retirement_forward']==forward_marker_data(p),'EXACT_HISTORICAL_TERMINAL_INTENT_UNLEASED_NO_CURRENT_EPOCH_ALIAS')
    prepared,returned=image_read_pair(r,target['read_id'],a);reply=returned['original_record'];obs=reply['observation']
    need(returned['kind']=='absence' and returned['record_sha256']==p['native_absence_sha256'] and reply['status']=='observed' and reply['call_failed']is False and reply['original_context_failed']is False and obs['server_absent']is True and obs['server_absence_complete']is True and obs['billable_resources_absent']is True and obs['retirement_complete']is True and obs['auxiliary_inventory_complete']is True and obs['hold_reasons']==[] and len(obs['auxiliary_resources'])==2 and all(x['absent']is True for x in obs['auxiliary_resources']),'GENUINE_S8_OWN_COMPLETE_ABSENCE_NOT_PENDING_OR_FAILED')
    grants=[g for g in r['destroy_grants']if g['id']==p['destroy_grant_id']];need(len(grants)==1,'ONE_HISTORICAL_S8_PAID_DELETE')
    record=paid_original_sdk(grants[0],p['original']['Request']['intent']['tuple'],True)
    need(record['grant']['state']=='confirmed' and record['proof']['resource_absent']is True and len(record['proof']['auxiliary_absent'])==2 and obs['destroy_grant_id']==record['grant']['grant_id'] and obs['id']==record['settlement']['resource_id'],'HISTORICAL_S8_CONFIRMED_GRANT_AND_AUX2_PROOF')
    w,j=completed_owner(r,target['run_id'],p,True)
    need(utc(returned['recorded_at'])<=utc(p['recorded_at'])<=utc(w['finished_at'])<=utc(j['finalization_ack_at']),'HISTORICAL_S8_TERMINAL_BEFORE_ITS_COMPLETED_ACK')
    return True

def validate_current_live(value, case):
    OLD_SOURCE = HISTORICAL_CORE6_SOURCE
    closed(case,'schema retirement_request_id admission_id preregistration_id current_runtime_source current_generation current_fencing_token current_lease_owner current_executor_id current_failed_run_id expected_records_sha256 provider_lanes historical_s8_ref','CLOSED_TERMINAL_S8_CURRENT_LIVE_CASE13')
    need(case['schema']==LIVE_CASE_SCHEMA and case['historical_s8_ref']==S8_TERMINAL_REF and case['retirement_request_id']==LIVE_TARGET['retirement_request_id'] and case['admission_id']==LIVE_TARGET['admission_id'] and case['preregistration_id']==LIVE_TARGET['preregistration_id'] and case['current_runtime_source']==OLD_SOURCE and type(case['current_generation'])is int and case['current_generation']==LIVE_TARGET['generation'] and type(case['current_fencing_token'])is int and case['current_fencing_token']==LIVE_TARGET['fence'] and case['current_lease_owner']==LIVE_TARGET['lease_owner'] and case['current_executor_id']==LIVE_TARGET['executor_id'] and case['current_failed_run_id']==LIVE_TARGET['run_id'],'EXACT_DISTINCT_ROOT_CURRENT_LIVE_OWNER_NOT_S8')
    r=image_snapshot(value,case['expected_records_sha256'])
    closed(r,'selected_runtime_source target current_intent current_intent_pgtext active_policies forward_rows create_grants retirement_contexts delete_bindings destroy_grants read_counts own_read_count all_read_rows unreturned_prepared latest_reads_all_outcomes workflow_runs workflow_run_steps owning_dispatch_jobs','CLOSED_FULL_CURRENT_LIVE_RECORD_SET')
    need(r['selected_runtime_source']==OLD_SOURCE and r['target']=={'parent_forward_id':LIVE_TARGET['admission_id'],'retirement_request_id':LIVE_TARGET['retirement_request_id'],'preregistration_id':LIVE_TARGET['preregistration_id'],'resource_id':LIVE_TARGET['resource_id']},'FIXED_CURRENT_LIVE_TARGET_SOURCE_SCOPE')
    arow=one_frame(r['forward_rows'],LIVE_TARGET['admission_id'],'admitted');qrow=one_frame(r['forward_rows'],LIVE_TARGET['admission_id'],'off_qualified');a,q=arow['original_record'],qrow['original_record']
    need(len(r['forward_rows'])==2 and a['mode']=='live' and a['issuer']=='source:ordinary-retirement' and a['root_admission_id']==a['id']==LIVE_TARGET['admission_id'] and not a.get('parent_admission_id') and not a.get('continuation') and a['actual_core_source']==OLD_SOURCE and a['preregistration_id']==LIVE_TARGET['preregistration_id'] and a['retirement_request_id']==LIVE_TARGET['retirement_request_id'],'ONE_ORDINARY_LIVE_ROOT_ADMISSION_NO_CONTINUATION_ALIAS')
    mask={'stage','recorded_at','admission_sha256','native_off_read_id','native_off_sha256'}
    need(q['admission_sha256']==arow['record_sha256'] and {k:v for k,v in q.items()if k not in mask}=={k:v for k,v in a.items()if k not in mask},'EXACT_GO_OWN_OFF_QUALIFICATION_COPY')
    current=r['current_intent']['intent'];need(loads(r['current_intent_pgtext'])==current and current['retirement_forward']==forward_marker_data(q) and current['generation']==a['generation']==case['current_generation'] and current['fencing_token']==a['fence']==case['current_fencing_token'] and current['lease_owner']==a['lease_owner']==case['current_lease_owner'] and current['lease_executor_id']==a['executor_id']==case['current_executor_id'] and a['run_id']==case['current_failed_run_id'] and current['phase']=='drained' and utc(current['lease_expires_at'])<=utc(value['observed_at_pg']),'CURRENT_LIVE_FAILED_EXPIRED_OWNER_EXACT_NO_COUNTER_OR_TIMER_RESET')
    original=base64.b64decode(a['original_intent_wire'],validate=True);need(sha(original)==a['original_intent_sha256'],'CURRENT_LIVE_ORIGINAL_INTENT_WIRE_PRESERVED')
    need(len(r['active_policies'])==1 and r['active_policies'][0]['id']==current['policy_id'] and r['active_policies'][0]['checksum']==current['policy_checksum'],'CURRENT_LIVE_SINGLE_EXACT_POLICY')
    tuple_=a['original']['Request']['intent']['tuple'];need(tuple_['slot']==LIVE_TARGET['slot'] and tuple_['resource_id']==LIVE_TARGET['resource_id'] and tuple_['resource_created_at']==LIVE_TARGET['resource_created_at'],'EXACT_CURRENT_LIVE_PAID_NATIVE_TUPLE')
    creates=r['create_grants'];need(len(creates)==1 and creates[0]['id']==a['original']['Preregistration']['original_create_grant_id'],'ONE_CURRENT_LIVE_ORIGINAL_CREATE')
    create=paid_original_sdk(creates[0],tuple_,False);need(create['grant']['request_sha256']==a['original']['Preregistration']['original_create_request_sha256'],'CURRENT_LIVE_CREATE_REQUEST_PROVENANCE')
    need(r['unreturned_prepared']==[] and type(r['own_read_count'])is int and r['own_read_count']==len(r['all_read_rows']) and len(r['all_read_rows'])>=2,'ALL_CURRENT_READS_RETAINED_NO_OPEN_OR_ZERO_OWN_REINTERPRETATION')
    ids={row['id']for row in r['all_read_rows']}
    for ident in ids:
        prepared,returned=image_read_pair(r,ident,a)
        need(prepared['original_record']['admission_sha256']==arow['record_sha256'],'CURRENT_READS_BIND_EXACT_ADMITTED_SHA')
    prepared,off=image_read_pair(r,q['native_off_read_id'],a);reply=off['original_record'];server=reply['plan']['server']
    need(off['kind']=='off' and off['record_sha256']==q['native_off_sha256'] and utc(off['recorded_at'])==utc(q['recorded_at']) and reply['status']=='observed' and reply['call_failed']is False and reply['original_context_failed']is False and server['id']==tuple_['resource_id'] and server['created_at']==tuple_['resource_created_at'] and server['status']=='stopped','GENUINE_CURRENT_OWN_STOPPED_OFF_PAIR_NOT_FAILED_READ_AUTHORITY')
    need(len(r['delete_bindings'])==len(r['destroy_grants'])==1,'ONE_KNOWN_CURRENT_LIVE_DELETE_NOT_ADMISSION_FIELD_GUESS')
    binding=r['delete_bindings'][0];wire=bytes.fromhex(binding['wire_hex']);eligibility=binding['original_eligibility_record']
    closed(eligibility,'schema admission_id admission_sha256 native_off_read_id native_off_sha256','CLOSED_OWNING_CURRENT_DELETE_ELIGIBILITY')
    need(loads(wire)==eligibility and sha(wire)==binding['eligibility_sha256'] and binding['intent_id']==a['retirement_request_id'] and binding['destroy_grant_id']==LIVE_TARGET['destroy_grant_id'] and eligibility=={'schema':'original_guest_partial_poweroff_delete_eligibility_v1','admission_id':a['id'],'admission_sha256':arow['record_sha256'],'native_off_read_id':q['native_off_read_id'],'native_off_sha256':q['native_off_sha256']},'CURRENT_DELETE_BINDS_OWN_REAL_OFF_NOT_S8_TERMINAL')
    stored=r['destroy_grants'][0];need(stored['id']==LIVE_TARGET['destroy_grant_id'],'CURRENT_DELETE_NOT_HISTORICAL_S8_PAID_GRANT')
    paid=paid_original_sdk(stored,tuple_,True);need(paid['generation']==a['generation'] and paid['fencing_token']==a['fence'] and paid['lease_owner']==a['lease_owner'] and paid['executor_id']==a['executor_id'],'CURRENT_KNOWN_DELETE_EXACT_ORIGINAL_OWNER')
    w,j=completed_owner(r,a['run_id'],a)
    need(j['id']==LIVE_TARGET['dispatch_id'] and all(utc(x['recorded_at'])<=utc(j['returned_at'])for x in r['all_read_rows']) and utc(j['finalization_ack_at'])<=utc(value['observed_at_pg']),'CURRENT_ALL_CLOSED_READS_BEFORE_ITS_FAILED_FINAL_ACK')
    return True

def validate_maintenance_scenario(c, C):
    if c['schema'] == NORMAL_FINISH_SCHEMA:
        return validate_normal_finish97(loads(input_ref(C,c['normal_finish_preimage_ref'])),c['normal_finish_case'])
    if c['schema']=='g15_pre_read_continuation_image_maintenance_v1':
        return validate_pre_read96(loads(input_ref(C,c['pre_read_preimage_ref'])),c['pre_read_case'])
    need(c['schema']==LIVE_SCHEMA,'ONLY_EXPLICIT_IMAGE_MAINTENANCE_SCENARIOS')
    case=c['pre_read_case'];validate_current_live(loads(input_ref(C,c['pre_read_preimage_ref'])),case)
    need(case['historical_s8_ref']==S8_TERMINAL_REF,'EXACT_RETAINED_HISTORICAL_S8_SOURCE')
    return validate_terminal_s8(loads(input_ref(C,case['historical_s8_ref'])))

def catalog97_select(legacy):
    """Same seven-key catalog, explicitly retaining the new M97 function."""
    sql = catalog94_select(legacy)
    old = "p.proname IN('guard_retirement_forward','guard_retirement_forward_read','guard_retirement_forward_delete_binding','retirement_forward_continuation_quiet','retirement_forward_continuation_valid')"
    need(sql.count(old) == 1, 'EXACT_HISTORICAL_FUNCTION_SELECTOR_FOR97')
    return sql.replace(old, old[:-1] + ",'retirement_forward_normal_finish_recovery_valid')", 1)


def migration97_functions(sql):
    need(digest_value(M97) and sha(sql.encode()) == M97, 'EXACT_PINNED_M97_SOURCE')
    up = sql.split('-- +goose Down', 1)[0]
    patterns = {
        'retirement_forward_normal_finish_recovery_valid':
            (r"CREATE OR REPLACE FUNCTION public\.retirement_forward_normal_finish_recovery_valid\(r jsonb, retirement uuid\) RETURNS boolean\nLANGUAGE plpgsql STABLE SET timezone='UTC' AS \$\$(.*?)\$\$;",
             'r jsonb, retirement uuid', 'boolean', 's', ['TimeZone=UTC']),
        'guard_retirement_forward':
            (r"CREATE OR REPLACE FUNCTION public\.guard_retirement_forward\(\) RETURNS trigger LANGUAGE plpgsql AS \$\$(.*?)\$\$;",
             '', 'trigger', 'v', None),
    }
    result = {}
    for name, (pattern, arguments, output, volatility, config) in patterns.items():
        rows = re.findall(pattern, up, re.S)
        need(len(rows) == 1 and rows[0], 'ONE_EXACT_SOURCE97_FUNCTION_' + name)
        result[name] = {'arguments': arguments, 'result': output, 'language': 'plpgsql',
                        'volatility': volatility, 'config': config, 'body': rows[0]}
    return result


def constraint97_definitions(prior96, carrier, read_ref, expected_source):
    """Authenticate unchanged CI originals through explicit same-hash copies."""
    closed(carrier, 'artifact_ref before96_ref after97_ref', 'CLOSED97_PG_ORIGINAL_CUSTODY_CARRIER')
    raw = {key: read_ref(value) for key, value in carrier.items()}
    artifact = loads(raw['artifact_ref'])
    closed(artifact, 'schema source_commit postgres_major fixture_only native_authority before96_ref after97_ref migration97_sha256 old_continuation_functions_unchanged old_continuation_constraints_unchanged old_mode93_absent new_mode97_and_normal_finish97_validated', 'CLOSED_ACTUAL97_PG_CI_ARTIFACT12')
    need(artifact['schema'] == 'normal_finish_recovery_schema97_pg_catalog_v1'
         and source(expected_source) and artifact['source_commit'] == expected_source
         and artifact['postgres_major'] in (16, 17)
         and type(artifact['postgres_major']) is int and artifact['fixture_only'] is True
         and artifact['native_authority'] is False and artifact['migration97_sha256'] == M97
         and all(artifact[key] is True for key in (
             'old_continuation_functions_unchanged', 'old_continuation_constraints_unchanged',
             'old_mode93_absent', 'new_mode97_and_normal_finish97_validated')),
         'ACTUAL97_SOURCE_PG_CI_FACTS_NOT_NATIVE_QUALIFICATION')
    views = {}
    for key in ('before96_ref', 'after97_ref'):
        original = artifact[key]
        closed(original, 'path sha256 bytes', 'CLOSED_CANONICAL97_PG_CI_ORIGINAL_REF')
        need(type(original['path']) is str and Path(original['path']).is_absolute()
             and digest_value(original['sha256']) and type(original['bytes']) is int
             and 0 < original['bytes'] <= CAP and len(raw[key]) == original['bytes']
             and sha(raw[key]) == original['sha256'] == carrier[key]['sha256'],
             'COMPLETE97_PG_ORIGINAL_SAME_SHA_COPY')
        view = loads(raw[key])
        closed(view, 'server_version_num functions constraints', 'CLOSED97_PG_RAW_CATALOG')
        need(type(view['server_version_num']) is int
             and view['server_version_num'] // 10000 == artifact['postgres_major']
             and type(view['functions']) is dict and type(view['constraints']) is list,
             'ACTUAL97_PG_VERSION_AND_FULL_CATALOG_SHAPES')
        views[key] = view
    before, after = views['before96_ref'], views['after97_ref']
    need(before['server_version_num'] == after['server_version_num'], 'SAME97_CI_PG_SERVER')
    old_names = {'guard_retirement_forward', 'retirement_forward_continuation_valid',
                 'retirement_forward_continuation_quiet'}
    need(set(before['functions']) == old_names
         and set(after['functions']) == old_names | {'retirement_forward_normal_finish_recovery_valid'}
         and all(type(value) is str and value for value in before['functions'].values())
         and all(type(value) is str and value for value in after['functions'].values()),
         'EXACT97_CHANGED_ADDED_AND_HISTORICAL_FUNCTION_ROSTER')
    prior_functions = {row['name']: row for row in prior96['functions93']}
    need(all(before['functions'][name] == prior_functions[name]['definition'] for name in old_names)
         and all(after['functions'][name] == before['functions'][name] for name in (
             'retirement_forward_continuation_valid', 'retirement_forward_continuation_quiet'))
         and after['functions']['guard_retirement_forward'] != before['functions']['guard_retirement_forward'],
         'ORIGINAL96_FUNCTIONS_AND_ONLY97_GUARD_CHANGE')
    checks = {}
    for label, view in (('before', before), ('after', after)):
        rows = view['constraints']
        for row in rows:
            closed(row, 'name validated definition', 'CLOSED97_PG_CHECK_ORIGINAL')
            need(type(row['name']) is str and row['validated'] is True
                 and type(row['definition']) is str and row['definition'].startswith('CHECK ('),
                 'ALL97_PG_CHECKS_VALIDATED_AND_COMPLETE')
        need(len({row['name'] for row in rows}) == len(rows), 'UNIQUE97_CHECK_NAMES')
        checks[label] = {row['name']: row for row in rows}
    prior_checks = {row['name']: {'name': row['name'], 'validated': row['validated'],
                                'definition': row['definition']}
                    for row in prior96['catalog90']['constraints']
                    if row['table'] == 'capacity_guest_retirement_forwards'
                    and row['definition'].startswith('CHECK (')}
    need(checks['before'] == prior_checks and 'retirement_forward_mode93' in checks['before']
         and set(checks['after']) == (set(checks['before']) - {'retirement_forward_mode93'}) |
             {'retirement_forward_mode97', 'retirement_forward_normal_finish97'}
         and all(checks['after'][name] == row for name, row in checks['before'].items()
                 if name != 'retirement_forward_mode93'), 'ONLY97_MODE_REPLACEMENT_AND_NEW_PROOF_CHECK')
    return {'checks': {name: checks['after'][name]['definition'] for name in (
                'retirement_forward_mode97', 'retirement_forward_normal_finish97')},
            'functions': after['functions']}


def catalog97_delta(prior96, actual97, functions, definitions):
    need(set(prior96) == set(actual97) == {
        'catalog90', 'catalog91', 'columns90_91', 'functions93',
        'index92_definition', 'index92_valid', 'schema94'},
        'SAME_COMPLETE_SEVEN_KEY_CATALOG_AT97')
    need(set(functions) == set(M97_FUNCTIONS)
         and set(definitions['checks']) == {
             'retirement_forward_mode97', 'retirement_forward_normal_finish97'},
         'EXACT_SOURCE97_FUNCTION_AND_CHECK_DELTA')
    expected = copy.deepcopy(prior96)
    old = [row for row in expected['functions93'] if row['name'] == 'guard_retirement_forward']
    need(len(old) == 1, 'ONE_PRIOR96_FORWARD_GUARD')
    for name in M97_FUNCTIONS:
        rows = [row for row in actual97['functions93'] if row['name'] == name]
        need(len(rows) == 1 and rows[0]['body'] == functions[name]['body']
             and all(rows[0][key] == functions[name][key] for key in (
                 'arguments', 'result', 'language', 'volatility', 'config'))
             and rows[0]['definition'] == definitions['functions'][name]
             and rows[0]['definition'].count(rows[0]['body']) == 1,
             'WHOLE97_SOURCE_AND_ACTUAL_PG_DEFINITION_' + name)
        if name == 'guard_retirement_forward':
            need(set(rows[0]) == set(old[0])
                 and all(rows[0][key] == old[0][key] for key in (
                     'name', 'arguments', 'result', 'language', 'volatility', 'config')),
                 'UNCHANGED97_FORWARD_GUARD_SIGNATURE')
            old[0].update(body=rows[0]['body'], definition=rows[0]['definition'])
        else:
            need(not any(row['name'] == name for row in expected['functions93']),
                 'NEW97_NORMAL_FINISH_FUNCTION_NOT_PRIOR_AUTHORITY')
            expected['functions93'].append(copy.deepcopy(rows[0]))
    expected['functions93'].sort(key=lambda row: row['name'])
    mode = [row for row in expected['catalog90']['constraints']
            if row['table'] == 'capacity_guest_retirement_forwards'
            and row['name'] == 'retirement_forward_mode93']
    need(len(mode) == 1 and mode[0]['validated'] is True, 'ONE_PRIOR96_MODE_CHECK')
    new_check = copy.deepcopy(mode[0])
    mode[0].update(name='retirement_forward_mode97',
                   definition=definitions['checks']['retirement_forward_mode97'])
    new_check.update(name='retirement_forward_normal_finish97',
                     definition=definitions['checks']['retirement_forward_normal_finish97'])
    expected['catalog90']['constraints'].append(new_check)
    expected['catalog90']['constraints'].sort(key=lambda row: (row['table'], row['name']))
    need(expected == actual97, 'ALL_OTHER96_CATALOG_FUNCTION_INDEX_TRIGGER_BYTES_UNCHANGED')
    return actual97


def root97_overlay(receipt_raw, prior96_raw, pins, read_ref):
    need(sha(prior96_raw) == ROOT96_SHA, 'IMMUTABLE_ROOT96_WHOLE_ORIGINAL')
    previous, value = loads(prior96_raw), loads(receipt_raw)
    closed(value, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration97_sha256 complete_history_sha256 prior96_history_sha256 catalog97_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'ROOT97_CLOSED21')
    need(previous['schema'] == 'root_goose96_guest_retirement_pre_read_continuation_acceptance_v1'
         and previous['reviewed_by_root'] is True and previous['schema_after'] == 96
         and value['schema'] == 'root_goose97_normal_finish_recovery_acceptance_v1'
         and value['reviewed_by_root'] is True and value['schema_before'] == 96
         and value['schema_after'] == 97, 'ROOT97_DISTINCT_FROM_HISTORICAL96')
    need(value['current_core_source'] == ROOT97_CURRENT_CORE_SOURCE
         and value['current_ops_source'] == pins['current_ops_source']
         and source(value['current_ops_source']) and value['business_source'] == pins['business_source']
         and source(value['business_source']) and value['amd64_D'] == pins['amd64_D']
         and digest_value(value['amd64_D']), 'ROOT97_ACTUAL_CORE7_AND_QUALIFIED_CORE8_COMPANION')
    need(digest_value(M97) and value['migration97_sha256'] == M97
         and value['complete_history_sha256'] == pins['complete_history_sha256']
         and value['prior96_history_sha256'] == previous['complete_history_sha256'] == pins['prior96_history_sha256']
         and value['catalog97_sha256'] == pins['catalog97_sha256']
         and value['index92_definition_sha256'] == previous['index92_definition_sha256'] == pins['index92_definition_sha256']
         and value['catalog90_91_sha256'] == pins['catalog90_91_sha256'],
         'ACTUAL97_WHOLE_HISTORY_CATALOG_AND_PRIOR96')
    need(full_id(value['job_uid']) and full_id(value['pod_uid'])
         and type(value['exit_code']) is int and value['exit_code'] == 0
         and value['single_job_create'] is True
         and type(value['provider_guest_core_mutations']) is int and value['provider_guest_core_mutations'] == 0
         and value['old_records_and_sdk_preserved'] is True, 'ROOT97_ONE_JOB_NO_PROVIDER_OR_CORE_MUTATION')
    closed(value['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image',
           'ROOT97_FIVE_ORIGINAL_ROLES')
    need(len({ref['sha256'] for ref in value['original_refs'].values()}) == 5,
         'ROOT97_DISTINCT_ORIGINAL_ROLES')
    for ref in value['original_refs'].values():
        original = read_ref(ref)
        need(type(original) is bytes and len(original) > 1, 'ROOT97_COMPLETE_ORIGINAL_CUSTODY')
    return value



def normal_pg_bytea(value):
    need(type(value) is str and re.fullmatch(r'\\x(?:[0-9a-f]{2})*',value),
         'CANONICAL_POSTGRES_JSON_BYTEA_HEX')
    return bytes.fromhex(value[2:])


def normal_finish_stamp_ns(value):
    """Keep original wire order; datetime precision is not deadline authority."""
    stamp = utc(value).astimezone(datetime.timezone.utc)
    delta = stamp - datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
    fraction = re.search(r'\.(\d{1,9})(?=Z|[+-])', value)
    tail = int((fraction.group(1) + '000000000')[:9][-3:]) if fraction else 0
    return ((delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds) * 1000 + tail


def normal_finish_pg_deadline_equal(original, stored):
    """Only the wire-to-PG join rounds to PG microseconds, nearest ties even."""
    nanos = normal_finish_stamp_ns(original)
    pg_nanos = normal_finish_stamp_ns(stored)
    micros, remainder = divmod(nanos, 1000)
    if remainder > 500 or (remainder == 500 and micros % 2):
        micros += 1
    return pg_nanos % 1000 == 0 and pg_nanos == micros * 1000


def normal_finish_wire(row, record_key, digest_key):
    raw = bytes.fromhex(row['wire_hex'])
    need(normal_pg_bytea(row['original_wire']) == raw
         and loads(raw) == row[record_key] and sha(raw) == row[digest_key],
         'COMPLETE_NORMAL_FINISH_ORIGINAL_WIRE')
    return raw


def validate_normal_finish97(value, case):
    closed(case, 'schema retirement_request_id preregistration_id current_runtime_source current_generation current_fencing_token current_lease_owner current_executor_id current_failed_run_id expected_records_sha256 provider_lanes',
           'CLOSED_NORMAL_FINISH_IMAGE_CASE11')
    t = NORMAL_FINISH_TARGET
    need(case['schema'] == NORMAL_FINISH_CASE_SCHEMA
         and case['retirement_request_id'] == t['retirement_request_id']
         and case['preregistration_id'] == t['preregistration_id']
         and case['current_runtime_source'] == ROOT97_CURRENT_CORE_SOURCE
         and type(case['current_generation']) is int and case['current_generation'] == t['generation']
         and type(case['current_fencing_token']) is int and case['current_fencing_token'] == t['fence']
         and case['current_lease_owner'] == t['lease_owner']
         and case['current_executor_id'] == t['executor_id']
         and case['current_failed_run_id'] == t['run_id'], 'EXACT_G37_NORMAL_FINISH_OWNER_NOT_LIVE')
    r = image_snapshot(value, case['expected_records_sha256'])
    closed(r, 'selected_runtime_source target current_intent current_intent_pgtext active_policies retirement_requests preregistrations create_grants retirement_contexts caller_returns original_returns native_poweroff_reads forward_rows forward_reads delete_bindings destroy_grants workflow_runs owning_dispatch_jobs',
           'FULL_NORMAL_FINISH_RECORD_SET')
    need(r['selected_runtime_source'] == ROOT97_CURRENT_CORE_SOURCE
         and r['target'] == {k: t[k] for k in ('retirement_request_id','preregistration_id')}
         and r['forward_rows'] == r['forward_reads'] == r['delete_bindings'] == r['destroy_grants'] == [],
         'NO_NORMAL_FINISH_FORWARD_OR_DELETE_AUTHORITY_INVENTED')
    current = r['current_intent']['intent']
    need(loads(r['current_intent_pgtext']) == current
         and current['generation'] == t['generation'] and current['fencing_token'] == t['fence']
         and current['lease_owner'] == t['lease_owner'] and current['lease_executor_id'] == t['executor_id']
         and current['phase'] in ('draining','drained') and current.get('recovery_only',False) is False
         and current.get('floor_degraded',False) is False and current.get('retirement_forward') is None
         and utc(current['lease_expires_at']) < utc(value['observed_at_pg']),
         'EXACT_EXPIRED_NORMAL_EPOCH_NO_MARKER_OR_CLOCK_RESET')
    need(len(r['active_policies']) == 1 and r['active_policies'][0]['id'] == current['policy_id']
         and r['active_policies'][0]['checksum'] == current['policy_checksum'],
         'NORMAL_FINISH_CURRENT_POLICY_NOT_RELABELED')
    need(len(r['retirement_requests']) == len(r['preregistrations']) == len(r['create_grants'])
         == len(r['retirement_contexts']) == len(r['caller_returns']) == 1,
         'ONE_ORIGINAL_NORMAL_RETIREMENT_CALLER_AND_CREATE')
    request, pre = r['retirement_requests'][0], r['preregistrations'][0]
    need(request['id'] == t['retirement_request_id'] and request['preregistration_id'] == pre['id']
         == t['preregistration_id'], 'ORIGINAL_NORMAL_REQUEST_PREREGISTRATION')
    request_raw = bytes.fromhex(request['wire_hex'])
    need(request_raw == normal_pg_bytea(request['original_wire'])
         and loads(request_raw)['intent'] == request['intent_record']
         and sha(raw_json_member(request_raw,'intent')) == request['intent_sha256'],
         'COMPLETE_DURABLE_NORMAL_REQUEST_WITH_EXACT_INTENT_TOKEN_HASH')
    intent = request['intent_record']
    need(intent['schema'] == 'original_guest_production_retirement_intent_v2'
         and intent['request_id'] == request['id'] and intent['attempt_id'] == request['attempt_id']
         and intent['preregistration_id'] == pre['id']
         and intent['generation'] == t['generation'] and intent['fence'] == t['fence']
         and intent['lease_owner'] == t['lease_owner'] and loads(request_raw)['nonce'] == '',
         'EXACT_ORIGINAL_NORMAL_REQUEST_OWNER_AND_DURABLE_REDACTED_NONCE')
    caller = r['caller_returns'][0]; caller_raw = normal_finish_wire(caller,'original_record','return_sha256')
    c = caller['original_record']
    need(caller['intent_id'] == request['id'] and c['request_id'] == request['id']
         and c['attempt_id'] == request['attempt_id'] and type(c['status']) is int and c['status'] == 200
         and c['body_persisted'] is True and all(c[k] is False for k in (
             'preflight_failed','do_failed','read_failed','close_failed','original_context_failed'))
         and normal_finish_stamp_ns(c['original_deadline']) == normal_finish_stamp_ns(intent['original_deadline'])
         and normal_finish_pg_deadline_equal(c['original_deadline'], request['original_deadline'])
         and normal_finish_stamp_ns(intent['issued_at']) <= normal_finish_stamp_ns(c['started_at'])
         <= normal_finish_stamp_ns(c['do_started_at']) <= normal_finish_stamp_ns(c['do_returned_at'])
         <= normal_finish_stamp_ns(c['read_returned_at']) <= normal_finish_stamp_ns(c['close_returned_at'])
         <= normal_finish_stamp_ns(c['driver_returned_at']) < normal_finish_stamp_ns(c['original_deadline']),
         'GENUINE_ORIGINAL_NORMAL_CALLER200_COMPLETE_BEFORE_DEADLINE')
    original = r['original_returns']
    need(len(original) == 5 and [x['sequence'] for x in original] == [1,2,3,4,5]
         and all(x['intent_id'] == request['id'] for x in original)
         and [x['original_return_record']['record']['sequence'] for x in original[1:]] == [1,2,3,4]
         and [x['kind'] for x in original] == ['production_clock_nonce_v2'] + [
             'production_retirement_v2:' + state for state in (
                 'possible_start','quiescent','poweroff_possible_start','poweroff_command_returned')],
         'ALL_FIVE_NORMAL_ORIGINAL_RETIREMENT_RETURNS')
    raws = []
    for index,row in enumerate(original):
        raw = bytes.fromhex(row['wire_hex'])
        need(raw == normal_pg_bytea(row['original_wire'])
             and loads(raw) == row['original_return_record']
             and sha(raw if index == 0 else raw_json_member(raw,'record')) == row['return_sha256'],
             'COMPLETE_NORMAL_NONCE_OR_JOURNAL_WITH_ITS_SOURCE_DIGEST_DOMAIN')
        raws.append(raw)
    nonce = original[0]['original_return_record']
    need(original[0]['kind'] == 'production_clock_nonce_v2'
         and nonce['schema'] == 'original_core_guest_retirement_nonce_return_v2'
         and nonce['preflight_sha256'] == request['intent_sha256'],
         'AUTHENTICATED_ORIGINAL_NORMAL_NONCE_NOT_JSON_RECODE')
    final_request = nonce['final_request']; final_intent = final_request['intent']
    final_request_raw = raw_json_member(raws[0], 'final_request')
    final_intent_raw = raw_json_member(final_request_raw, 'intent')
    final_sha = sha(final_intent_raw)
    need(loads(final_intent_raw) == final_intent and final_intent['tuple'] == request['intent_record']['tuple']
         and final_request['nonce'] == ''
         and all(final_intent[k] == intent[k] for k in (
             'schema','request_id','attempt_id','preregistration_id','generation','fence','lease_owner')),
         'EXACT_FINALIZED_NORMAL_INTENT_RAW_TOKEN')
    returned = original[4]['original_return_record']
    need(original[4]['kind'] == 'production_retirement_v2:poweroff_command_returned'
         and loads(base64.b64decode(c['body'],validate=True)) == returned
         and returned['journal_complete'] is True and returned['hold_reasons'] == []
         and returned['record']['sequence'] == 4 and returned['record']['poweroff_command_returned'] is True
         and returned['record']['writer_quiescence_evidence'] is True
         and returned['record']['powered_off_observed'] is False,
         'NORMAL_RETIRE_SUCCESS_IS_NOT_NATIVE_OFF_OR_DELETE_AUTHORITY')
    tuple_ = final_intent['tuple']
    need(tuple_['slot'] == 2 and current['decision']['units'] == 1
         and final_intent['policy_id'] == current['policy_id']
         and final_intent['policy_checksum'] == current['policy_checksum'],
         'NORMAL_FINISH_EXACT_SLOT2_AND_CURRENT_POLICY')
    created = paid_original_sdk(r['create_grants'][0],tuple_,False)
    need(pre['create_grant_id'] == created['grant']['grant_id'], 'NORMAL_FINISH_SAME_PAID_ORIGINAL_CREATE')
    context = r['retirement_contexts'][0]
    need(context['intent_id'] == request['id']
         and context['executor_id'] == t['executor_id']
         and context['core_actual_source_commit'] == ROOT97_CURRENT_CORE_SOURCE
         and utc(context['original_context_deadline']) < utc(value['observed_at_pg'])
         and utc(request['original_deadline']) < utc(value['observed_at_pg']),
         'NATURAL_NORMAL_CONTEXT_AND_LEASE_EXPIRY')
    reads = r['native_poweroff_reads']
    need(len(reads) == 2, 'EXACT_NORMAL_OFF_PREPARED_AND_FAILED_RETURN')
    prepared = [x for x in reads if x['original_record'].get('schema') == 'original_core_guest_native_poweroff_read_challenge_v2']
    replies = [x for x in reads if x['original_record'].get('schema') == 'original_core_guest_native_poweroff_read_return_v2']
    need(len(prepared) == len(replies) == 1, 'NO_UNKNOWN_OR_EXTRA_NORMAL_OFF_ORIGINAL')
    prepared, reply = prepared[0], replies[0]
    challenge_raw = normal_finish_wire(prepared,'original_record','observation_sha256')
    normal_finish_wire(reply,'original_record','observation_sha256')
    d, v = prepared['original_record'], reply['original_record']
    need(normal_pg_bytea(reply['original_native_join_wire']) == challenge_raw
         and v['challenge'] == d and d['read_id'] == prepared['id'] and d['intent_id'] == request['id']
         and d['intent_sha256'] == final_sha and d['original_caller_sha256'] == caller['return_sha256']
         and d['tuple'] == tuple_ and digest_value(d['mutation_binding_sha256'])
         and d['adapter_source_commit'] == created['binding']['original_provider_source_commit']
         and utc(caller['recorded_at']) < utc(prepared['recorded_at']) <= utc(reply['recorded_at'])
         and utc(d['issued_at_core']) < utc(d['original_deadline_core'])
         <= utc(d['issued_at_core']) + datetime.timedelta(seconds=5),
         'EXACT_ORIGINAL_NORMAL_OFF_CHALLENGE_JOIN_AND_FIVE_SECOND_CAP')
    need(v['call_failed'] is True and v['original_context_failed'] is False
         and v['status'] in ('','observed') and 'plan' not in v
         and utc(d['issued_at_core']) <= utc(v['started_at_core'])
         <= utc(v['original_returned_at_core']) < utc(d['original_deadline_core'])
         and utc(v['original_returned_at_core']) <= utc(reply['recorded_at']),
         'ACTUAL_FAILED_NORMAL_OFF_WITHOUT_OBSERVED_AUTHORITY')
    need(len(r['workflow_runs']) == len(r['owning_dispatch_jobs']) == 1,
         'UNIQUE_NORMAL_FINISH_ORIGINAL_WORKFLOW_OWNER')
    w,j = r['workflow_runs'][0],r['owning_dispatch_jobs'][0]
    need(loads(w['run_wire']) == {k:v for k,v in w.items() if k!='run_wire'}
         and loads(j['dispatch_wire']) == {k:v for k,v in j.items() if k!='dispatch_wire'}
         and w['id'] == j['run_id'] == t['run_id'] and w['status'] == w['result']['status']
         == j['return_status'] == 'failed' and j['state'] == 'returned'
         and utc(reply['recorded_at']) <= utc(w['finished_at']) == utc(j['returned_at'])
         <= utc(j['finalization_ack_at']) <= utc(value['observed_at_pg'])
         and w['metadata']['capacity_dispatch_job_id'] == j['id']
         and w['metadata']['triggered_by'] == 'workflow_scheduler'
         and loads(j['envelope'])['workflow']['id'] == final_intent['workflow_id'],
         'EXACT_NORMAL_FINISH_FAILED_WORKFLOW_AND_FINAL_ACK')
    steps=w['result']['steps'];need(len(steps)==7 and len({x['id'] for x in steps})==7,
                                  'EXACT_NORMAL_FINISH_SEVEN_STEPS')
    steps={x['id']:x for x in steps};plan=steps['plan-original-guest'];retired=steps['retire-original-guest']
    need(plan['status']=='succeeded' and plan['metadata']['generation']==t['generation']
         and plan['metadata']['fencing_token']==t['fence']
         and plan['metadata']['lease_owner']==t['lease_owner']
         and retired['status']=='succeeded' and retired['metadata']['request_id']==request['id']
         and retired['metadata']['intent_sha256']==final_sha
         and retired['metadata']['native_poweroff_known'] is False
         and steps['finish-original-retirement']['status']=='failed'
         and all(steps[k]['status']=='skipped' for k in (
             'provision-original-notify','complete-original-provision',
             'refresh-original-membership','complete-original-retirement')),
         'FAILED_NORMAL_FINISH_NOT_FAILED_PLAN_OR_LIVE_FORWARD')
    return True



def maintenance_inputs97(C, c, raw):
    closed(c, 'schema source_R amd64_D core_preimage normal_finish_case schema_pins policy_state normal_finish_preimage_ref schema94_catalog_ref schema95_catalog_ref prior93_history_ref prior94_history_ref legacy_catalog_sql_ref acceptance_refs schema96_catalog_ref prior95_history_ref schema97_catalog_ref prior96_history_ref', 'CLOSED18_NORMAL_FINISH97_MAINTENANCE')
    need(c['schema'] == NORMAL_FINISH_SCHEMA and c['source_R'] == CORE_R == C.SOURCE_R
         and c['amd64_D'] == NEW_DIGEST == C.NEW_DIGEST and C.OLD_CORE_UID == UID
         and C.OLD_CORE_GENERATION == GENERATION and C.OLD_CORE_POD_UID == OLD_POD,
         'QUALIFIED_CORE8_AND_CURRENT_CORE7_PREIMAGE')
    p = c['core_preimage']
    closed(p, 'deployment_uid generation pod_uid container_id image_config_digest spec_sha256 annotations_sha256', 'CLOSED_CURRENT7_LIFETIME')
    need(p['deployment_uid'] == UID and p['generation'] == GENERATION and p['pod_uid'] == OLD_POD
         and p['container_id'] == OLD_CONTAINER_ID and p['image_config_digest'] == OLD_IMAGE_CONFIG_DIGEST
         and all(digest_value(p[k]) for k in ('spec_sha256','annotations_sha256')),
         'EXACT_CURRENT7_WHOLE_SPEC_AND_ANNOTATIONS')
    closed(c['acceptance_refs'], 'qualified_business_release business_Source_CI Root_Goose94_acceptance Root_Goose95_acceptance Root_Goose96_acceptance Root_Goose97_acceptance Root_separate_rollout_review current_Core7_operational_acceptance inventory_readonly_operational_acceptance', 'DISTINCT_ROOT97_CORE7_READER_TARGET_AND_HISTORICAL_ACCEPTANCES')
    for r in c['acceptance_refs'].values():
        need(len(input_ref(C,r)) > 1, 'ACTUAL_COMPLETE_PINNED_ACCEPTANCE_ORIGINAL')
    need(c['acceptance_refs']['Root_Goose97_acceptance']['sha256'] == ROOT97_SHA
         and digest_value(ROOT97_SHA), 'ACTUAL_ROOT97_NOT_FUTURE_OR_HISTORICAL_ALIAS')
    need(type(c['policy_state']) is dict and set(c['policy_state']) == {'aws','hetzner'}
         and all(type(v) is dict and set(v) == {'intent_identity','owned_slots','active_policies','policy_catalog_wire'}
                 for v in c['policy_state'].values()), 'BOTH_WHOLE_POLICY_ROSTERS_UNCHANGED')
    deployment_ready_inputs(C,c)
    validate_normal_finish97(loads(input_ref(C,c['normal_finish_preimage_ref'])),c['normal_finish_case'])
    sql = loads(input_ref(C,SQL_DATA_REF))
    need(sql['schema'] == 'fixed_policy_publication_schema92_SQL_data_v1'
         and set(sql['queries']) == {'original_notify_aws_vm_members','original_notify_hetzner_vm_members'},
         'EXACT_SOURCE_E70_QUERIES_WITHOUT_RECONSTRUCTION')
    return c, raw, sql


def schema97_facts(c, legacy, current, C):
    v, pins = legacy['schema_facts'], c['schema_pins']
    versions = [0] + [x for x in range(1,98) if x != 40]
    need(current['legacy']['database'] == v['database'] == 'yggdrasil'
         and current['legacy']['readonly'] == v['readonly'] == 'on'
         and current['legacy']['latest_versions'] == v['latest_versions'] == versions
         and v['history_max_version'] == 97 and v['rows90'] == v['rows91'] == v['rows92'] == 1
         and legacy['index89_valid'] is True and legacy['index92_valid'] is True,
         'EXACT97_HEAD_AND_OLD_INDEXES_NO_SCHEMA_ALIAS')
    closed(pins, 'complete_history_sha256 index92_definition_sha256 catalog90_91_sha256 schema94_catalog_sha256 schema95_catalog_sha256 schema96_catalog_sha256 constraint96_deparse_ref schema97_catalog_sha256 constraint97_deparse_ref', 'CLOSED97_CATALOG_HISTORY_PINS')
    need(all(digest_value(pins[k]) for k in pins if k not in ('constraint96_deparse_ref','constraint97_deparse_ref')),
         'REAL97_DIGEST_PINS')
    prior96_raw = input_ref(C,c['prior96_history_ref'])
    prior95_raw = input_ref(C,c['prior95_history_ref'])
    prior96, prior95 = loads(prior96_raw), loads(prior95_raw)
    full = loads(v['complete_history_wire'])
    need(loads(current['legacy']['complete_history_wire']) == full
         and len(full) == len(prior96) + 1 and [x for x in full if x['version_id'] != 97] == prior96
         and len([x for x in full if x['version_id'] == 97 and x['is_applied'] is True]) == 1
         and next(x['id'] for x in full if x['version_id'] == 97) > max(x['id'] for x in prior96)
         and all(x['is_applied'] is True for x in full)
         and sha(v['complete_history_wire'].encode()) == pins['complete_history_sha256'],
         'SOLE97_WHOLE_PRIOR96_HISTORY_RAW_VALUES_PRESERVED')
    need(len(prior96) == len(prior95) + 1
         and [x for x in prior96 if x['version_id'] != 96] == prior95
         and len([x for x in prior96 if x['version_id'] == 96 and x['is_applied'] is True]) == 1,
         'HISTORICAL96_SOLE_APPEND_TO95')
    prior96_catalog = loads(input_ref(C,c['schema96_catalog_ref']))
    prior95_catalog = loads(input_ref(C,c['schema95_catalog_ref']))
    actual = catalog94_projection(current)
    need(actual == loads(input_ref(C,c['schema97_catalog_ref']))
         and sha(C.wire(actual)) == pins['schema97_catalog_sha256']
         and sha(C.wire(prior96_catalog)) == pins['schema96_catalog_sha256']
         and sha(C.wire(prior95_catalog)) == pins['schema95_catalog_sha256']
         and sha(legacy['index92_definition'].encode()) == pins['index92_definition_sha256']
         and sha(C.wire({'catalog90':v['catalog90'],'catalog91':v['catalog91']})) == pins['catalog90_91_sha256'],
         'EXACT97_CATALOG_AND_DISTINCT_PRIOR96_95_ORIGINALS')
    prior_rows = [x for x in prior96_catalog['functions93'] if x['name'] == M96_FUNCTION]
    need(len(prior_rows) == 1 and sha(prior_rows[0]['body'].encode()) == M96_BODY_SHA, 'HISTORICAL96_EXACT_SOURCE_BODY')
    catalog96_delta(prior95_catalog,prior96_catalog,prior_rows[0]['body'],
                    constraint96_definition(prior95_catalog,loads(input_ref(C,pins['constraint96_deparse_ref']))))
    definitions = constraint97_definitions(prior96_catalog,pins['constraint97_deparse_ref'],lambda r:input_ref(C,r),CORE_R)
    functions = {}
    specs = {
        'guard_retirement_forward': {'arguments':'','result':'trigger','language':'plpgsql','volatility':'v','config':None},
        'retirement_forward_normal_finish_recovery_valid': {'arguments':'r jsonb, retirement uuid','result':'boolean','language':'plpgsql','volatility':'s','config':['TimeZone=UTC']},
    }
    for name in M97_FUNCTIONS:
        rows = [x for x in actual['functions93'] if x['name'] == name]
        need(len(rows) == 1 and sha(rows[0]['body'].encode()) == M97_FUNCTION_BODY_SHAS[name],
             'EXACT_IMMUTABLE97_SOURCE_BODY_' + name)
        functions[name] = {**specs[name],'body':rows[0]['body']}
    catalog97_delta(prior96_catalog,actual,functions,definitions)
    need(all(v[k] == 0 and current['legacy'][k] == 0 for k in ('other_migrators_ddl','other_cic','ddl_locks')),
         'NO_OTHER_MIGRATOR_CIC_OR_DDL_LOCK')
    refs = c['acceptance_refs']
    need(refs['Root_Goose95_acceptance']['sha256'] == ROOT95_SHA
         and refs['Root_Goose96_acceptance']['sha256'] == ROOT96_SHA
         and refs['Root_Goose97_acceptance']['sha256'] == ROOT97_SHA
         and refs['Root_Goose94_acceptance']['sha256'] == '3ad88f1ada8cc96db0d6c6b0c3844a4de070e18f458cd6b053ab3a468b90c5e4',
         'DISTINCT_UNREWRITTEN_ROOT94_95_96_AND_ACTUAL97')
    r95_raw, r96_raw = input_ref(C,refs['Root_Goose95_acceptance']), input_ref(C,refs['Root_Goose96_acceptance'])
    r95, r96 = loads(r95_raw), loads(r96_raw)
    need(r95['catalog95_sha256'] == pins['schema95_catalog_sha256']
         and r95['complete_history_sha256'] == sha(prior95_raw)
         and r95['prior94_history_sha256'] == sha(input_ref(C,c['prior94_history_ref']))
         and sha(C.wire(loads(input_ref(C,c['schema94_catalog_ref'])))) == pins['schema94_catalog_sha256'],
         'HISTORICAL95_AND94_RECEIPTS_AND_WHOLE_HISTORY')
    root96_overlay(r96_raw,r95_raw,{
        'current_ops_source':ROOT96_HISTORICAL_OPS_SOURCE,
        'business_source':ROOT96_HISTORICAL_BUSINESS_SOURCE,'amd64_D':ROOT96_HISTORICAL_AMD64_D,
        'complete_history_sha256':sha(prior96_raw),'prior95_history_sha256':sha(prior95_raw),
        'catalog96_sha256':pins['schema96_catalog_sha256'],
        'index92_definition_sha256':pins['index92_definition_sha256'],
        'catalog90_91_sha256':sha(C.wire({'catalog90':prior96_catalog['catalog90'],'catalog91':prior96_catalog['catalog91']}))
    },lambda r:input_ref(C,r))
    root97_overlay(input_ref(C,refs['Root_Goose97_acceptance']),r96_raw,{
        'current_ops_source':G15_OPS_P,'business_source':CORE_R,'amd64_D':NEW_DIGEST,
        'complete_history_sha256':pins['complete_history_sha256'],
        'prior96_history_sha256':sha(prior96_raw),'catalog97_sha256':pins['schema97_catalog_sha256'],
        'index92_definition_sha256':pins['index92_definition_sha256'],
        'catalog90_91_sha256':pins['catalog90_91_sha256']
    },lambda r:input_ref(C,r))


def database_normal_finish97(cut, run, c, sql, label):
    require_bound()
    result = {}
    case = c['normal_finish_case']
    for provider,key in (('aws','original_notify_aws_vm_members'),('hetzner','original_notify_hetzner_vm_members')):
        value = query(cut,run,label+'-'+provider.upper(),sql['queries'][key])
        need(all(value[k] == c['policy_state'][provider][k] for k in (
                 'intent_identity','owned_slots','active_policies','policy_catalog_wire')),
             'ALL_OTHER_POLICY_AND_ROSTER_BYTES_EXACT')
        lanes = {k:value[k] for k in ('jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries','intent_count','intent_busy','pending_authority','forward_markers')}
        need(all(type(v) is int for v in lanes.values())
             and lanes == case['provider_lanes'][provider] and lanes['intent_count'] == 1
             and all(type(lanes[k]) is int and lanes[k] == 0 for k in (
                 'jobs_busy','runs_busy','forward_unreturned_reads','live_unreturned_canaries'))
             and lanes['forward_markers'] == lanes['pending_authority'] == 0
             and type(lanes['intent_busy']) is int and lanes['intent_busy'] in (0,1),
             'EXACT_NORMAL_FINISH_QUIET_NO_FORWARD_OR_GUESSED_LANES')
        result[provider] = lanes
    actual = query(cut,run,label+'-NORMAL-FINISH',NORMAL_FINISH_SQL)
    validate_normal_finish97(actual,case)
    need(actual['records_wire'] == loads(input_ref(cut.C,c['normal_finish_preimage_ref']))['records_wire'],
         'WHOLE_NORMAL_FINISH_ORIGINALS_UNCHANGED_BEFORE_PRESEND')
    current = query(cut,run,label+'-SCHEMA97',catalog97_select(input_ref(cut.C,c['legacy_catalog_sql_ref']).decode()))
    first = query(cut,run,label+'-SOURCE-SCHEMA97',sql['queries']['original_notify_aws_vm_members'])
    schema97_facts(c,first,current,cut.C)
    return result


if __name__=="__main__":main()
