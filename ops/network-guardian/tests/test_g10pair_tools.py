"""Closed G10 derivation and real cutover sequencing with declared CI operands."""
import copy
import unittest
from unittest.mock import patch

import test_g7pair_cutover as historical
import test_g10pair_source as source

G, C, D, S, cut = source.G, source.C, source.D, source.S, source.CUT


class G10ToolTests(unittest.TestCase):
    def test_controller_derivation_changes_exactly_image_pair_and_review(self):
        r42, prefix = source.old_tools.controller_inputs()
        previous = D.strict_loads(prefix[-1])
        previous['core_container_images'] = D.G9_CORE_IMAGE_PAIRS
        previous['root_review_attestation'] = 'Declared prior G9 CI controller operand; no actual installed config claim. ' * 3
        g9raw = D.canonical(previous)
        review = 'Declared new G10 CI controller operand; no Root approval or native adoption. ' * 3
        with source.binding():
            expected = copy.deepcopy(previous)
            expected['core_container_images'] = G.G10_CORE_IMAGE_PAIRS
            expected['root_review_attestation'] = review
            chain = (*D.PAIR_CHAIN[:-2], ('g9pair', D.G9_CORE_IMAGE_PAIRS, D.G9_CONFIG, source.digest(g9raw)),
                     ('g10pair', G.G10_CORE_IMAGE_PAIRS, D.G10_CONFIG, None))
            with patch.multiple(D, PROPOSAL_BOUND=True, HEAD_NEW_CORE_DIGEST=G.HEAD_NEW_CORE_DIGEST,
                CORE_G10=G.CORE_G10, G10_CORE_IMAGE_PAIRS=G.G10_CORE_IMAGE_PAIRS,
                G10_CONFIG_SHA=source.digest(D.canonical(expected)), PAIR_CHAIN=chain):
                raw=D.derive(r42,[*prefix,g9raw],review)
                self.assertEqual(D.strict_loads(raw),expected)
                self.assertEqual({k for k in previous if previous[k]!=expected[k]}, {'core_container_images','root_review_attestation'})
                for index in range(len(prefix)+1):
                    changed=[*prefix,g9raw]; changed[index]+=b' '
                    with self.subTest(index=index),self.assertRaises(D.Refused): D.derive(r42,changed,review)
                with self.assertRaises(D.Refused): D.derive(r42,[*prefix,g9raw],previous['root_review_attestation'])

    def test_standing_derivation_adds_only_g9_axis_and_seven_head_fields(self):
        controller_raw=b'{"declared":"G10 CI controller"}\n';hub_raw=b'{"declared":"unchanged CI hub"}\n'
        with source.binding(), patch.object(G,'G10_CONTROLLER_CONFIG_SHA',source.digest(controller_raw)), \
                patch.object(S.C,'HEAD_CONFIG_SHA',source.digest(controller_raw)):
            old=source.g9_operand();old['hub_boot_config_sha256']=source.digest(hub_raw)
            units={S.C.CTRL:source.digest(b'new controller'),S.C.HUB:old['hub_unit_sha256'],
                   S.C.COLD:source.digest(b'new cold future unit'),S.C.GUARD:source.digest(b'new guardian unit')}
            m={'files':{'source/network_guardian.py':source.digest(b'declared G10 source')}}
            review='Declared CI standing review, never generated actual Root approval. '*4
            value=S.build(G,m,old,controller_raw,hub_raw,review,units)
            self.assertEqual(set(value)-set(old),{'g9_predecessor_guardian_source_sha256','g9_predecessor_standing_config_sha256'})
            self.assertEqual({k for k in old if old[k]!=value[k]}, {'schema','guardian_source_sha256','controller_unit_sha256',
                'cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','Root_review'})
            for key in ('guardian_source_sha256','new_controller_config_sha256','g6_predecessor_guardian_source_sha256'):
                wrong=copy.deepcopy(old);wrong[key]='1'*64
                with self.subTest(key=key),self.assertRaises(S.C.Hold):S.build(G,m,wrong,controller_raw,hub_raw,review,units)

    def test_unbound_deriver_and_cutover_cannot_submit(self):
        with patch.object(D,'PROPOSAL_BOUND',False),patch.object(D,'read_private') as read:
            with self.assertRaises(D.Refused):D.derive(b'{}',[],'declared')
            read.assert_not_called()
        with patch.object(cut.C,'PROPOSAL_BOUND',False),patch.object(cut,'native') as native,patch.object(cut,'custody') as custody:
            with self.assertRaises(cut.C.Hold):cut.swap_once(object())
            with self.assertRaises(cut.C.Hold):cut.main()
            native.assert_not_called();custody.assert_not_called()


class G10CutoverTests(unittest.TestCase):
    def assert_prefix(self, backend, length):
        return historical.G7CutoverTests.assert_prefix(self,backend,length)

    def reuse(self,name):
        with source.binding(),patch.object(historical,'cut',cut):
            getattr(historical.G7CutoverTests,name)(self)

    def test_six_actual_positions_custody_unknown_ack_and_no_retry(self):
        for name in ('test_real_cli_success_uses_only_six_fixed_native_submissions',
            'test_closed_native_boundary_refuses_unknown_or_changed_effect',
            'test_native_timeout_retains_possible_and_uncertain_original_return',
            'test_native_nonzero_is_failure_without_forward_or_compensating_actions',
            'test_possible_send_persistence_failure_prevents_that_native_call',
            'test_return_persistence_failure_keeps_possible_without_replay',
            'test_guard_cas_readiness_and_qualification_failures_hold_at_exact_prefix',
            'test_uncertain_attempt_cannot_reenter_or_replace_original_claim',
            'test_hold_record_failure_never_triggers_a_cleanup_or_retry'):
            with self.subTest(corpus=name):self.reuse(name)

    def test_exclusive_claim_and_readonly_close_preserve_originals(self):
        for name in ('test_real_once_writer_is_exclusive_durable_and_never_overwrites',
            'test_real_backend_global_claim_survives_another_evidence_directory',
            'test_actual_backend_close_only_joins_read_observers'):
            with self.subTest(corpus=name):self.reuse(name)

    def test_bounded_process_identities_no_cold_hub_execution(self):
        for name in ('test_real_absence_guard_accepts_retained_terminal_pid_and_refuses_live_identity',
            'test_real_type_simple_wait_handles_only_one_bounded_fork_exec_lifetime',
            'test_actual_backend_final_closure_rechecks_both_physical_processes',
            'test_real_shared_parent_accepts_0755_without_chmod_and_refuses_writes_or_links'):
            with self.subTest(corpus=name):self.reuse(name)
