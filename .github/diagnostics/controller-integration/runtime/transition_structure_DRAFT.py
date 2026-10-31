"""LAB source-only closed structural validator, not an operational Guardian.

It proves neither xt program identity nor provenance of gate handles. The
caller must separately supply a trustworthy native receipt binding every gate
rule and its frozen program; this module deliberately cannot manufacture it.
"""
import copy
import hashlib
import json

import native_structure as baseline
import nft_owner as nft


class Rejected(Exception):
    pass


def require(value, code):
    if not value:
        raise Rejected(code)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _owned(data):
    try:
        rows, _ = baseline._objects(data)
        return rows
    except (ValueError, TypeError, nft.Held) as exc:
        raise Rejected('INVALID_NFT_JSON') from exc


def _structure(rows):
    try:
        return baseline._structure(rows, keep_handles=True)
    except (ValueError, TypeError, KeyError, nft.Held) as exc:
        raise Rejected('INVALID_BASELINE_STRUCTURE') from exc


def _handle(row):
    kind = next(iter(row))
    return row[kind]['handle']


class OriginalPin:
    """Private in-process original 47-object pin, not decoded from a caller."""
    def __init__(self, raw):
        self.rows = _owned(raw)
        self.digest = _digest(_structure(self.rows))
        try:
            unhandled = _digest(baseline._structure(self.rows, keep_handles=False))
        except (ValueError, TypeError, KeyError, nft.Held) as exc:
            raise Rejected('INVALID_COMPILED_AST') from exc
        require(unhandled == baseline.COMPILED_NATIVE_AST_SHA256, 'NOT_REVIEWED_BASELINE_AST')
        self.handles = frozenset(_handle(row) for row in self.rows if next(iter(row)) != 'chain')
        self.chain_handles = frozenset(_handle(row) for row in self.rows if 'chain' in row)
        require(len(self.rows)==47, 'NOT_47')


def verify_original(pin, raw):
    require(type(pin) is OriginalPin, 'ORIGINAL_PIN_REQUIRED')
    rows = _owned(raw)
    require(len(rows)==47 and _digest(_structure(rows))==pin.digest, 'ORIGINAL_PIN_MISMATCH')
    return {'schema':'lab_original_47_shape_v1', 'count':47, 'production_authority':False}


def verify_guarded(pin, raw, *, observed_chain_handle, observed_rule_handles):
    """Validate exact old structure + narrowly described, observed LAB gate.

    `observed_*` must come from independently checked kernel-native receipts,
    never a request or configuration. This draft is shape-only; the provision
    of valid program provenance is a separate mandatory gate.
    """
    require(type(pin) is OriginalPin, 'ORIGINAL_PIN_REQUIRED')
    require(type(observed_chain_handle) is int and observed_chain_handle>0, 'CHAIN_HANDLE_REQUIRED')
    require(type(observed_rule_handles) is tuple and len(observed_rule_handles)==2
            and all(type(v) is int and v>0 for v in observed_rule_handles)
            and len(set(observed_rule_handles))==2, 'EXACT_TWO_OBSERVED_RULE_HANDLES')
    rows = _owned(raw)
    require(len(rows)==50, 'NOT_EXACTLY_50')
    gate_chains=[];gate_rules=[];base=[];changed=0
    for item in copy.deepcopy(rows):
        kind=next(iter(item));v=item[kind]
        if kind=='chain' and v.get('name')=='admit_deadline':
            require(set(v)=={'family','table','name','handle'} and v['handle']==observed_chain_handle,
                    'EXACT_GATE_CHAIN')
            gate_chains.append(v);continue
        if kind=='rule' and v.get('chain')=='admit_deadline':
            require(set(v)=={'family','table','chain','handle','expr'}
                    and v['expr']==[{'xt':None},{'jump':{'target':'admit_new'}}], 'EXACT_GATE_RULE_EXPR')
            gate_rules.append(v['handle']);continue
        if kind=='rule':
            for e in v.get('expr',[]):
                if type(e) is dict and e.get('jump')=={'target':'admit_deadline'}:
                    require(v.get('chain')=='forward_guard', 'GATE_JUMP_WRONG_CHAIN')
                    e['jump']['target']='admit_new';changed+=1
        base.append(item)
    require(len(gate_chains)==1 and tuple(gate_rules)==observed_rule_handles, 'EXACT_ORDERED_GATE_HANDLES')
    require(changed==3 and len(base)==47, 'ONLY_THREE_FORWARD_JUMPS')
    require(_digest(_structure(base))==pin.digest, 'BASELINE_OR_HANDLES_CHANGED')
    require(observed_chain_handle not in pin.handles and not (set(observed_rule_handles)&pin.handles)
            and observed_chain_handle not in pin.chain_handles
            and observed_chain_handle not in observed_rule_handles, 'NEW_HANDLES_MUST_BE_DISTINCT')
    return {'schema':'lab_guarded_50_shape_v1','count':50,'gate_rule_count':2,
            'program_provenance_verified':False,'production_authority':False}
