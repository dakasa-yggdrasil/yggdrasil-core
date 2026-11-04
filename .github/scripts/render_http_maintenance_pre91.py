#!/usr/bin/env python3
"""Render data-only pre91 observation SQL from the seven migration91 bodies.

No SQL, product import, network, subprocess or schema operation is performed.
The generated query requires a READ ONLY UTC transaction on schema89 or later.
It observes admission operands; the new Core process barrier and full Go ADR94
validator remain separate requirements of the actual disposition transaction.
"""
import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / 'db/migrations/00091_recorded_http_maintenance_dispatch_dispositions.sql'
OUTPUT = ROOT / 'ops/http-maintenance/http_maintenance_pre91.sql'
PREFIX = 'http_maintenance_dispatch_'
PRIVATE = '__r6_pre91_'
SOURCE_CAP = 128 << 10
OUTPUT_CAP = 1 << 20
FUNCTIONS = {
    PREFIX + 'result_valid': (('result', 'jsonb'), ('generation', 'text'), ('fence', 'text')),
    PREFIX + 'policy_projection': (('input_spec', 'jsonb'),),
    PREFIX + 'policy_continuous': (('prior_id', 'uuid'), ('prior_checksum', 'text'), ('current_id', 'uuid'), ('current_checksum', 'text')),
    PREFIX + 'members': (('job', 'uuid'),),
    PREFIX + 'effect_scan': (('job', 'uuid'),),
    PREFIX + 'effect_scan_tolerable': (('scan', 'jsonb'),),
    PREFIX + 'admission_valid': (('job', 'uuid'),),
}
LEGACY_CALLS = {'finalization_lost_dispatch_effect_scan', 'finalization_lost_dispatch_effect_scan_tolerable'}
BUILTINS = {'coalesce', 'jsonb_typeof', 'jsonb_array_length', 'jsonb_array_elements', 'jsonb_agg',
            'jsonb_build_object', 'jsonb_each', 'unnest', 'encode', 'sha256', 'convert_to',
            'num_nonnulls', 'clock_timestamp', 'statement_timestamp', 'count', 'min', 'trunc', 'to_jsonb'}
SQL_PARENS = {'exists', 'in', 'not', 'from', 'as', 'values', 'select', 'where', 'and', 'or', 'join', 'when', 'then', 'else'}
FORBIDDEN = {'insert', 'update', 'delete', 'merge', 'create', 'alter', 'drop', 'truncate', 'copy',
             'call', 'do', 'execute', 'grant', 'revoke', 'vacuum', 'analyze', 'set', 'reset', 'into'}


def need(value, message):
    if not value:
        raise ValueError(message)


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    start: int
    end: int


def tokens(text):
    """Closed lexical scanner. Quoted text/comments are never rewritten."""
    result, pos = [], 0
    while pos < len(text):
        start = pos
        if text[pos] in ' \t\r\n':
            pos += 1
            continue
        if text.startswith('--', pos):
            end = text.find('\n', pos)
            pos = len(text) if end < 0 else end + 1
            continue
        if text.startswith('/*', pos):
            depth, pos = 1, pos + 2
            while depth:
                need(pos < len(text), 'unterminated block comment')
                if text.startswith('/*', pos):
                    depth, pos = depth + 1, pos + 2
                elif text.startswith('*/', pos):
                    depth, pos = depth - 1, pos + 2
                else:
                    pos += 1
            continue
        if text[pos] in "'\"":
            quote = text[pos]
            pos += 1
            while True:
                need(pos < len(text), 'unterminated quoted token')
                if text[pos] == quote:
                    pos += 1
                    if pos < len(text) and text[pos] == quote:
                        pos += 1
                        continue
                    break
                pos += 1
            result.append(Token('string' if quote == "'" else 'quoted', text[start:pos], start, pos))
            continue
        dollar = re.match(r'\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$', text[pos:])
        if dollar:
            tag = dollar.group()
            end = text.find(tag, pos + len(tag))
            need(end >= 0, 'unterminated dollar quote')
            pos = end + len(tag)
            result.append(Token('dollar', text[start:pos], start, pos))
            continue
        word = re.match(r'[A-Za-z_][A-Za-z_0-9]*', text[pos:])
        if word:
            pos += len(word.group())
            result.append(Token('word', text[start:pos], start, pos))
            continue
        number = re.match(r'[0-9]+(?:\.[0-9]+)?', text[pos:])
        if number:
            pos += len(number.group())
            result.append(Token('number', text[start:pos], start, pos))
            continue
        operator = re.match(r'(?:#>>|->>|::|->|#>|<>|<=|>=|\|\||[().,;\[\]+*/%=<>~!?|&^:\-])', text[pos:])
        need(operator is not None, 'unsupported SQL character at offset ' + str(pos))
        pos += len(operator.group())
        result.append(Token('symbol', text[start:pos], start, pos))
    return result


def extract(source):
    ts, found = tokens(source), {}
    for i in range(len(ts) - 7):
        if [t.text.lower() for t in ts[i:i + 6]] != ['create', 'or', 'replace', 'function', 'public', '.']:
            continue
        name = ts[i + 6].text
        if not name.startswith(PREFIX):
            continue
        need(name in FUNCTIONS and name not in found and ts[i + 7].text == '(', 'unknown or duplicate target function')
        close = i + 8
        while close < len(ts) and ts[close].text != ')':
            need(ts[close].text != '(', 'unsupported parameter declaration')
            close += 1
        need(close < len(ts), 'missing function parameters end')
        declaration = [t.text.lower() for t in ts[i + 8:close]]
        expected = []
        for index, (parameter, typ) in enumerate(FUNCTIONS[name]):
            if index:
                expected.append(',')
            expected += [parameter, typ]
        need(declaration == expected, 'changed function signature: ' + name)
        tail, j = [], close + 1
        while j < len(ts) and ts[j].kind != 'dollar':
            tail.append(ts[j].text.lower())
            j += 1
        need(j + 1 < len(ts) and ts[j + 1].text == ';', 'missing whole function body')
        returns = 'jsonb' if name.endswith(('policy_projection', 'members', 'effect_scan')) else 'boolean'
        need(len(tail) in (6, 10) and tail[:2] == ['returns', returns]
             and tail[2:4] == ['language', 'sql'] and tail[4] in ('immutable', 'stable') and tail[-1] == 'as', 'unsupported function attributes')
        if len(tail) == 10:
            need(tail[5:9] == ['set', 'timezone', '=', "'utc'"], 'only UTC function setting supported')
        literal = ts[j].text
        need(literal.startswith('$$') and literal.endswith('$$'), 'only exact migration dollar body supported')
        body = literal[2:-2]
        validate_body(body)
        found[name] = body
    need(set(found) == set(FUNCTIONS), 'exactly seven Source SQL functions required')
    return found


def validate_body(body):
    ts = tokens(body)
    need(ts and ts[0].text.lower() in ('select', 'with'), 'only scalar SELECT/WITH body supported')
    need(PRIVATE not in body, 'reserved generated alias collision')
    need(not any(t.kind in ('dollar', 'quoted') or t.text == ';' for t in ts), 'unsupported body statement or quoted identifier')
    need(not any(t.kind == 'word' and t.text.lower() in FORBIDDEN for t in ts), 'body must be read-only SQL')
    depth = 0
    for i, token in enumerate(ts):
        if token.text == '(':
            depth += 1
        elif token.text == ')':
            depth -= 1
            need(depth >= 0, 'unbalanced body')
        if token.kind != 'word' or i + 1 >= len(ts) or ts[i + 1].text != '(':
            continue
        word = token.text.lower()
        if i and ts[i - 1].text == '.':
            need(i >= 2 and ts[i - 2].text.lower() == 'public' and word in set(FUNCTIONS) | LEGACY_CALLS, 'unknown qualified function')
        elif i and ts[i - 1].text.lower() in (')', 'ordinality'):
            continue  # Source derived-row alias with an explicit column list.
        else:
            need(word in BUILTINS | SQL_PARENS, 'unsupported scalar function or alias: ' + word)
    need(depth == 0, 'unbalanced body')


class Expander:
    def __init__(self, bodies):
        self.bodies, self.serial = bodies, 0

    def call(self, name, arguments, chain=()):
        need(name in self.bodies and name not in chain and len(chain) < 8, 'unknown or recursive function dependency')
        signature = FUNCTIONS[name]
        need(len(arguments) == len(signature), 'function argument count mismatch')
        self.serial += 1
        alias = PRIVATE + 'args_' + str(self.serial)
        bindings = {parameter: alias + '.p' + str(i) for i, (parameter, _) in enumerate(signature)}
        body, ts, replacements = self.bodies[name], tokens(self.bodies[name]), []
        for i, token in enumerate(ts):
            if token.kind != 'word' or token.text.lower() not in bindings:
                continue
            if (i and ts[i - 1].text == '.') or (i + 1 < len(ts) and ts[i + 1].text == '.'):
                continue  # A qualified column is never a formal parameter.
            need(not i or ts[i - 1].text.lower() not in ('as', 'from', 'join', 'with'), 'formal parameter shadows an alias')
            replacements.append((token.start, token.end, bindings[token.text.lower()]))
        for start, end, value in reversed(replacements):
            body = body[:start] + value + body[end:]
        body = self.expand(body, chain + (name,))
        arguments_sql = ', '.join('(' + argument + ')::' + typ + ' AS p' + str(i)
                                  for i, (argument, (_, typ)) in enumerate(zip(arguments, signature)))
        # Bind outside the Source body so its local j/p/spec aliases cannot
        # capture a caller argument. MATERIALIZED evaluates each operand once.
        return '(WITH ' + alias + ' AS MATERIALIZED (SELECT ' + arguments_sql + ') SELECT (' + body + ') FROM ' + alias + ')'

    def expand(self, sql, chain=()):
        ts, changes, i = tokens(sql), [], 0
        while i < len(ts) - 3:
            if ts[i].text.lower() != 'public' or ts[i + 1].text != '.' or ts[i + 2].text not in FUNCTIONS or ts[i + 3].text != '(':
                i += 1
                continue
            name, first, depth, parts, k = ts[i + 2].text, ts[i + 3].end, 1, [], i + 4
            while k < len(ts):
                if ts[k].text == '(':
                    depth += 1
                elif ts[k].text == ')':
                    depth -= 1
                    if depth == 0:
                        parts.append(sql[first:ts[k].start])
                        break
                elif ts[k].text == ',' and depth == 1:
                    parts.append(sql[first:ts[k].start])
                    first = ts[k].end
                k += 1
            need(k < len(ts) and all(part.strip() for part in parts), 'unclosed or empty function arguments')
            arguments = [self.expand(part, chain) for part in parts]
            changes.append((ts[i].start, ts[k].end, self.call(name, arguments, chain)))
            i = k + 1
        for start, end, value in reversed(changes):
            sql = sql[:start] + value + sql[end:]
        need(len(sql.encode()) <= OUTPUT_CAP, 'expanded SQL exceeds bound')
        return sql


def render(raw):
    need(0 < len(raw) <= SOURCE_CAP, 'bounded migration Source required')
    source = raw.decode('utf-8')
    bodies = extract(source)
    expander = Expander(bodies)
    scan = expander.call(PREFIX + 'effect_scan', [PRIVATE + 'input.job_id'])
    admission = expander.call(PREFIX + 'admission_valid', [PRIVATE + 'input.job_id'])
    header = ['-- Generated from migration91 SQL bodies; do not hand-edit.',
              '-- Source SHA256: ' + hashlib.sha256(raw).hexdigest(),
              '-- READ ONLY UTC transaction required; no new-process barrier or full Go ADR94 proof.',
              '-- Two independent Source scan expansions are preserved; no inferred memoization.']
    header += ['-- ' + name + ': ' + hashlib.sha256(bodies[name].encode()).hexdigest() for name in FUNCTIONS]
    sql = '\n'.join(header) + '''
WITH __r6_pre91_input AS MATERIALIZED (
 SELECT $1::uuid AS job_id
 WHERE current_setting('transaction_read_only')='on' AND current_setting('TimeZone')='UTC'
  AND current_setting('standard_conforming_strings')='on'
), __r6_pre91_scan AS MATERIALIZED (
 SELECT ''' + scan + ''' AS effect_scan FROM __r6_pre91_input
)
SELECT jsonb_build_object(
 'observed_at_pg',clock_timestamp(),'job_id',j.id,'run_id',j.run_id,
 'original_dispatch_sha256',CASE WHEN j.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(j)::text,'UTF8')),'hex') END,
 'original_run_sha256',CASE WHEN w.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') END,
 'cas',jsonb_build_object('job_id',j.id,'expected_run_id',j.run_id,'expected_envelope_sha256',j.envelope_sha256,
  'expected_fencing_token',j.fencing_token,'expected_lease_owner',j.lease_owner,'expected_pending_wake_count',j.pending_wake_count,
  'expected_returned_at',j.returned_at,
  'expected_run_sha256',CASE WHEN w.id IS NOT NULL THEN encode(sha256(convert_to(to_jsonb(w)::text,'UTF8')),'hex') END,
  'expected_members_sha256',__r6_pre91_scan.effect_scan->>'current_members_sha256'),
 'effect_scan',__r6_pre91_scan.effect_scan,'admission',COALESCE(''' + admission + ''',false))
FROM __r6_pre91_input CROSS JOIN __r6_pre91_scan
LEFT JOIN public.capacity_dispatch_jobs j ON j.id=__r6_pre91_input.job_id
LEFT JOIN public.workflow_runs w ON w.id=j.run_id;
'''
    need(sql.count('$1::uuid') == 1 and not re.search(r'public\.' + PREFIX, sql), 'unique input and complete expansion required')
    need(0 < len(sql.encode()) <= OUTPUT_CAP, 'bounded final SQL required')
    return sql.encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='compare the existing artifact without writing')
    args = parser.parse_args()
    raw = render(MIGRATION.read_bytes())
    if args.check:
        need(OUTPUT.read_bytes() == raw, 'generated SQL differs from current migration bodies')
    else:
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(OUTPUT, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        try:
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                need(written > 0, 'full artifact write required')
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        parent = os.open(OUTPUT.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    print('artifact bytes=' + str(len(raw)) + ' sha256=' + hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    main()
