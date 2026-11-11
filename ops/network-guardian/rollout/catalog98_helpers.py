"""Pure schema98 DATA helpers; no IO, execution, qualification or acceptance writes.

The embedding consumer supplies its unchanged qualified catalog97_select callable.
read_ref is a custody reader; every returned whole byte string is rehashed here.
This module deliberately has no activation entry point or product imports.
"""
import copy
import hashlib
import json
import re
from pathlib import PurePosixPath

SOURCE_BOUND = False
QUALIFIED_SOURCE = None
M98 = 'a739323d44b526beeef229c9faa17d0e8d27a2460028835e6fe7650b60b1904f'
ROOT97_SHA = '896eb09327ecdabb823957c37266774e94ab72b3afd2875a1775d30536e754c9'
CURRENT_CORE8 = '0764e6b267d3d6ddbfb4d7a4b9fb4024018bf89f'
CAP = 8 * 1024 * 1024
TABLE98 = 'capacity_dispatch_installed_provision_timeout_dispositions'
FUNCTIONS98 = (
    'installed_provision_timeout_valid', 'guard_installed_provision_timeout_insert',
    'check_installed_provision_timeout_transition', 'guard_capacity_dispatch_job',
    'guard_installed_provision_timeout_job_insert', 'immutable_installed_provision_timeout',
    'guard_installed_provision_timeout_workflow', 'require_installed_provision_timeout_links',
    'guard_installed_timeout_origin')
OLD_CHECKS98 = ('capacity_dispatch_jobs_lifecycle_v9_check', 'capacity_dispatch_jobs_state_v9_check')
NEW_CHECKS98 = ('capacity_dispatch_jobs_lifecycle_v10_check', 'capacity_dispatch_jobs_state_v10_check')
OLD7 = 'catalog90 catalog91 columns90_91 functions93 index92_definition index92_valid schema94'


def need98(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def closed98(value, keys, reason):
    need98(type(value) is dict and set(value) == set(keys.split()), reason)
    return value


def sha98(raw):
    need98(type(raw) is bytes, 'WHOLE98_BYTES')
    return hashlib.sha256(raw).hexdigest()


def same98(left, right):
    """JSON identity retains array order and distinguishes booleans from numbers."""
    return json.dumps(left, sort_keys=True, separators=(',', ':'), allow_nan=False) == json.dumps(
        right, sort_keys=True, separators=(',', ':'), allow_nan=False)


def loads98(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            need98(key not in value, 'NO_DUPLICATE98_JSON_KEY')
            value[key] = item
        return value
    def nonfinite(value):
        raise RuntimeError('NO_NONFINITE98_JSON_' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def digest98(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None


def source98(value):
    return type(value) is str and re.fullmatch('[0-9a-f]{40}', value) is not None


def original98(ref, read_ref, with_size=False):
    closed98(ref, 'path sha256 bytes' if with_size else 'path sha256', 'CLOSED98_ORIGINAL_REF')
    need98(type(ref['path']) is str and PurePosixPath(ref['path']).is_absolute()
           and '..' not in PurePosixPath(ref['path']).parts and digest98(ref['sha256']),
           'ABSOLUTE98_WHOLE_ORIGINAL_REF')
    raw = read_ref(ref)
    need98(type(raw) is bytes and 1 < len(raw) <= CAP and sha98(raw) == ref['sha256'],
           'COMPLETE98_ORIGINAL_HASH_AND_CAP')
    if with_size:
        need98(type(ref['bytes']) is int and ref['bytes'] == len(raw), 'ACTUAL98_ORIGINAL_SIZE')
    return raw


def projection97_98(value):
    """The unchanged old seven-key stable projection, from genuine full raw DATA."""
    need98(type(value) is dict and type(value.get('legacy')) is dict
           and type(value.get('supplement')) is dict, 'FULL98_LEGACY_AND_SUPPLEMENT')
    legacy, supplement = value['legacy'], value['supplement']
    schema94 = value['schema94']
    closed98(schema94, 'tables columns constraints indexes triggers functions', 'CLOSED98_RETAINED_SCHEMA94')
    need98(all(type(rows) is list for rows in schema94.values()), 'RETAINED98_SCHEMA94_ARRAYS')
    return {'catalog90': legacy['catalog90'], 'catalog91': legacy['catalog91'],
            **{key: supplement[key] for key in ('columns90_91', 'functions93', 'index92_valid', 'index92_definition')},
            'schema94': schema94}


def catalog98_projection(rawFull):
    supplement98(rawFull['schema98'])
    return {**projection97_98(rawFull), 'schema98': rawFull['schema98']}


def catalog98_select(legacy, base_select=None):
    """Compose only SELECTs inside the consumer's unchanged RR/RO read wrapper."""
    selector = base_select if base_select is not None else globals().get('catalog97_select')
    need98(callable(selector), 'EXACT_QUALIFIED_CATALOG97_SELECTOR_REQUIRED')
    sql = selector(legacy)
    old = "c.conname IN('capacity_dispatch_jobs_state_v8_check','capacity_dispatch_jobs_lifecycle_v8_check','capacity_dispatch_jobs_state_v9_check','capacity_dispatch_jobs_lifecycle_v9_check')"
    need98(type(sql) is str and sql.count(old) == 1, 'ONE98_DISPATCH_SELECTOR_IN_AUTHENTICATED_C9')
    replacement = old[:-1] + ",'capacity_dispatch_jobs_state_v10_check','capacity_dispatch_jobs_lifecycle_v10_check')"
    sql = sql.replace(old, replacement, 1)
    return ('WITH old97(v) AS (' + sql + '), supplement98(v) AS (' + SUPPLEMENT98_SQL
            + '), structure98(v) AS (' + STRUCTURE98_SQL + ') SELECT (SELECT v FROM old97)'
            + " || jsonb_build_object('schema98',(SELECT v FROM supplement98),'structural98',(SELECT v FROM structure98))")


def supplement98(value):
    closed98(value, 'functions constraints triggers columns', 'CLOSED98_FOUR_CATALOG_ARRAYS')
    shapes = {'functions': 'name arguments definition',
              'constraints': 'table name kind validated definition',
              'triggers': 'table name enabled definition',
              'columns': 'table name number type not_null'}
    for kind, keys in shapes.items():
        rows = value[kind]
        need98(type(rows) is list, 'FULL98_' + kind)
        identities = []
        for row in rows:
            closed98(row, keys, 'CLOSED98_' + kind + '_ROW')
            need98(type(row['name']) is str and row['name'], 'NAMED98_' + kind)
            identity = (row['name'], row['arguments']) if kind == 'functions' else (row['table'], row['name'])
            identities.append(identity)
            if kind in ('functions', 'constraints', 'triggers'):
                need98(type(row['definition']) is str and row['definition'], 'FULL98_DEFINITION')
            if kind == 'functions':
                need98(type(row['arguments']) is str, 'TYPED98_FUNCTION_IDENTITY')
            if kind == 'constraints':
                need98(row['validated'] is True and type(row['kind']) is str, 'VALIDATED98_CONSTRAINT')
            if kind == 'triggers':
                need98(row['enabled'] == 'O', 'ENABLED98_TRIGGER')
            if kind == 'columns':
                need98(type(row['number']) is int and row['number'] > 0
                       and type(row['type']) is str and type(row['not_null']) is bool, 'TYPED98_COLUMN')
        need98(len(identities) == len(set(identities)), 'NO_DUPLICATE98_' + kind)
        key = (lambda row: (row['name'], row['arguments'])) if kind == 'functions' else (
            (lambda row: (row['table'], row['number'])) if kind == 'columns' else
            (lambda row: (row['table'], row['name'])))
        need98(rows == sorted(rows, key=key), 'DECLARED98_QUERY_ORDER_' + kind)
    return value


def migration98_functions(sql):
    need98(type(sql) is str and sha98(sql.encode()) == M98, 'EXACT98_MIGRATION_SOURCE')
    up, down = sql.split('-- +goose Down', 1)
    pattern = r'CREATE OR REPLACE FUNCTION public\.([a-z_]+)\((.*?)\)\s*RETURNS\s+(.*?)\s+LANGUAGE plpgsql(.*?)\s+AS \$\$(.*?)\$\$;'
    def collect(text):
        result = {}
        for name, arguments, returns, options, body in re.findall(pattern, text, re.S):
            need98(name not in result, 'ONE98_SOURCE_FUNCTION_' + name)
            need98(options.strip() in ('', 'STABLE SET timezone=\'UTC\'', "SET timezone='UTC'"),
                   'EXACT98_SOURCE_FUNCTION_ATTRIBUTES')
            result[name] = {'arguments': arguments, 'result': returns.strip(), 'body': body,
                            'stable': 'STABLE' in options, 'utc': "timezone='UTC'" in options}
        return result
    result = collect(up)
    need98(set(result) == set(FUNCTIONS98), 'EXACT98_SOURCE_NINE_FUNCTIONS')
    previous = collect(down)
    need98(set(previous) == {'guard_capacity_dispatch_job'}, 'SOURCE98_PREDECESSOR_GUARD_INVERSE')
    result['guard_capacity_dispatch_job']['prior'] = previous['guard_capacity_dispatch_job']
    return result


def pg_function98(row, spec):
    """Match Source body/signature/attributes, preserving the CI full definition."""
    definition = row['definition']
    match = re.fullmatch(r'CREATE OR REPLACE FUNCTION public\.([a-z_]+)\((.*?)\)\s+RETURNS\s+(.*?)\s+LANGUAGE plpgsql(.*?)\s+AS (\$[A-Za-z_0-9]*\$)(.*?)\5\s*;?\s*', definition, re.S)
    need98(match is not None and match.group(1) == row['name'], 'FULL98_PG_FUNCTION_DEPARSE')
    normalize = lambda text: re.sub(r'\s+', ' ', text.replace('public.', '').replace(',', ', ')).strip()
    need98(normalize(row['arguments']) == normalize(spec['arguments']) == normalize(match.group(2))
           and normalize(match.group(3)) == normalize(spec['result'])
           and match.group(6) == spec['body'], 'SOURCE98_BODY_AND_SIGNATURE_MATCH_PG')
    attributes = match.group(4).strip()
    expected = ('STABLE' if spec['stable'] else '')
    if spec['utc']:
        expected += (' ' if expected else '') + 'SET "TimeZone" TO \'UTC\''
    need98(re.sub(r'\s+', ' ', attributes) == expected, 'SOURCE98_PG_FUNCTION_ATTRIBUTES')


def history98(before_wire, after_wire):
    need98(type(before_wire) is str and type(after_wire) is str, 'WHOLE98_HISTORY_WIRES')
    before, after = loads98(before_wire), loads98(after_wire)
    need98(type(before) is list and before and type(after) is list
           and type(before[-1]) is dict and type(before[-1].get('version_id')) is int
           and before[-1]['version_id'] == 97 and before[-1].get('is_applied') is True
           and len(after) == len(before) + 1 and same98(after[:-1], before)
           and type(after[-1]) is dict and after[-1].get('version_id') == 98
           and type(after[-1].get('version_id')) is int and after[-1].get('is_applied') is True
           and type(after[-1].get('id')) is int and after[-1]['id'] > before[-1]['id']
           and not any(row.get('version_id') == 98 for row in before), 'SOLE98_APPEND_TO_WHOLE97_HISTORY')


def constraint98_definitions(prior97catalog7, carrier, read_ref, expected_source, source_sql):
    closed98(prior97catalog7, OLD7, 'WHOLE_PRIOR97_CATALOG7')
    closed98(carrier, 'artifact_ref before97_ref after98_ref', 'CLOSED98_CI_CARRIER3')
    raw = {key: original98(ref, read_ref) for key, ref in carrier.items()}
    artifact = loads98(raw['artifact_ref'])
    closed98(artifact, 'schema source_commit postgres_major fixture_only native_authority before97_ref after98_ref migration98_sha256 history_sole98_append old_public_functions_changed historical97_constraints_and_triggers_unchanged new_table_columns all_observed_constraints_validated', 'ACTUAL98_CI_ARTIFACT13')
    need98(artifact['schema'] == 'installed_provision_timeout_schema98_pg_catalog_v1'
           and source98(expected_source) and artifact['source_commit'] == expected_source
           and type(artifact['postgres_major']) is int and artifact['postgres_major'] in (16, 17)
           and artifact['fixture_only'] is True and artifact['native_authority'] is False
           and artifact['migration98_sha256'] == M98
           and artifact['old_public_functions_changed'] == ['guard_capacity_dispatch_job']
           and type(artifact['new_table_columns']) is int and artifact['new_table_columns'] == 10
           and all(artifact[key] is True for key in ('history_sole98_append',
               'historical97_constraints_and_triggers_unchanged', 'all_observed_constraints_validated')),
           'QUALIFIED98_SOURCE_PG_FIXTURE_FACTS')
    views = {}
    for key in ('before97_ref', 'after98_ref'):
        ref = artifact[key]
        closed98(ref, 'path sha256 bytes', 'ACTUAL98_CI_CANONICAL_REF')
        need98(type(ref['path']) is str and PurePosixPath(ref['path']).is_absolute()
               and digest98(ref['sha256']) and type(ref['bytes']) is int
               and ref['bytes'] == len(raw[key]) and ref['sha256'] == sha98(raw[key]) == carrier[key]['sha256'],
               'COMPLETE98_CANONICAL_CI_COPY')
        value = loads98(raw[key])
        closed98(value, 'server_version_num history_wire functions constraints triggers columns', 'WHOLE98_CI_CATALOG6')
        need98(type(value['server_version_num']) is int
               and value['server_version_num'] // 10000 == artifact['postgres_major'], 'ACTUAL98_PG_MAJOR')
        supplement98({key: value[key] for key in ('functions', 'constraints', 'triggers', 'columns')})
        views[key] = value
    before, after = views['before97_ref'], views['after98_ref']
    need98(before['server_version_num'] == after['server_version_num'], 'SAME98_PG_SERVER')
    history98(before['history_wire'], after['history_wire'])
    specs = migration98_functions(source_sql)
    oldfn = {(row['name'], row['arguments']): row for row in before['functions']}
    newfn = {(row['name'], row['arguments']): row for row in after['functions']}
    selected_before = [row for row in before['functions'] if row['name'] in FUNCTIONS98]
    selected_after = [row for row in after['functions'] if row['name'] in FUNCTIONS98]
    need98(len(selected_before) == 1 and selected_before[0]['name'] == 'guard_capacity_dispatch_job'
           and len(selected_after) == 9 and {row['name'] for row in selected_after} == set(FUNCTIONS98),
           'EXACT98_NEW_FUNCTIONS_NO_OVERLOADS')
    pg_function98(selected_before[0], specs['guard_capacity_dispatch_job']['prior'])
    for row in selected_after:
        pg_function98(row, specs[row['name']])
    expectedfn = copy.deepcopy(oldfn)
    for row in selected_after:
        expectedfn[(row['name'], row['arguments'])] = row
    need98(newfn == expectedfn and selected_after != selected_before, 'ONLY98_NINE_SOURCE_FUNCTION_DELTA')
    prior_guard = prior97catalog7['catalog91']['shared_dispatch_guard']
    need98(same98(prior_guard, [{'name': 'guard_capacity_dispatch_job', 'definition': selected_before[0]['definition']}]),
           'IMMUTABLE97_NATIVE_GUARD_EQUALS_CI_AND_SOURCE_INVERSE')
    prior_checks = prior97catalog7['catalog91']['dispatch_constraints']
    ci_old_checks = [{'name': row['name'], 'validated': row['validated'], 'definition': row['definition']}
                     for row in before['constraints'] if row['table'] == 'capacity_dispatch_jobs' and row['name'] in OLD_CHECKS98]
    need98(same98(prior_checks, ci_old_checks) and len(ci_old_checks) == 2, 'ACTUAL97_NATIVE_V9_EQUALS_CI')
    before_supp = {key: before[key] for key in ('functions', 'constraints', 'triggers', 'columns')}
    after_supp = {key: after[key] for key in ('functions', 'constraints', 'triggers', 'columns')}
    before_supp['functions'] = selected_before
    after_supp['functions'] = selected_after
    defs = {'before': before_supp, 'after': after_supp, 'source_functions': specs,
            'server_version_num': before['server_version_num'], 'source_commit': expected_source}
    expected_supplement98(before_supp, after_supp)
    return defs


def expected_supplement98(before, after):
    supplement98(before)
    supplement98(after)
    need98(not any(row['table'] == TABLE98 for key in ('constraints', 'columns', 'triggers') for row in before[key]),
           'NO98_TABLE_IN_PRIOR97')
    expected = copy.deepcopy(before)
    need98([row['name'] for row in before['functions']] == ['guard_capacity_dispatch_job']
           and len(after['functions']) == 9 and {row['name'] for row in after['functions']} == set(FUNCTIONS98),
           'ONE_PRIOR_GUARD_EIGHT98_ADDITIONS')
    expected['functions'] = after['functions']
    oldchecks = [row for row in before['constraints'] if row['table'] == 'capacity_dispatch_jobs' and row['name'] in OLD_CHECKS98]
    newchecks = [row for row in after['constraints'] if row['table'] == 'capacity_dispatch_jobs' and row['name'] in NEW_CHECKS98]
    need98(len(oldchecks) == 2 and len(newchecks) == 2 and {r['name'] for r in oldchecks} == set(OLD_CHECKS98)
           and {r['name'] for r in newchecks} == set(NEW_CHECKS98)
           and all(r['kind'] == 'c' and r['definition'].startswith('CHECK (') for r in oldchecks + newchecks),
           'EXACT98_TWO_V9_TO_TWO_V10_CHECKS')
    newtable = [row for row in after['constraints'] if row['table'] == TABLE98]
    need98(newtable and len([r for r in newtable if r['kind'] == 'p']) == 1
           and len([r for r in newtable if r['kind'] == 'u']) == 2, 'ACTUAL98_TYPED_TABLE_CONSTRAINTS')
    expected['constraints'] = sorted([r for r in before['constraints'] if r not in oldchecks] + newchecks + newtable,
                                     key=lambda row: (row['table'], row['name']))
    added_triggers = [row for row in after['triggers'] if (row['table'], row['name']) not in
                      {(r['table'], r['name']) for r in before['triggers']}]
    need98({(r['table'], r['name']) for r in added_triggers} == {
        (TABLE98, 'installed_timeout_insert'), (TABLE98, 'installed_timeout_immutable'),
        (TABLE98, 'installed_timeout_complete_links'), ('capacity_dispatch_jobs', 'installed_timeout_job_insert'),
        ('workflow_runs', 'installed_timeout_workflow_immutable'), ('capacity_intents', 'installed_timeout_readiness_origin')},
        'EXACT98_SIX_NEW_TRIGGERS')
    expected['triggers'] = sorted(before['triggers'] + added_triggers, key=lambda row: (row['table'], row['name']))
    newcols = [row for row in after['columns'] if row['table'] == TABLE98]
    need98(len(newcols) == 10 and [row['number'] for row in newcols] == list(range(1, 11)), 'ACTUAL98_TEN_TABLE_COLUMNS')
    expected['columns'] = sorted(before['columns'] + newcols, key=lambda row: (row['table'], row['number']))
    need98(same98(expected, after), 'WHOLE98_SUPPLEMENT_ONLY_SOURCE_DELTA')
    return expected


def structural98(value, defs, before=False):
    closed98(value, 'server_version_num table columns indexes', 'CLOSED98_FRESH_STRUCTURE4')
    need98(type(value['server_version_num']) is int and value['server_version_num'] // 10000 in (16, 17),
           'FRESH98_SUPPORTED_PG')
    if before:
        need98(value['table'] is None and value['columns'] == [] and value['indexes'] == [], 'PRE98_TABLE_ABSENT')
        return value
    need98(same98(value['table'], {'name': TABLE98, 'kind': 'r', 'persistence': 'p', 'replica_identity': 'd',
                                 'row_security': False, 'force_row_security': False}), 'FRESH98_ORDINARY_HEAP')
    columns = [row for row in defs['after']['columns'] if row['table'] == TABLE98]
    expected = [{**{key: row[key] for key in ('name', 'number', 'type', 'not_null')},
                 'identity': '', 'generated': '', 'default': None} for row in columns]
    need98(len(columns) == 10 and same98(value['columns'], expected), 'FRESH98_NO_DEFAULT_IDENTITY_GENERATED')
    rows = value['indexes']
    need98(type(rows) is list and len(rows) == 3 and rows == sorted(rows, key=lambda row: row['name']),
           'FRESH98_EXACT_THREE_ORDERED_INDEXES')
    constraints = {row['name']: row for row in defs['after']['constraints']
                   if row['table'] == TABLE98 and row['kind'] in ('p', 'u')}
    observed = set()
    for row in rows:
        closed98(row, 'name constraint_name constraint_kind valid ready live unique primary method predicate expressions keys',
                 'CLOSED98_FRESH_INDEX')
        name = row['constraint_name']
        need98(name in constraints and name not in observed and row['name'] == name
               and row['constraint_kind'] == constraints[name]['kind']
               and all(row[key] is True for key in ('valid', 'ready', 'live', 'unique'))
               and row['method'] == 'btree' and row['predicate'] is None and row['expressions'] is None
               and row['keys'] in (['id'], ['job_id'], ['run_id']) and type(row['primary']) is bool
               and row['primary'] == (row['keys'] == ['id'])
               and row['constraint_kind'] == ('p' if row['primary'] else 'u'), 'FRESH98_VALID_LIVE_UNIQUE_TYPED_INDEX')
        expected_definition = ('PRIMARY KEY' if row['primary'] else 'UNIQUE') + ' (' + row['keys'][0] + ')'
        need98(constraints[name]['definition'] == expected_definition, 'FRESH98_INDEX_KEY_EQUALS_ACTUAL_CI_CONSTRAINT')
        observed.add(name)
    need98(observed == set(constraints) and {tuple(row['keys']) for row in rows} == {('id',), ('job_id',), ('run_id',)},
           'FRESH98_COMPLETE_THREE_KEY_ROSTER')
    return value


def catalog98_delta(prior97catalog7, beforeFull, afterFull, source_functions, defs):
    closed98(prior97catalog7, OLD7, 'CLOSED98_IMMUTABLE_PRIOR97_PROJECTION')
    need98(same98(projection97_98(beforeFull), prior97catalog7), 'NATIVE98_BEFORE_WHOLE_ROOT97_CATALOG')
    need98(same98(source_functions, defs['source_functions']), 'SAME98_AUTHENTICATED_SOURCE_FUNCTIONS')
    before_supp, after_supp = beforeFull['schema98'], afterFull['schema98']
    supplement98(before_supp)
    supplement98(after_supp)
    need98(same98(before_supp, defs['before']) and same98(after_supp, defs['after']), 'WHOLE98_NATIVE_SUPPLEMENT_EQUALS_CI')
    expected_supplement98(before_supp, after_supp)
    structural98(beforeFull['structural98'], defs, before=True)
    structural98(afterFull['structural98'], defs)
    need98(beforeFull['structural98']['server_version_num'] == afterFull['structural98']['server_version_num'],
           'SAME98_NATIVE_PG_SERVER_BEFORE_AFTER')
    expected = copy.deepcopy(prior97catalog7)
    guard = next(row for row in defs['after']['functions'] if row['name'] == 'guard_capacity_dispatch_job')
    expected['catalog91']['shared_dispatch_guard'] = [{'name': guard['name'], 'definition': guard['definition']}]
    expected['catalog91']['dispatch_constraints'] = [
        {key: row[key] for key in ('name', 'validated', 'definition')}
        for row in defs['after']['constraints'] if row['table'] == 'capacity_dispatch_jobs' and row['name'] in NEW_CHECKS98]
    need98(len(expected['catalog91']['dispatch_constraints']) == 2
           and same98(projection97_98(afterFull), expected), 'ALL_OTHER97_CATALOG_BYTES_AND_ARRAYS_UNCHANGED')
    history98(beforeFull['legacy']['complete_history_wire'], afterFull['legacy']['complete_history_wire'])
    result = {**expected, 'schema98': after_supp}
    need98(same98(result, catalog98_projection(afterFull)), 'WHOLE98_EXPECTED_EIGHT_KEY_PROJECTION')
    return result


def root98_overlay(rawRoot98, rawRoot97, pins, read_ref):
    need98(sha98(rawRoot97) == ROOT97_SHA, 'IMMUTABLE98_ROOT97_WHOLE_ORIGINAL')
    previous, value = loads98(rawRoot97), loads98(rawRoot98)
    closed98(value, 'schema reviewed_by_root schema_before schema_after current_core_source current_ops_source business_source amd64_D migration98_sha256 complete_history_sha256 prior97_history_sha256 catalog98_sha256 index92_definition_sha256 catalog90_91_sha256 job_uid pod_uid exit_code single_job_create provider_guest_core_mutations old_records_and_sdk_preserved original_refs', 'ROOT98_CLOSED21')
    need98(previous['schema'] == 'root_goose97_normal_finish_recovery_acceptance_v1'
           and previous['reviewed_by_root'] is True and previous['schema_after'] == 97
           and value['schema'] == 'root_goose98_installed_provision_timeout_acceptance_v1'
           and value['reviewed_by_root'] is True and type(value['schema_before']) is int and value['schema_before'] == 97
           and type(value['schema_after']) is int and value['schema_after'] == 98, 'ROOT98_SEPARATE_HISTORICAL97')
    need98(value['current_core_source'] == CURRENT_CORE8 and value['current_ops_source'] == pins['current_ops_source']
           and source98(value['current_ops_source']) and value['business_source'] == pins['business_source']
           and source98(value['business_source']) and value['amd64_D'] == pins['amd64_D']
           and digest98(value['amd64_D']), 'ROOT98_HONEST_OLD_CORE8_NEW_CORE9_COMPANION')
    need98(value['migration98_sha256'] == M98
           and value['prior97_history_sha256'] == previous['complete_history_sha256'] == pins['prior97_history_sha256']
           and value['index92_definition_sha256'] == previous['index92_definition_sha256'] == pins['index92_definition_sha256']
           and all(digest98(value[key]) and value[key] == pins[key] for key in (
               'complete_history_sha256', 'catalog98_sha256', 'catalog90_91_sha256')),
           'ROOT98_WHOLE_CURRENT_HISTORY_CATALOG_PRIOR97_PINS')
    uuid = lambda text: type(text) is str and re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text) is not None
    need98(uuid(value['job_uid']) and uuid(value['pod_uid']) and type(value['exit_code']) is int
           and value['exit_code'] == 0 and value['single_job_create'] is True
           and type(value['provider_guest_core_mutations']) is int and value['provider_guest_core_mutations'] == 0
           and value['old_records_and_sdk_preserved'] is True, 'ROOT98_ONE_JOB_ZERO_PROVIDER_GUEST_CORE_MUTATIONS')
    closed98(value['original_refs'], 'migration_result before_catalog after_catalog source_ci qualified_image', 'ROOT98_FIVE_RAW_ORIGINAL_ROLES')
    for ref in value['original_refs'].values():
        original98(ref, read_ref)
    need98(len({ref['sha256'] for ref in value['original_refs'].values()}) == 5, 'ROOT98_DISTINCT_WHOLE_ORIGINALS')
    return value


SUPPLEMENT98_SQL = "-- INERT Source/DATA only. No BEGIN/COMMIT or IO; caller must retain the existing bounded RR/RO wrapper.\n-- The four arrays match the existing M98 CI dump row shapes and explicit ordering.\nSELECT jsonb_build_object(\n 'functions',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',p.proname,'arguments',pg_get_function_identity_arguments(p.oid),'definition',pg_get_functiondef(p.oid)) ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)),'[]'::jsonb) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public' AND p.prokind='f' AND p.proname IN('installed_provision_timeout_valid','guard_installed_provision_timeout_insert','check_installed_provision_timeout_transition','guard_capacity_dispatch_job','guard_installed_provision_timeout_job_insert','immutable_installed_provision_timeout','guard_installed_provision_timeout_workflow','require_installed_provision_timeout_links','guard_installed_timeout_origin')),\n 'constraints',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',r.relname,'name',c.conname,'kind',c.contype,'validated',c.convalidated,'definition',pg_get_constraintdef(c.oid,false)) ORDER BY r.relname,c.conname),'[]'::jsonb) FROM pg_constraint c JOIN pg_class r ON r.oid=c.conrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions','capacity_guest_retirement_forwards','capacity_guest_retirement_forward_reads','capacity_intents','capacity_guest_authority_issues','workflow_runs')),\n 'triggers',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',r.relname,'name',g.tgname,'enabled',g.tgenabled,'definition',pg_get_triggerdef(g.oid,false)) ORDER BY r.relname,g.tgname),'[]'::jsonb) FROM pg_trigger g JOIN pg_class r ON r.oid=g.tgrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND NOT g.tgisinternal AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions','capacity_guest_retirement_forwards','capacity_guest_retirement_forward_reads','capacity_intents','capacity_guest_authority_issues','workflow_runs')),\n 'columns',(SELECT COALESCE(jsonb_agg(jsonb_build_object('table',r.relname,'name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull) ORDER BY r.relname,a.attnum),'[]'::jsonb) FROM pg_attribute a JOIN pg_class r ON r.oid=a.attrelid JOIN pg_namespace n ON n.oid=r.relnamespace WHERE n.nspname='public' AND a.attnum>0 AND NOT a.attisdropped AND r.relname IN('capacity_dispatch_jobs','capacity_dispatch_installed_provision_timeout_dispositions'))\n)\n"

STRUCTURE98_SQL = "-- INERT Source/DATA only. Fresh structural facts, not claimed CI-deparse originals.\n-- Before M98 table is null and columns/indexes empty. After M98 validate exact Source DDL expectations.\nSELECT jsonb_build_object(\n 'server_version_num',current_setting('server_version_num')::int,\n 'table',(SELECT jsonb_build_object('name',c.relname,'kind',c.relkind,'persistence',c.relpersistence,'replica_identity',c.relreplident,'row_security',c.relrowsecurity,'force_row_security',c.relforcerowsecurity) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname='capacity_dispatch_installed_provision_timeout_dispositions'),\n 'columns',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',a.attname,'number',a.attnum,'type',format_type(a.atttypid,a.atttypmod),'not_null',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY a.attnum),'[]'::jsonb) FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum WHERE a.attrelid=to_regclass('public.capacity_dispatch_installed_provision_timeout_dispositions') AND a.attnum>0 AND NOT a.attisdropped),\n 'indexes',(SELECT COALESCE(jsonb_agg(jsonb_build_object('name',ci.relname,'constraint_name',con.conname,'constraint_kind',con.contype,'valid',i.indisvalid,'ready',i.indisready,'live',i.indislive,'unique',i.indisunique,'primary',i.indisprimary,'method',am.amname,'predicate',pg_get_expr(i.indpred,i.indrelid),'expressions',pg_get_expr(i.indexprs,i.indrelid),'keys',(SELECT jsonb_agg(a.attname ORDER BY u.position) FROM unnest(i.indkey) WITH ORDINALITY AS u(attnum,position) LEFT JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=u.attnum)) ORDER BY ci.relname),'[]'::jsonb) FROM pg_index i JOIN pg_class ci ON ci.oid=i.indexrelid JOIN pg_am am ON am.oid=ci.relam LEFT JOIN pg_constraint con ON con.conindid=i.indexrelid AND con.conrelid=i.indrelid AND con.contype IN('p','u') WHERE i.indrelid=to_regclass('public.capacity_dispatch_installed_provision_timeout_dispositions'))\n)\n"
