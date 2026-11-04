"""Closed G10 operational ABI. Definitions only; no native action on import.

The image-pair prefix and the five Guardian ancestry axes are independent.
Callers pin the complete operational package by its reviewed manifest hash.
"""
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import types

ROOT = Path('/opt/dakasa/capacity-network')
ETC = Path('/etc/dakasa/capacity-network')
UNIT_DIR = Path('/etc/systemd/system')
CTRL = 'dakasa-capacity-network.service'
GUARD = 'dakasa-capacity-network-guardian.service'
COLD = 'dakasa-capacity-network-cold-transport.service'
HUB = 'dakasa-capacity-network-hub.service'
UNITS = (CTRL, GUARD, COLD, HUB)
OLD_CORE_SOURCE = 'c02512e9d11d29cad4e4ff67186602d3485d6fa3'
OLD_CORE_UID = 'a58ab8c2-da48-46c1-ae62-a650141eeb86'
OLD_CORE_GENERATION = 273
OLD_CORE_POD_UID = '0b47fd47-7654-4f8b-8dca-204bc9bd9de6'
PROPOSAL_BOUND = True
SOURCE_R = 'd7d7adcff71807e60b782f50c8473bbb5981b9c9'
OLD_DIGEST = '7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6'
NEW_DIGEST = '4fa5525f3b4bdac22a83260bac4fdd655106720b73ede11300f6f034451a6181'
IMAGE_PREFIX = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@sha256:'
G6_CONFIG_SHA = '8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
G7_CONFIG_SHA = 'd68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'
G8_CONFIG_SHA = '42b9d05dac25610678ebce295335ead8b6086a87527fcd5ad030413a37a2a1a5'
G10_CONFIG_SHA = '7b11191f9840a6ebf92f6f9332a438198d7b34b5546e69ca4869b624f8e7d6ed'
G9_CONFIG_SHA = '3d8ed6cf0341d6fe36ff190ade585321a1c88274577b9ebb57f8e7c235654111'
G8_SOURCE_SHA = '8259638127d811079d6a461d3bd7407f8a53ff3ebb75e8061bf8538dcf6508b9'
G8_STANDING_SHA = 'a02690f5e7a8c000478ceca6c4f4715e7b589814bf93fc5cbefe3bd9126e08d3'
HEAD_CONFIG_SHA = G10_CONFIG_SHA
G7_SOURCE_SHA = '2379e9cb0fcf36faf7dfe58e930d0eb6ae97ba4d177db6610a23583d0a00a8aa'
G7_STANDING_SHA = 'dd7d449ea8fdba60a43d6badb138ea9496e1342572f90633e62d7b87d9b44866'
ACTUAL_PREDECESSOR_SOURCE_SHA = '6defe12adc0cac920c767c09c49c25db589d9ec9a0dee5abc0f3cc03dfe18765'
ACTUAL_PREDECESSOR_STANDING_SHA = 'af0ae4a82c5ee7504025cf4564b67ea941cc99122677aa1fa8a82f96c6a44a87'
ACTUAL_PREDECESSOR_CONFIG_SHA = G9_CONFIG_SHA
G6_SOURCE_SHA = '6c2cc19f1f962d9d8eaec0cd5e6f813bf49004f8ff6fef9c9fe9f8f0310d8f1b'
G6_STANDING_SHA = 'be5b25495056bd25e1512827b5ccbe7236f84928b4d20515f5000383771dcc79'
F315_SOURCE_SHA = 'f3152cc6d8c5d7edee2e5349db17fac4b8650a18423dfc207c04fcc116955e6d'
F315_STANDING_SHA = 'faa6b2cb3132ce2e0ee4304bd833d7f0f999850244014d355f1c33ed176ebb83'
OLD_SOURCE = ROOT / 'network-boot-recovery-r13-g9pair-source-v1'
NEW_SOURCE = ROOT / 'network-boot-recovery-r13-g10pair-source-v1'
OLD_STANDING = ETC / 'network-recovery.r13-g9pair.production.json'
NEW_STANDING = ETC / 'network-recovery.r13-g10pair.production.json'
OLD_CONFIG = ETC / 'controller.r13-netlink-g9pair.production.json'
NEW_CONFIG = ETC / 'controller.r13-netlink-g10pair.production.json'
RUNTIME = ROOT / 'source-r13-netlink-v1'
LEDGER = Path('/var/lib/dakasa-capacity-network-recovery')
STATE = Path('/var/lib/dakasa-core-rollout/g10pair')
MAINTENANCE = Path('/run/dakasa-capacity-network/guardian-maintenance.lock')
DROPIN = Path('/etc/systemd/system.control') / (CTRL + '.d/50-CPUQuota.conf')
# The existing CPU quota override is deliberately retained.
DROPIN_SHA = '2acd3272d2ee396203c519bc353c089be5871c3b70d79eff9e27f8ef70f14994'
OLD_UNIT_SHAS = {CTRL: 'a6a4bdcda5270a7000dc8399c1eb5e84fc762ceac9f6ad3845c4a334eaea6c0d', COLD: '4b49a3ec10cb131242e7a17d8c0026aa6a48e1e0d2d1ec3c3610ae3763406879', GUARD: '038d72711a76ccd98d71127f7746a41dc0c4fda27f255f566bee6161aa8a2531', HUB: '4ae45486e7b25c5c3f525409a5714568c22d16f72c4e6d8afad9bc3b3576ebfe'}
MODULES = ('network_guardian.py', 'coverage.py', 'journal_contract.py', 'proof_cache.py',
           'current15_bounded_reader.py', 'current15_bounded_tail_contract.py',
           'initial_boot_Cold_read_adoption.py', 'qualification_initializer.py')
TOOLS = ('pair_change_contract.py', 'derive_g10pair_controller_config.py', 'derive_standing_config.py', 'g10cut.py')
HELPERS = {'coverage.py': 'eb7ed1fcbcc665cdc3603812a10103b4e19dd0b66693b99dc8cfeb15adceeb88',
           'journal_contract.py': 'b0c153b69cc8275e1e330cb3c584b498c1685c1b999c4b5c7b972f164c96db6c',
           'proof_cache.py': 'c2e0b981a2843c15dd5907cc186e4c23a7d844a78c1ce4f7e2e3578704eb5b4b',
           'current15_bounded_reader.py': '1124dfbfbd57c60decc4fdcb0233c03253e87a941f50c8fa5b6aad3e28ae30cd',
           'current15_bounded_tail_contract.py': 'c18809987960f9aea524240f7ea6886a1ed782e5c4001e68edac875bbbe3431d',
           'initial_boot_Cold_read_adoption.py': '0e690f4b74303da774aa7d5a651444e7f74c8445428af38002192bf1079b5799',
           'qualification_initializer.py': 'd73ade12564ba7b672a4dbdf8225e99af13a64a9b8aff4a41fb1a0225bef9ec8'}
PREFIX_STANDINGS = {'f5pair': 'afcfe2e5cad8dbf59732fb805e7f6c4a709608f36ba77bc112ca6633c8e3833c',
                    'g2pair': '494a57d8d4995f9f52348e6153bca5e00a73b873fbd69e8e36c187407cc0f57f',
                    'g3pair': '2922be85534c7d93257a9d703af8509c72e585e5683edfd35496ff8294df40d9',
                    'g4pair': '385928fe10e25980b918ca44bacd5b7e8b901cd2cbcde2bae8304e58d8931997',
                    'g5pair': '180b38fa905099e57776e944eda2be856ccc89bc070ad6b67a9142ab380139ca'}
ANCESTORS = {'g6_predecessor_guardian_source_sha256': G6_SOURCE_SHA,
             'g6_predecessor_standing_config_sha256': G6_STANDING_SHA,
             'g6_boot_v2_predecessor_guardian_source_sha256': F315_SOURCE_SHA,
             'g6_boot_v2_predecessor_standing_config_sha256': F315_STANDING_SHA,
             'g7_predecessor_guardian_source_sha256': G7_SOURCE_SHA,
             'g7_predecessor_standing_config_sha256': G7_STANDING_SHA,
             'g8_predecessor_guardian_source_sha256': G8_SOURCE_SHA,
             'g8_predecessor_standing_config_sha256': G8_STANDING_SHA,
             'g9_predecessor_guardian_source_sha256': ACTUAL_PREDECESSOR_SOURCE_SHA,
             'g9_predecessor_standing_config_sha256': ACTUAL_PREDECESSOR_STANDING_SHA}
DERIVATION_SCHEMA = 'r13_g10pair_guardian_standing_config_derivation_v1'
PACKAGE_SCHEMA = 'guardian_g10pair_operational_package_v1'
STAGED_SCHEMA = 'guardian_g10pair_staged_v1'
HISTORICAL_G9_REQUIRED_CI = frozenset((('Capacity intent PostgreSQL protocol', 'pull_request'), ('Capacity source-owned HTTP qualification', 'pull_request'), ('Context Freshness (ADR + durable context)', 'pull_request'), ('Docs freshness', 'pull_request'), ('Failed installed Guest administrative HTTP Source', 'pull_request'), ('Failed serving Guest Source and PostgreSQL', 'pull_request'), ('Guest historical unknown read recovery', 'pull_request'), ('Installed Guest reconciliation Source', 'pull_request'), ('Native OIDC protocol integration', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'push'), ('Original and native denied disposition Source', 'pull_request'), ('Owned Network Guardian', 'pull_request'), ('Partial Guest native OFF reconciliation Source', 'pull_request'), ('Protected native capacity API qualification', 'pull_request'), ('Service contract', 'pull_request'), ('Service contract', 'push'), ('template-go-api CI', 'pull_request'), ('Recorded HTTP maintenance disposition Source and PostgreSQL', 'pull_request')))

REQUIRED_CI = frozenset((('Capacity intent PostgreSQL protocol', 'pull_request'), ('Capacity source-owned HTTP qualification', 'pull_request'), ('Docs freshness', 'pull_request'), ('Failed installed Guest administrative HTTP Source', 'pull_request'), ('Failed serving Guest Source and PostgreSQL', 'pull_request'), ('Guest historical unknown read recovery', 'pull_request'), ('Installed Guest reconciliation Source', 'pull_request'), ('Native OIDC protocol integration', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'pull_request'), ('Original Guest Core source and PostgreSQL gates', 'push'), ('Original and native denied disposition Source', 'pull_request'), ('Owned Network Guardian', 'pull_request'), ('Partial Guest native OFF reconciliation Source', 'pull_request'), ('Protected native capacity API qualification', 'pull_request'), ('Recorded HTTP maintenance disposition Source and PostgreSQL', 'pull_request'), ('Service contract', 'pull_request'), ('Service contract', 'push'), ('template-go-api CI', 'pull_request')))

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


class Hold(RuntimeError):
    """Preserve evidence and reconcile actual state; never automatically replay."""


def need(ok, guard):
    if not ok:
        raise Hold(guard)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def loads(raw):
    def unique(rows):
        out = {}
        for key, value in rows:
            need(key not in out, 'DUPLICATE_JSON_KEY')
            out[key] = value
        return out
    def reject(_):
        raise Hold('NONFINITE_JSON')
    def finite_float(text):
        value = float(text)
        need(math.isfinite(value), 'NONFINITE_JSON')
        return value
    return json.loads(raw, object_pairs_hook=unique, parse_constant=reject, parse_float=finite_float)


def digest(value):
    return type(value) is str and re.fullmatch('[a-f0-9]{64}', value) is not None and value != '0' * 64


def identity(value):
    need(type(value) is dict and set(value) == {'boot_id', 'pid', 'start_ticks', 'InvocationID', 'ExecMainStartTimestampMonotonic'}, 'CLOSED_NATIVE_IDENTITY')
    need(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', str(value['boot_id']))
         and type(value['pid']) is int and value['pid'] > 1 and type(value['start_ticks']) is int and value['start_ticks'] > 0
         and re.fullmatch('[a-f0-9]{32}', str(value['InvocationID'])) and re.fullmatch('[1-9][0-9]*', str(value['ExecMainStartTimestampMonotonic'])), 'EXACT_PHYSICAL_NATIVE_IDENTITY')


def read(path, cap=1 << 20, mode=None):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1 and
             (stat.S_IMODE(a.st_mode) == mode if mode is not None else not stat.S_IMODE(a.st_mode) & 0o022), 'ROOT_STABLE_REGULAR_FILE')
        chunks, size = [], 0
        while True:
            row = os.read(fd, min(65536, cap + 1 - size))
            if not row:
                break
            size += len(row)
            need(size <= cap, 'BOUNDED_FILE')
            chunks.append(row)
        b = os.fstat(fd)
        need((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns) ==
             (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'STABLE_FULL_READ')
        return b''.join(chunks)
    finally:
        os.close(fd)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def shared_parent(path):
    """Inspect the existing shared parent; never chmod or replace it."""
    path = Path(path)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not path.is_symlink()
         and not stat.S_IMODE(s.st_mode) & 0o022, 'ROOT_SHARED_PARENT_NOT_SYMLINK_OR_WRITABLE')


def private_dir(path, create=False):
    path = Path(path)
    if create:
        path.mkdir(mode=0o700, exist_ok=False)
        sync_dir(path.parent)
    s = path.lstat()
    need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and stat.S_IMODE(s.st_mode) == 0o700 and not path.is_symlink(), 'ROOT_PRIVATE_DIRECTORY')


def once(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            need(n > 0, 'FULL_WRITE')
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)
    sync_dir(path.parent)
    need(read(path, max(len(raw), 1), mode) == raw, 'NEW_FILE_READBACK')


def load_guardian(path, expected_sha):
    raw = read(Path(path) / 'network_guardian.py')
    need(digest(expected_sha) and sha(raw) == expected_sha, 'EXACT_GUARDIAN_DEFINITIONS')
    module = types.ModuleType('exact_g10_operational_guardian_definitions')
    module.__file__ = str(Path(path) / 'network_guardian.py')
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


def validate_standing_output(value, expected, units_source):
    require_bound()
    """Same closed ABI for staged and live derivation; no native operations."""
    need(type(value) is dict and set(value) == {'schema', 'hub_profile', 'units_source', 'standing_config_sha256', 'standing_config_written', 'input_sha256', 'review_text_printed', 'private_files_read'}, 'CLOSED_G10_DERIVATION_OUTPUT')
    need(value['schema'] == DERIVATION_SCHEMA and value['hub_profile'] == 'r13' and units_source in ('staged', 'live') and value['units_source'] == units_source
         and value['standing_config_written'] is True and value['review_text_printed'] is False and value['private_files_read'] is False
         and digest(value['standing_config_sha256']), 'EXACT_G10_DERIVATION_RESULT')
    need(type(expected) is dict and set(expected) == {'source_sha256', 'unit_sha256', 'controller_prefix_sha256', 'ancestry_input_sha256'}, 'CLOSED_EXPECTED_DERIVATION')
    inputs = {'successor_guardian_source_sha256': expected['source_sha256'], 'head_generation': 'g10pair', 'head_core_digest': 'sha256:' + NEW_DIGEST,
              'head_controller_config_sha256': HEAD_CONFIG_SHA, 'historical_g6_controller_config_sha256': G6_CONFIG_SHA,
              'pair_predecessor_standing_config_sha256': PREFIX_STANDINGS, **ANCESTORS,
              'pair_chain_controller_config_sha256': {**expected['controller_prefix_sha256'], 'g10pair': HEAD_CONFIG_SHA},
              **expected['unit_sha256'], **expected['ancestry_input_sha256']}
    need(set(expected['unit_sha256']) == set(UNITS) and set(expected['controller_prefix_sha256']) == {'base', 'f5pair', 'g2pair', 'g3pair', 'g4pair', 'g5pair', 'g6pair', 'g7pair', 'g8pair', 'g9pair'}
         and expected['controller_prefix_sha256']['g6pair'] == G6_CONFIG_SHA
         and expected['controller_prefix_sha256']['g7pair'] == G7_CONFIG_SHA
         and expected['controller_prefix_sha256']['g8pair'] == G8_CONFIG_SHA
         and expected['controller_prefix_sha256']['g9pair'] == G9_CONFIG_SHA, 'EXACT_PREFIX_AND_FOUR_UNITS')
    need(set(expected['ancestry_input_sha256']) == {'predecessor_standing_config_sha256', 'r13_predecessor_standing_config_sha256', 'r42_controller_config_sha256', 'r13_base_controller_config_sha256', 'hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256'}, 'CLOSED_ORIGINAL_ANCESTRY_INPUTS')
    need(expected['unit_sha256'][HUB] == expected['ancestry_input_sha256']['hub_unit_sha256']
         and expected['controller_prefix_sha256']['base'] == expected['ancestry_input_sha256']['r13_base_controller_config_sha256'], 'SAME_HUB_UNIT_AND_R13_BASE_ACROSS_OUTPUT_AXES')
    need(all(digest(x) for x in [expected['source_sha256'], *expected['unit_sha256'].values(), *expected['controller_prefix_sha256'].values(), *expected['ancestry_input_sha256'].values()]), 'NONZERO_DERIVATION_PINS')
    need(value['input_sha256'] == inputs, 'EXACT_G10_DUAL_ANCESTRY_STAGED_OR_LIVE_ABI')
    return value['standing_config_sha256']


def validate_manifest(m):
    keys = {'schema', 'source_commit', 'source_R', 'amd64_D', 'runtime_package_sha256', 'files', 'tools', 'controller_unit_sha256', 'root_controller_review_sha256', 'root_standing_review_sha256', 'expected_controller_identity', 'expected_guardian_identity', 'protected_refs', 'ci_attestation', 'continuity_peer_ipv4'}
    need(type(m) is dict and set(m) == keys and m['schema'] == PACKAGE_SCHEMA and m['source_R'] == SOURCE_R and m['amd64_D'] == NEW_DIGEST and re.fullmatch('[a-f0-9]{40}', str(m['source_commit'])), 'CLOSED_EXACT_G10_OPERATIONAL_PACKAGE')
    for key in ('runtime_package_sha256', 'controller_unit_sha256', 'root_controller_review_sha256', 'root_standing_review_sha256'):
        need(digest(m[key]), 'EXACT_PACKAGE_PIN')
    need(set(m['files']) == {'source/' + n for n in MODULES} | {'units/' + n for n in (COLD, GUARD)} and all(digest(x) for x in m['files'].values()), 'EXACT_SOURCE8_UNITS2_ROSTER')
    need(all(m['files']['source/' + n] == h for n, h in HELPERS.items()) and set(m['tools']) == set(TOOLS) and all(digest(x) for x in m['tools'].values()), 'UNCHANGED_SEVEN_HELPERS_AND_EXACT_FOUR_TOOLS')
    identity(m['expected_controller_identity']); identity(m['expected_guardian_identity'])
    need(m['expected_controller_identity']['boot_id'] == m['expected_guardian_identity']['boot_id'] and m['expected_controller_identity']['pid'] != m['expected_guardian_identity']['pid'], 'SAME_BOOT_DISTINCT_OWNED_LIFETIMES')
    need(type(m['continuity_peer_ipv4']) is str and str(ipaddress.IPv4Address(m['continuity_peer_ipv4'])) == m['continuity_peer_ipv4'] and ipaddress.IPv4Address(m['continuity_peer_ipv4']).is_private, 'ROOT_REVIEWED_ACTUAL_CONTINUITY_PEER_IPV4')
    refs = m['protected_refs']
    need(type(refs) is list and 3 <= len(refs) <= 128, 'EXPLICIT_ORIGINAL_PROTECTED_REFS')
    for v in refs:
        need(type(v) is dict and set(v) == {'path', 'sha256'} and Path(v['path']).parent == LEDGER and re.fullmatch('[A-Za-z0-9_.-]+(?:\.PUBLIC(?:\.json)?|\.JSONL)', Path(v['path']).name) and digest(v['sha256']), 'FIXED_PUBLIC_LEDGER_REF')
    need(len({v['path'] for v in refs}) == len(refs) and {v['path']:v['sha256'] for v in refs} == protected_ref_union(), 'EXACT_INHERITED_AND_CURRENT_G9_PROTECTED_REF_UNION')
    ci = m['ci_attestation']
    need(type(ci) is dict and set(ci) == {'schema', 'commit', 'reviewed_by_root', 'runs'} and ci['schema'] == 'guardian_g10_exact_source_ci_v1'
         and ci['commit'] == m['source_commit'] and ci['reviewed_by_root'] is True and type(ci['runs']) is list and len(ci['runs']) == len(REQUIRED_CI), 'ROOT_REVIEWED_EXACT_G10_CI')
    need(all(type(r) is dict and set(r) == {'id', 'name', 'event', 'head_sha', 'status', 'conclusion', 'attempt'} and type(r['id']) is int and r['id'] > 0 and r['head_sha'] == m['source_commit']
             and r['status'] == 'completed' and r['conclusion'] == 'success' and type(r['attempt']) is int and r['attempt'] >= 1 for r in ci['runs']) and len({r['id'] for r in ci['runs']}) == len(ci['runs']), 'EVERY_REQUIRED_EXACT_G10_CI_RUN_SUCCESS')
    need({(r['name'], r['event']) for r in ci['runs']} == REQUIRED_CI, 'ALL_APPLICABLE_G10_CI_NAMES_AND_EVENTS_PRESENT')
    return m


def package(folder, expected_sha):
    require_bound()
    folder = Path(folder); private_dir(folder)
    raw = read(folder / 'MANIFEST.json')
    need(digest(expected_sha) and sha(raw) == expected_sha, 'ROOT_REVIEWED_PACKAGE_MANIFEST_SHA')
    m = validate_manifest(loads(raw))
    runtime_raw = read(folder / 'PACKAGE.json')
    need(sha(runtime_raw) == m['runtime_package_sha256'] and loads(runtime_raw)['files'] == m['files'], 'EXACT_SEPARATE_RUNTIME_PACKAGE10')
    for name, pin in m['files'].items():
        need(sha(read(folder / name)) == pin, 'EXACT_RUNTIME_PACKAGE_FILE')
    for name, pin in m['tools'].items():
        need(sha(read(folder / 'tools' / name)) == pin, 'EXACT_OPERATIONAL_TOOL_FILE')
    need(sha(read(folder / 'controller.service', 32768)) == m['controller_unit_sha256'], 'EXACT_DERIVED_CONTROLLER_UNIT')
    need(sha(read(folder / 'ROOT-CONTROLLER-REVIEW.txt', 8192)) == m['root_controller_review_sha256'] and sha(read(folder / 'ROOT-STANDING-REVIEW.txt', 8192)) == m['root_standing_review_sha256'], 'EXACT_ROOT_REVIEW_FILES')
    return folder, m


# Added current G8 proofs are bound only from Root's fresh actual preimage.
# The inherited39 mapping above remains byte-for-byte unchanged.
EXPECTED_G8_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/d323cc228bec43596ac73c99cc473298896b8f2d88b06219aa69a549633925b3-QUALIFIED.PUBLIC.json': '68f5b3bcd33a9ab8e1ad29f3fdbf52a83166b694b81f5bce474e2fe85afecce3', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-a1826878088e4dbaa5e7adfb67cba5c6-FIRST-CURRENT15-RETURN.PUBLIC.json': 'e406648a4ecd503ff8231e5fde8d6969a091fe9327c4e8e0927815eb929711c4'}
ROOT_G8_REF_ACCEPTANCE_SHA = 'e1b3071bc51da5d8902ba7392f55370860f60362564429ad68320e9b9c4f87cb'

EXPECTED_G9_PROOF_REFS = {'/var/lib/dakasa-capacity-network-recovery/eeb07b5f3d171544f5eddc02c4d0cbad6d07854bdf2958d697ef56d33c5e9c5c-QUALIFIED.PUBLIC.json': 'c3d6f4cac12d61e8ade4189012d065fff95e213f9cdc8edaeea757887234b16d', '/var/lib/dakasa-capacity-network-recovery/2b7e9be2-e45a-4cd5-86f2-6f0a3372576d-GUARDIAN-821ba94c6a3d4b32a22f022949691a1e-FIRST-CURRENT15-RETURN.PUBLIC.json': '2c18fb8de9ab3d1aeffd0302ac8d93f4797936ff6fb475e6f32061880ce17f56'}
ROOT_G9_REF_ACCEPTANCE_SHA = 'f97c6695172560358289a111b6dc473607398869e513688bf9d5380597f6ca8e'

def require_bound():
    need(PROPOSAL_BOUND is True and type(SOURCE_R) is str and re.fullmatch('[a-f0-9]{40}', SOURCE_R) is not None and SOURCE_R != '0' * 40
         and type(OLD_CORE_GENERATION) is int and OLD_CORE_GENERATION > 0
         and type(OLD_CORE_POD_UID) is str and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', OLD_CORE_POD_UID) is not None
         and digest(NEW_DIGEST) and NEW_DIGEST != OLD_DIGEST and digest(HEAD_CONFIG_SHA)
         and digest(ACTUAL_PREDECESSOR_STANDING_SHA)
         and type(EXPECTED_G9_PROOF_REFS) is dict and len(EXPECTED_G9_PROOF_REFS) == 2
         and digest(ROOT_G9_REF_ACCEPTANCE_SHA)
         and type(REQUIRED_CI) is frozenset and bool(REQUIRED_CI)
         and all(type(row) is tuple and len(row) == 2 and type(row[0]) is str and bool(row[0])
                 and row[1] in ('pull_request', 'push') for row in REQUIRED_CI),
         'G10_RELEASE_CONFIG_AND_ACTUAL_G9_REFS_NOT_BOUND')
def protected_ref_union():
    require_bound()
    out = dict(EXPECTED_INHERITED_REFS)
    for rows in (EXPECTED_G8_PROOF_REFS, EXPECTED_G9_PROOF_REFS):
        for path, pin in rows.items():
            need(type(path) is str and digest(pin) and path not in out,
                 'DISTINCT_ORIGINAL_PROOF_REFERENCE_NO_REPLACEMENT')
            out[path] = pin
    need(len(out) == 43, 'EXACT_OLD41_PLUS_TWO_ACTUAL_G9_REFS')
    return out