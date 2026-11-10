"""Derive the g7 pair config on the Brain from all byte-pinned predecessors. Only core_container_images and the new root attestation change. No service is mutated by this derivation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

ETC = Path('/etc/dakasa/capacity-network')
R42_CONFIG = ETC / 'controller.r42-cold-unknown184014.production.json'
R42_CONFIG_SHA = '0f4631320e7319cf4da3c37586bbee2ae977eb338831fb0e991ed735cb9113c3'
BASE_CONFIG = ETC / 'controller.r13-netlink.production.json'
BASE_CONFIG_SHA = '460b0fd49191248fecffa7009636a82391815a64fc23db11e039b7ee9f5d928a'
F5_CONFIG = ETC / 'controller.r13-netlink-f5pair.production.json'
F5_CONFIG_SHA = 'ed797c474d71a064f4e9dfe99a4c2ddc6530b49ae712eb78033b75967c2b6621'
G2_CONFIG = ETC / 'controller.r13-netlink-g2pair.production.json'
G2_CONFIG_SHA = '9168e9c661a40a9f1761e0938deb7fda44a4ce3a0a3e852f8cab281bdb71e48b'
G3_CONFIG = ETC / 'controller.r13-netlink-g3pair.production.json'
G3_CONFIG_SHA = '7b452ccca85f722e59c3748dc127f0cccda3e54bbcecc9f74c9b4c6cbc589068'
G4_CONFIG = ETC / 'controller.r13-netlink-g4pair.production.json'
G4_CONFIG_SHA = '431a42ee4caba690a6a479e1ca19d842835dc23d8acccb3bc63a05bee7ea663b'
G5_CONFIG = ETC / 'controller.r13-netlink-g5pair.production.json'
G5_CONFIG_SHA = '1b38e2cb050b9c98fc6edf07d867edaed1758aba1bdb496ad4566f13e5fb6a45'
G6_CONFIG_SHA = '8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
G7_CONFIG_SHA = 'd68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'
G7_CONFIG = ETC / 'controller.r13-netlink-g7pair.production.json'
G8_CONFIG_SHA = '42b9d05dac25610678ebce295335ead8b6086a87527fcd5ad030413a37a2a1a5'
G11_CONFIG_SHA = 'a3706d21323a4cce2ef1d0746a9daffd81c1dad538f028635765bcbc116c7777'
G12_CONFIG_SHA = '7c05da2f2ab22a08abd57d5e514e71c7c378e03387a532a8189e1845e3865879'
G13_CONFIG_SHA = '2fafe364344596ec0ab4a87a1887c8a4bcc581b103937fedb807e624fc3e6ac0'
G15_CONFIG_SHA = '9094bab152bae7be581b524fb32417c7cfb320ce1ad46f9a171347d3043fa4a5'
PROPOSAL_BOUND = True
G8_CONFIG = ETC / 'controller.r13-netlink-g8pair.production.json'
G12_CONFIG = ETC / 'controller.r13-netlink-g12pair.production.json'
G6_CONFIG = ETC / 'controller.r13-netlink-g6pair.production.json'
GUARDIAN_SOURCE = Path('/opt/dakasa/capacity-network/network-boot-recovery-r13-g15pair-source-v1/network_guardian.py')
# The package supplies the exact reviewed successor Guardian source hash.
FIELDS = {'schema', 'execute', 'source_files_sha256', 'eks_endpoint', 'eks_public_ca_base64', 'core_service_uid',
          'core_container_images', 'root_review_attestation'}
SCHEMA = 'root_fixed_capacity_network_controller_v5'
R13_RUNTIME_HASHES = {'brain_https.py': '15af040c378166c60f6ec6e7ca912b51d682fe4547a6de11ebfef5ef26cebedc', 'controller.py': '1beed2de38f5fb4dadaf6224fc94bf4db0b320bff2008cc9ae47a0ae7325c20c', 'dns_native.py': '53c65633595880123c155a105f5238f63276d1bc601b02fc0ddc18121667c177', 'eks_https.py': 'e25ed2a1ca7ce8236ebe9e18e5fa0c8298046c682b71fbd6b71e7224d103f57b', 'install_owned_once.py': '29195dbc473ded10ee7c2565fb7e605f9b52c3f59816002ffdd94db70ace03fc', 'kube_native.py': '9fae13d7a6f07781d43871af97e02b358487e87866ed49264104e87daf98eb08', 'native_io.py': '1242740c98bd488047baa77cb0e93539af9279355dbff9c39b46a637e9105943', 'native_structure.py': '8db8098a8d39d146a1ef95ddc9584fcf916b4110858c79722ac6a50904d9fb59', 'nft_owner.py': '054a16bfaf4370fd71f716c63986bafb2ccd3f4aa78eebf4cf8b58b51b1afdab', 'nl_apply.py': '019081131fba5f86eb87b955fc6fd5304c031353860117f7f9b74a14dd4f79e3', 'observations.py': 'bc59af9e9bb60f7ace06021c4cb866b201d3bde1a757ba4587234736de138d33', 'original_process.py': 'f0940634592b00dbff8d8547744b2a26e90cd23bc9a4eacdc8a0c1d0ccb1273f', 'transition_adoption.py': 'eed800ed8acc35439358d7ff73a079342b7f1d138131534b4261f93d55e3cc6a', 'whole_witness.py': '3c2ab7edd68f4fc16d9736608249fa0895ab25d1ce431383645a23dba94b8776'}
CORE_IMAGE_REF = '153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@'
CORE_417 = CORE_IMAGE_REF + 'sha256:417ec2ba7649820700816d4a9cd422d857e2f3ede41a09875ec890e06e114f28'
CORE_C423 = CORE_IMAGE_REF + 'sha256:c4238ebdedc618a180183ba19e0748957c134bbce8c81c7987eea5ea8c0bc68a'
CORE_87CF = CORE_IMAGE_REF + 'sha256:87cf7de98bcf402a0438fea7ebf6025bd487db0e880189f1401e1170afb02c07'
CORE_2C68 = CORE_IMAGE_REF + 'sha256:2c68827818e8bcd53629835dff89ab66056907af3a5aa7721605ee726a4778ad'
CORE_A9FA = CORE_IMAGE_REF + 'sha256:a9fa2599db02016ff6a7cc90e95281448953fc4ee20160953042fc8c1c405494'
CORE_9913 = CORE_IMAGE_REF + 'sha256:9913ebfb5afc3620b8d6f4136ea1b9cc5acfda0c339199a99be4444fa10f417e'
# The ONE place the new head Core image digest appears in this file (set_head_digest.py).
CORE_CADC = CORE_IMAGE_REF + 'sha256:cadc0c4491109d5791438b6187b53620008f8a634ae8d93903f664ae18c18edd'
HEAD_NEW_CORE_DIGEST = 'sha256:85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876'
HEAD_DIGEST_PLACEHOLDER = 'sha256:' + '0' * 64
CORE_G5 = CORE_CADC
CORE_G6 = CORE_IMAGE_REF + 'sha256:750d5e46aee679075c2b88c163d22036093cf893edbe16bb5c2ca484f4275838'
CORE_G7 = CORE_IMAGE_REF + 'sha256:f809040367a1c6c9fea0e8f4b31486970f03ed68a979a5bdcd412ed95bd70dcb'
CORE_G8 = CORE_IMAGE_REF + 'sha256:0970e1188ceb5fa3ba52a1a11337f5fae7ac0657a66a69e08d24f9888f813826'
CORE_G11 = CORE_IMAGE_REF + 'sha256:8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc'
CORE_G12 = CORE_IMAGE_REF + 'sha256:b0ee27bd53443260e8e05123f9474454e8108310c4b94a7e72b6bae107cf1ac2'
CORE_G13 = CORE_IMAGE_REF + 'sha256:d8a86c844f0b2df14aa3ae3b0281f43be14a7f6aed3b1bf962816a603e966a1b'
CORE_G14 = CORE_IMAGE_REF + 'sha256:35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde'
CORE_G15 = CORE_IMAGE_REF + HEAD_NEW_CORE_DIGEST if isinstance(HEAD_NEW_CORE_DIGEST, str) else None
G14_CONFIG_SHA = '90fb39778f79963af7a515401df0e66d969de997d7762aed6f2c50284a733804'
G14_CONFIG = ETC / 'controller.r13-netlink-g14pair.production.json'
CORE_G9 = CORE_IMAGE_REF + 'sha256:7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6'
G9_CONFIG_SHA = '3d8ed6cf0341d6fe36ff190ade585321a1c88274577b9ebb57f8e7c235654111'
G9_CONFIG = ETC / 'controller.r13-netlink-g9pair.production.json'
R42_CORE_IMAGE_PAIRS = [{'image': CORE_417, 'image_id': CORE_417}, {'image': CORE_C423, 'image_id': CORE_C423}]
F5_CORE_IMAGE_PAIRS = [{'image': CORE_C423, 'image_id': CORE_C423}, {'image': CORE_87CF, 'image_id': CORE_87CF}]
G2_CORE_IMAGE_PAIRS = [{'image': CORE_87CF, 'image_id': CORE_87CF}, {'image': CORE_2C68, 'image_id': CORE_2C68}]
G3_CORE_IMAGE_PAIRS = [{'image': CORE_2C68, 'image_id': CORE_2C68}, {'image': CORE_A9FA, 'image_id': CORE_A9FA}]
G4_CORE_IMAGE_PAIRS = [{'image': CORE_A9FA, 'image_id': CORE_A9FA}, {'image': CORE_9913, 'image_id': CORE_9913}]
G5_CORE_IMAGE_PAIRS = [{'image': CORE_9913, 'image_id': CORE_9913}, {'image': CORE_G5, 'image_id': CORE_G5}]
G6_CORE_IMAGE_PAIRS = [{'image': CORE_CADC, 'image_id': CORE_CADC}, {'image': CORE_G6, 'image_id': CORE_G6}]
G7_CORE_IMAGE_PAIRS = [{'image': CORE_G6, 'image_id': CORE_G6}, {'image': CORE_G7, 'image_id': CORE_G7}]
G8_CORE_IMAGE_PAIRS = [{'image': CORE_G7, 'image_id': CORE_G7}, {'image': CORE_G8, 'image_id': CORE_G8}]
G9_CORE_IMAGE_PAIRS = [{'image': CORE_G8, 'image_id': CORE_G8}, {'image': CORE_G9, 'image_id': CORE_G9}]
CORE_G10 = CORE_IMAGE_REF + 'sha256:4fa5525f3b4bdac22a83260bac4fdd655106720b73ede11300f6f034451a6181'
G10_CONFIG = Path('/etc/dakasa/capacity-network/controller.r13-netlink-g10pair.production.json')
G10_CONFIG_SHA = '7b11191f9840a6ebf92f6f9332a438198d7b34b5546e69ca4869b624f8e7d6ed'
G10_CORE_IMAGE_PAIRS = [{'image': CORE_G9, 'image_id': CORE_G9}, {'image': CORE_G10, 'image_id': CORE_G10}]
G11_CONFIG = ETC / 'controller.r13-netlink-g11pair.production.json'
G11_CORE_IMAGE_PAIRS = [{'image': CORE_G10, 'image_id': CORE_G10}, {'image': CORE_G11, 'image_id': CORE_G11}]
G12_CORE_IMAGE_PAIRS = [{'image': CORE_G11, 'image_id': CORE_G11}, {'image': CORE_G12, 'image_id': CORE_G12}]
G13_CORE_IMAGE_PAIRS = [{'image': CORE_G12, 'image_id': CORE_G12}, {'image': CORE_G13, 'image_id': CORE_G13}]
G14_CORE_IMAGE_PAIRS = [{'image': CORE_G13, 'image_id': CORE_G13}, {'image': CORE_G14, 'image_id': CORE_G14}]
G15_CORE_IMAGE_PAIRS = [{'image': CORE_G14, 'image_id': CORE_G14}, {'image': CORE_G15, 'image_id': CORE_G15}]
G13_CONFIG = ETC / 'controller.r13-netlink-g13pair.production.json'
G15_CONFIG = ETC / 'controller.r13-netlink-g15pair.production.json'
# Same order and pins as the G12 Guardian's PAIR_CHAIN. Head last (sha None).
PAIR_CHAIN = (
    ('base', R42_CORE_IMAGE_PAIRS, BASE_CONFIG, BASE_CONFIG_SHA),
    ('f5pair', F5_CORE_IMAGE_PAIRS, F5_CONFIG, F5_CONFIG_SHA),
    ('g2pair', G2_CORE_IMAGE_PAIRS, G2_CONFIG, G2_CONFIG_SHA),
    ('g3pair', G3_CORE_IMAGE_PAIRS, G3_CONFIG, G3_CONFIG_SHA),
    ('g4pair', G4_CORE_IMAGE_PAIRS, G4_CONFIG, G4_CONFIG_SHA),
    ('g5pair', G5_CORE_IMAGE_PAIRS, G5_CONFIG, G5_CONFIG_SHA),
    ('g6pair', G6_CORE_IMAGE_PAIRS, G6_CONFIG, G6_CONFIG_SHA),
    ('g7pair', G7_CORE_IMAGE_PAIRS, G7_CONFIG, G7_CONFIG_SHA),
    ('g8pair', G8_CORE_IMAGE_PAIRS, G8_CONFIG, G8_CONFIG_SHA),
    ('g9pair', G9_CORE_IMAGE_PAIRS, G9_CONFIG, G9_CONFIG_SHA),
    ('g10pair', G10_CORE_IMAGE_PAIRS, G10_CONFIG, G10_CONFIG_SHA),
    ('g11pair', G11_CORE_IMAGE_PAIRS, G11_CONFIG, G11_CONFIG_SHA),
    ('g12pair', G12_CORE_IMAGE_PAIRS, G12_CONFIG, G12_CONFIG_SHA),
    ('g13pair', G13_CORE_IMAGE_PAIRS, G13_CONFIG, G13_CONFIG_SHA),
    ('g14pair', G14_CORE_IMAGE_PAIRS, G14_CONFIG, G14_CONFIG_SHA),
    ('g15pair', G15_CORE_IMAGE_PAIRS, G15_CONFIG, None),
)
# kube_native.approved_core_images (runtime-r13-prod, 9fae13d7...), verbatim rules.
KN_REPOSITORY = r'(?:ghcr\.io/dakasa-yggdrasil/yggdrasil-core|153828470928\.dkr\.ecr\.us-east-1\.amazonaws\.com/ghcr/dakasa-yggdrasil/yggdrasil-core)'


class Refused(Exception):
    pass


def require(ok, reason):
    if not ok:
        raise Refused(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def strict_loads(raw):
    def unique(rows):
        out = {}
        for k, v in rows:
            require(k not in out, 'DUPLICATE_JSON_KEY')
            out[k] = v
        return out

    def nonfinite(_):
        raise Refused('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)


def read_private(path, cap=32768, mode=0o600):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        require(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and a.st_nlink == 1
                and (mode is None and not stat.S_IMODE(a.st_mode) & 0o022 or stat.S_IMODE(a.st_mode) == mode),
                'ROOT_PRIVATE_REGULAR_FILE:' + path.name)
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= cap, 'BOUNDED_FILE:' + path.name)
        b = os.fstat(fd)
        require((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns)
                == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'STABLE_FILE_READ:' + path.name)
        return b''.join(chunks)
    finally:
        os.close(fd)


def approved_core_images(pairs):
    """Same closed rules as kube_native.approved_core_images (no runtime import)."""
    require(type(pairs) is list and 1 <= len(pairs) <= 2, 'ONE_OR_TWO_REVIEWED_CORE_IMAGE_PAIRS')
    images, runtimes = set(), set()
    for pair in pairs:
        require(type(pair) is dict and set(pair) == {'image', 'image_id'}, 'CLOSED_CORE_IMAGE_RUNTIME_PAIR')
        image, image_id = pair['image'], pair['image_id']
        require(isinstance(image, str) and re.fullmatch(KN_REPOSITORY + r'@sha256:[a-f0-9]{64}', image), 'APPROVED_CORE_IMMUTABLE_IMAGE')
        require(isinstance(image_id, str) and re.fullmatch(r'(?:docker-pullable://|containerd://)?(?:' + KN_REPOSITORY + r'@)?sha256:[a-f0-9]{64}', image_id),
                'ACTUAL_APPROVED_CORE_IMAGE_ID')
        a, b = image.rsplit(':', 1)[1], image_id.rsplit(':', 1)[1]
        require(a not in images and b not in runtimes, 'UNIQUE_CORE_IMAGE_AND_RUNTIME_DIGESTS')
        images.add(a)
        runtimes.add(b)


def no_zero_digest(pairs):
    """Beyond kube_native's rules: no PAIR_CHAIN link may admit the all-zero
    (placeholder) digest, whatever constant it came from."""
    require(all(p['image'].rsplit(':', 1)[1] != '0' * 64 and p['image_id'].rsplit(':', 1)[1] != '0' * 64 for p in pairs),
            'PAIR_CHAIN_LINK_ZERO_DIGEST')


def require_bound():
    require(PROPOSAL_BOUND is True and type(HEAD_NEW_CORE_DIGEST) is str
            and re.fullmatch('sha256:[a-f0-9]{64}', HEAD_NEW_CORE_DIGEST) is not None
            and HEAD_NEW_CORE_DIGEST != HEAD_DIGEST_PLACEHOLDER
            and type(G15_CONFIG_SHA) is str and re.fullmatch('[a-f0-9]{64}', G15_CONFIG_SHA) is not None
            and G15_CONFIG_SHA != '0' * 64 and CORE_G15 == CORE_IMAGE_REF + HEAD_NEW_CORE_DIGEST,
            'G15_RELEASE_AND_ROOT_CONFIG_NOT_BOUND')


def derive(r42_raw, chain_prefix_raws, attestation):
    require_bound()
    """chain_prefix_raws: the installed bytes of every link before the head, in
    PAIR_CHAIN order. Returns the head's canonical bytes."""
    require(HEAD_NEW_CORE_DIGEST != HEAD_DIGEST_PLACEHOLDER and re.fullmatch('sha256:[a-f0-9]{64}', HEAD_NEW_CORE_DIGEST),
            'HEAD_CORE_DIGEST_SET')
    require(PAIR_CHAIN[-1][3] is None and all(link[3] for link in PAIR_CHAIN[:-1])
            and len(chain_prefix_raws) == len(PAIR_CHAIN) - 1, 'PINNED_PAIR_CHAIN_SHAPE')
    require(sha(r42_raw) == R42_CONFIG_SHA, 'EXACT_INSTALLED_R42_CONFIG')
    r42 = strict_loads(r42_raw)
    require(type(r42) is dict and set(r42) == FIELDS and r42['core_container_images'] == R42_CORE_IMAGE_PAIRS, 'R42_CONFIG_SHAPE')
    reviews = [r42['root_review_attestation']]
    previous = None
    for (generation, pairs, _, pinned), raw in zip(PAIR_CHAIN, chain_prefix_raws):
        require(sha(raw) == pinned, 'EXACT_INSTALLED_PAIR_CHAIN_CONFIG:' + generation)
        link = strict_loads(raw)
        require(type(link) is dict and set(link) == FIELDS and link['schema'] == SCHEMA and link['execute'] is True
                and link['source_files_sha256'] == R13_RUNTIME_HASHES and link['core_container_images'] == pairs,
                'PAIR_CHAIN_LINK_SHAPE:' + generation)
        # The base was written indented by the R13 cutover (value comparisons
        # only); every later link was written canonically by its derivation.
        require(previous is None or canonical(link) == raw, 'PAIR_CHAIN_LINK_CANONICAL:' + generation)
        approved_core_images(pairs)
        no_zero_digest(pairs)
        if previous is None:
            require(all(link[k] == r42[k] for k in FIELDS - {'source_files_sha256', 'root_review_attestation'}),
                    'R13_BASE_IS_R42_PLUS_ROSTER_AND_REVIEW')
        else:
            require(all(link[k] == previous[k] for k in FIELDS - {'core_container_images', 'root_review_attestation'}),
                    'PAIR_CHAIN_LINK_ONLY_PAIR_AND_REVIEW:' + generation)
        require(link['root_review_attestation'] not in reviews, 'PAIR_CHAIN_LINK_REVIEW_NEW:' + generation)
        reviews.append(link['root_review_attestation'])
        previous = link
    head_pairs = PAIR_CHAIN[-1][1]
    require(head_pairs[0] == PAIR_CHAIN[-2][1][-1]
            and all(head_pairs[1]['image'] != p['image'] for _, pairs, _, _ in PAIR_CHAIN[:-1] for p in pairs),
            'HEAD_KEEPS_PREVIOUS_NEWEST_AND_NEVER_READMITS')
    require(isinstance(attestation, str) and 80 <= len(attestation) <= 4096 and attestation not in reviews,
            'NEW_EXPLICIT_ATTESTATION')
    approved_core_images(head_pairs)
    no_zero_digest(head_pairs)
    new = dict(previous)
    new['core_container_images'] = [dict(p) for p in head_pairs]   # the ONLY two changed fields
    new['root_review_attestation'] = attestation
    raw = canonical(new)
    require(len(raw) <= 32768 and strict_loads(raw) == new, 'BOUNDED_CANONICAL_HEAD_CONFIG')
    require(sorted(k for k in FIELDS if new[k] != previous[k]) == ['core_container_images', 'root_review_attestation'],
            'HEAD_DELTA_EXACTLY_PAIR_AND_REVIEW')
    require(sha(raw) == G15_CONFIG_SHA, 'EXACT_ROOT_REVIEWED_G15_CONFIG')
    return raw


def guardian_cross_check(r42_raw, chain_prefix_raws, raw, source_sha256):
    require_bound()
    if not os.path.lexists(GUARDIAN_SOURCE):
        return 'g15pair_guardian_not_installed'
    source = read_private(GUARDIAN_SOURCE, 1 << 20, None)
    require(sha(source) == source_sha256, 'EXACT_PINNED_G15PAIR_GUARDIAN_SOURCE')
    module = types.ModuleType('g15pair_guardian_definitions')
    module.__file__ = str(GUARDIAN_SOURCE)
    exec(compile(source, module.__file__, 'exec'), module.__dict__)   # definitions only; no action on import
    require([(g, p, str(c), s) for g, p, c, s in module.PAIR_CHAIN] == [(g, p, str(c), s) for g, p, c, s in PAIR_CHAIN],
            'SAME_PINNED_PAIR_CHAIN_AS_THE_GUARDIAN')
    require(module.pair_chain_controller_config_pure(r42_raw, [*chain_prefix_raws, raw]) == raw,
            'G15PAIR_GUARDIAN_REFUSES_DERIVED_CONFIG')
    return 'accepted_by_pinned_g15pair_guardian'


def write_new(path, raw):
    require_bound()
    if os.path.lexists(path):
        require(read_private(path) == raw, 'TARGET_EXISTS_WITH_DIFFERENT_BYTES')
        return 'identical'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            view = view[os.write(fd, view):]
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    require(read_private(path) == raw, 'WRITTEN_CONFIG_READBACK')
    return 'created'


def main():
    require_bound()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--attestation-file', required=True, type=Path)
    p.add_argument('--expected-guardian-sha256', required=True)
    p.add_argument('--out', type=Path)
    a = p.parse_args()
    require(os.geteuid() == 0 and sys.platform == 'linux', 'ROOT_LINUX_ONLY')
    require(re.fullmatch('[a-f0-9]{64}', a.expected_guardian_sha256) and a.expected_guardian_sha256 != '0' * 64, 'EXACT_PACKAGE_GUARDIAN_PIN')
    review = read_private(a.attestation_file, 8192).decode().removesuffix('\n')
    r42 = read_private(R42_CONFIG)
    prefix = [read_private(path) for _, _, path, _ in PAIR_CHAIN[:-1]]
    raw = derive(r42, prefix, review)
    cross = guardian_cross_check(r42, prefix, raw, a.expected_guardian_sha256)
    status = write_new(a.out, raw) if a.out else 'not_requested'
    print(json.dumps({'schema': 'r13_g15pair_controller_config_derivation_v1',
                      'head_core_digest': HEAD_NEW_CORE_DIGEST,
                      'pair_chain_config_sha256': {**{g: sha(v) for (g, _, _, _), v in zip(PAIR_CHAIN[:-1], prefix)}, 'g15pair': sha(raw)},
                      'guardian_cross_check': cross, 'write': status}, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (Refused, RuntimeError) as error:
        print(json.dumps({'schema': 'r13_g15pair_controller_config_derivation_refused_v1', 'guard': str(error)[:180]}), flush=True)
        raise SystemExit(2) from None
