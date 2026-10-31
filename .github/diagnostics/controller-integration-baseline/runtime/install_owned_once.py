"""Root-only NEW fixed hub installation. Source only until Root dispatch.

No package install/hooks, Guest create, cloud API, service start or reboot. The
caller owns a fresh explicit intent. Existing interfaces are never adopted or
deleted. A partial attempt stays HOLD with its original evidence intact.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

import controller
import nft_owner as nft

WG_BINARY = '/usr/bin/wg'
WG_SHA = 'd6b9717e9849349f5401f39dd9fcc554bcc05f955ba12b20b17f5bf0b09d3286'
ALIAS = 'dakasa-owned-capacity-overlay-v1'


def call(args, *, pass_fds=()):
    value = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False, pass_fds=pass_fds, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    nft.require(value.returncode == 0 and len(value.stdout) <= 65536, 'ORIGINAL_HUB_NATIVE_COMMAND_FAILED')
    return value.stdout


def once(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(directory)
    finally:os.close(directory)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', type=Path, required=True)
    p.add_argument('--install-seal', type=Path, required=True)
    a = p.parse_args()
    nft.require(os.geteuid() == 0, 'ROOT_HUB_INSTALL_ONLY')
    config = controller.load_config(a.config, execute=True)
    controller.private(a.install_seal)
    seal = json.loads(a.install_seal.read_text())
    nft.require(set(seal) == {'schema', 'execute', 'run_id', 'controller_config_sha256', 'hub_wg_config_path', 'hub_wg_config_sha256', 'hub_public_key', 'peer_public_keys', 'root_review_attestation'} and seal['schema'] == 'root_new_fixed_wireguard_hub_install_v1' and seal['execute'] is True, 'ROOT_NEW_HUB_INSTALL_SEAL')
    nft.require(re.fullmatch(r'wg-install-[0-9a-f]{20}', seal['run_id']) and len(seal['root_review_attestation']) >= 80 and hashlib.sha256(a.config.read_bytes()).hexdigest() == seal['controller_config_sha256'], 'EXACT_ROOT_INSTALL_REVIEW')
    nft.require(hashlib.sha256(Path(WG_BINARY).read_bytes()).hexdigest() == WG_SHA, 'EXACT_ALREADY_STAGED_WG_TOOL')
    nft.require(Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() == '1', 'EXISTING_HOST_FORWARDING_REQUIRED')
    controller.private(controller.STATE, True)
    lock = os.open(controller.STATE / 'controller.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    links = json.loads(call(['/usr/sbin/ip', '-j', 'link', 'show']))
    nft.require(not any(v['ifname'] == nft.WG for v in links), 'NO_ADOPTION_OR_RESTART_EXISTING_INTERFACE')
    peers = seal['peer_public_keys']
    nft.require(set(peers) == set(nft.PEERS) and len(set(peers.values())) == len(nft.PEERS), 'EXACT_UNIQUE_SLOT_PEER_KEYS')
    for value in peers.values():
        nft.require(len(base64.b64decode(value, validate=True)) == 32, 'NATIVE_WG_PUBLIC_KEY_SHAPE')
    nft.require(len(base64.b64decode(seal['hub_public_key'], validate=True)) == 32 and seal['hub_public_key'] not in peers.values(), 'EXACT_DISTINCT_HUB_PUBLIC_KEY')
    source = Path(seal['hub_wg_config_path'])
    nft.require(source == Path('/etc/dakasa/capacity-network/hub-wg.conf'), 'FIXED_PRIVATE_HUB_CONFIG_PATH')
    controller.private(source)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 65537)
        nft.require(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == seal['hub_wg_config_sha256'], 'ORIGINAL_PRIVATE_HUB_CONFIG_SHA')
        # setconf does not accept wg-quick's Address/Table/route hooks. Root's
        # fixed file must contain one Interface/privatekey/listenport and exactly
        # the16 preapproved public-key/allowedIP peer pairs, no executable hooks.
        text = raw.decode('ascii')
        nft.require(not re.search(r'(?im)^\s*(?:Pre|Post|Address|DNS|Table|SaveConfig|Endpoint|PresharedKey|PersistentKeepalive)', text), 'NO_HUB_HOOK_OR_DYNAMIC_ENDPOINT')
        sections = re.split(r'(?m)^\[Peer\]\s*$', text)
        head = sections.pop(0)
        lines = [v.strip() for v in head.splitlines() if v.strip()]
        nft.require(len(lines) == 3 and lines[0] == '[Interface]' and re.fullmatch(r'PrivateKey\s*=\s*[A-Za-z0-9+/]{43}=', lines[1]) and re.fullmatch(r'ListenPort\s*=\s*51820', lines[2]), 'EXACT_HUB_INTERFACE_CONFIG')
        nft.require(len(sections) == 16, 'EXACT_HUB_PEER_CONFIG')
        actual = {}
        for section in sections:
            values = [v.strip() for v in section.splitlines() if v.strip()]
            nft.require(len(values) == 2 and re.fullmatch(r'PublicKey\s*=\s*[A-Za-z0-9+/]{43}=', values[0]) and re.fullmatch(r'AllowedIPs\s*=\s*10\.201\.24\.[0-9]{1,3}/32', values[1]), 'EXACT_HUB_PEER_FIELDS')
            key = values[0].split('=', 1)[1].strip()
            address = values[1].split('=', 1)[1].strip()
            nft.require(address.endswith('/32') and address[:-3] not in actual, 'EXACT_HUB_PEER_ADDRESS')
            actual[address[:-3]] = key
        nft.require(actual == peers, 'EXACT_SEALED_PEER_KEY_TO_SLOT_BINDING')
        controller.private(controller.STATE, True)
        intent = controller.STATE / (seal['run_id'] + '-INTENT.json')
        import native_io
        native_io.configure()
        snapshot=nft.owned_table_snapshot()
        nft.require(snapshot.exists is False,'LAB_INSTALL_REQUIRES_ABSENT_OWN_TABLE')
        controller.ct_mark_preflight(False)
        once(intent, {'schema': 'original_fixed_hub_install_intent_v1', 'run_id': seal['run_id'], 'seal_sha256': hashlib.sha256(a.install_seal.read_bytes()).hexdigest(), 'interface_previously_absent': True, 'implicit_retry': False, 'status': 'POSSIBLE_KERNEL_EFFECT'})
        # Load empty DROP guards before the new interface can pass a packet.
        ownership=nft.revalidate_owned_ruleset(snapshot)
        initialized,pin=nft.native_initialize_static(apply=lambda: True,_ownership=ownership)
        nft.require(pin is not None and initialized['static_dynamic_collections_empty'] is True,'LAB_ORIGINAL_EMPTY_NFT_ECHO_REQUIRED')
        native_io.end_initialization()
        call(['/usr/sbin/ip', 'link', 'add', 'dev', nft.WG, 'type', 'wireguard'])
        call(['/usr/sbin/ip', 'link', 'set', 'dev', nft.WG, 'alias', ALIAS])
        call(['/usr/sbin/ip', 'link', 'set', 'dev', nft.WG, 'mtu', '1280'])
        os.lseek(fd, 0, os.SEEK_SET)
        call([WG_BINARY, 'setconf', nft.WG, '/proc/self/fd/' + str(fd)], pass_fds=(fd,))
        nft.require(call([WG_BINARY, 'show', nft.WG, 'public-key']).decode().strip() == seal['hub_public_key'], 'ORIGINAL_NATIVE_HUB_PUBLIC_KEY')
        for address in ('10.201.24.1', '10.201.24.2', '10.201.24.3'):
            call(['/usr/sbin/ip', '-4', 'address', 'add', address + '/32', 'dev', nft.WG])
        # Native route creation requires the link ready. Empty owned DROP guards
        # were loaded before creation; no backend is admitted by bringing it UP.
        call(['/usr/sbin/ip', 'link', 'set', 'dev', nft.WG, 'up'])
        for address in nft.PEERS:
            call(['/usr/sbin/ip', '-4', 'route', 'add', address + '/32', 'dev', nft.WG, 'proto', 'static'])
        checked = json.loads(call(['/usr/sbin/ip', '-j', 'link', 'show', 'dev', nft.WG]))
        nft.require(len(checked) == 1 and checked[0].get('ifalias') == ALIAS and checked[0]['mtu'] == 1280 and 'UP' in checked[0]['flags'], 'ORIGINAL_NATIVE_HUB_RETURN')
        allowed = call([WG_BINARY, 'show', nft.WG, 'allowed-ips']).decode().splitlines()
        nft.require(len(allowed) == 16 and {v.split()[1].removesuffix('/32'): v.split()[0] for v in allowed} == peers, 'ORIGINAL_NATIVE_PEER_BINDING')
        import native_structure
        native_structure.revalidate(pin)  # Same-process echo/handles after WG setup.
        once(controller.STATE / (seal['run_id'] + '-RETURN.json'), {'schema': 'original_fixed_hub_install_return_v1', 'run_id': seal['run_id'], 'ifindex': checked[0]['ifindex'], 'interface': nft.WG, 'empty_guard_loaded_before_up': True, 'peer_count': len(peers), 'private_key_exported': False, 'controller_started': False, 'native_TLS_or_Guest_path_qualified': False})
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
