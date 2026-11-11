"""G15 fixed pair."""
import argparse
import ast
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
import types
ROOT=Path('/opt/dakasa/capacity-network')
HERE=ROOT/'network-boot-recovery-r13-g20pair-source-v1'
SELF=HERE/'network_guardian.py'
CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g20pair.production.json')
R13_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-netlink-source-v1'
R13_PREDECESSOR_SOURCE_SHA='2f5bb7e1946d905fbfc83c0662b0df281f6fb9f1fba2c85b4036ba825376021c'
R13_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-netlink.production.json')
R13_PREDECESSOR_SCHEMA='Root_standing_R13_netlink_successor_Core262_R43_network_boot_terminal_recovery_v1'
PREDECESSOR_HERE=ROOT/'network-boot-recovery-Core262-r43-adoption-source-v1'
PREDECESSOR_SOURCE_SHA='d211254aa392513bd3384d05fd87c3f18179d18c7bf13370323b74ae97367d94'
PREDECESSOR_CONFIG_SHA='7f0f1f2b979bedf22f96d6cdb12c2dd3cff5d53c421135b1381d703c1bc2ee96'
LEDGER=Path('/var/lib/dakasa-capacity-network-recovery')
RUN=Path('/run/dakasa-capacity-network')
UNIT='dakasa-capacity-network.service'
HUB='dakasa-capacity-network-hub.service'
COLD='dakasa-capacity-network-cold-transport.service'
GUARDIAN='dakasa-capacity-network-guardian.service'
RUNTIME=ROOT/'source-r13-netlink-v1'
NEW_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g20pair.production.json')
BASE_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink.production.json')
BASE_CONFIG_SHA='460b0fd49191248fecffa7009636a82391815a64fc23db11e039b7ee9f5d928a'
F5PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-f5pair.production.json')
F5PAIR_CONFIG_SHA='ed797c474d71a064f4e9dfe99a4c2ddc6530b49ae712eb78033b75967c2b6621'
G2PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g2pair.production.json')
G2PAIR_CONFIG_SHA='9168e9c661a40a9f1761e0938deb7fda44a4ce3a0a3e852f8cab281bdb71e48b'
G3PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g3pair.production.json')
G3PAIR_CONFIG_SHA='7b452ccca85f722e59c3748dc127f0cccda3e54bbcecc9f74c9b4c6cbc589068'
G4PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g4pair.production.json')
G4PAIR_CONFIG_SHA='431a42ee4caba690a6a479e1ca19d842835dc23d8acccb3bc63a05bee7ea663b'
G5PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g5pair.production.json')
G5PAIR_CONFIG_SHA='1b38e2cb050b9c98fc6edf07d867edaed1758aba1bdb496ad4566f13e5fb6a45'
G6PAIR_CONFIG=Path('/etc/dakasa/capacity-network/controller.r13-netlink-g6pair.production.json')
G6PAIR_CONFIG_SHA='8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
R42_CONFIG_SHA='0f4631320e7319cf4da3c37586bbee2ae977eb338831fb0e991ed735cb9113c3'
CORE_IMAGE_REF='153828470928.dkr.ecr.us-east-1.amazonaws.com/ghcr/dakasa-yggdrasil/yggdrasil-core@'
CORE_417=CORE_IMAGE_REF+'sha256:417ec2ba7649820700816d4a9cd422d857e2f3ede41a09875ec890e06e114f28'
CORE_C423=CORE_IMAGE_REF+'sha256:c4238ebdedc618a180183ba19e0748957c134bbce8c81c7987eea5ea8c0bc68a'
CORE_87CF=CORE_IMAGE_REF+'sha256:87cf7de98bcf402a0438fea7ebf6025bd487db0e880189f1401e1170afb02c07'
CORE_2C68=CORE_IMAGE_REF+'sha256:2c68827818e8bcd53629835dff89ab66056907af3a5aa7721605ee726a4778ad'
CORE_A9FA=CORE_IMAGE_REF+'sha256:a9fa2599db02016ff6a7cc90e95281448953fc4ee20160953042fc8c1c405494'
CORE_9913=CORE_IMAGE_REF+'sha256:9913ebfb5afc3620b8d6f4136ea1b9cc5acfda0c339199a99be4444fa10f417e'
CORE_CADC=CORE_IMAGE_REF+'sha256:cadc0c4491109d5791438b6187b53620008f8a634ae8d93903f664ae18c18edd'
PROPOSAL_BOUND=True
HEAD_CORE_SOURCE='d083f7d5d52e15c22feb38fff56e024354ac86ae'
HEAD_NEW_CORE_DIGEST='sha256:8dcf22ae1aa0e16c5cace160c4d71398363e460ac54f6ca80a9c32ffbda5cac9'
HEAD_DIGEST_PLACEHOLDER='sha256:'+'0'*64
CORE_G5=CORE_CADC
CORE_G6=CORE_IMAGE_REF+'sha256:750d5e46aee679075c2b88c163d22036093cf893edbe16bb5c2ca484f4275838'
CORE_G7=CORE_IMAGE_REF+'sha256:f809040367a1c6c9fea0e8f4b31486970f03ed68a979a5bdcd412ed95bd70dcb'
CORE_G8=CORE_IMAGE_REF+'sha256:0970e1188ceb5fa3ba52a1a11337f5fae7ac0657a66a69e08d24f9888f813826'
CORE_G11=CORE_IMAGE_REF+'sha256:8e6d44d86bbae4463652d4bf9b3583241483a0813a4d34c7254b9c2e56dccafc'
CORE_G12=CORE_IMAGE_REF+'sha256:b0ee27bd53443260e8e05123f9474454e8108310c4b94a7e72b6bae107cf1ac2'
CORE_G13=CORE_IMAGE_REF+'sha256:d8a86c844f0b2df14aa3ae3b0281f43be14a7f6aed3b1bf962816a603e966a1b'
CORE_G14=CORE_IMAGE_REF+'sha256:35195e4ddff2a69f2ae7fca8f24b43177c61c49f12117a4fe4925a43e9cd6fde'
CORE_G15=CORE_IMAGE_REF+'sha256:85be238c7f5b15760f7eb903646cc48f6b4b86a6995d0a4727a1ba0d86d06876'
CORE_G16=CORE_IMAGE_REF+'sha256:311e5c19868a67f900b318e059a806e45e5dd217d0c411a03bcd598f6f10d5ce'
CORE_G17=CORE_IMAGE_REF+'sha256:9b6e2a5d06eed90b7b44d059d3f78a405a21430a7b104f17498c904f499bdd97'
G17_CONTROLLER_CONFIG_SHA='396a8f49baa8fd2851c7a93c3fb88ea67f9efe621c143bfff713e822e1116602'
G17_CORE_IMAGE_PAIRS=[{'image':CORE_G16,'image_id':CORE_G16},{'image':CORE_G17,'image_id':CORE_G17}]
CORE_G18=CORE_IMAGE_REF+'sha256:f02ec7b916b4d8b23a8bfe91703af2b3e8f33f25fd943b18642f9218baa1ee60'
G18_CONTROLLER_CONFIG_SHA='d8ed4b268c112fc396860b57f57b36090dcc8b63f768a3a47b291984aa6eab1a'
G18_CORE_IMAGE_PAIRS=[{'image':CORE_G17,'image_id':CORE_G17},{'image':CORE_G18,'image_id':CORE_G18}]
CORE_G19=CORE_IMAGE_REF+'sha256:ed5ee3a2a5e90e54acc3cc2492fcc302a85e1b7adb6f545c605c5bfe2a730b42'
G19_CONTROLLER_CONFIG_SHA='c5132de2b021eefdd0f3688edc3a65cee8d0d29d66f511d95a9bf05f70ac3e64'
G19_CORE_IMAGE_PAIRS=[{'image':CORE_G17,'image_id':CORE_G17},{'image':CORE_G19,'image_id':CORE_G19}]
CORE_G20=CORE_IMAGE_REF+HEAD_NEW_CORE_DIGEST if type(HEAD_NEW_CORE_DIGEST)is str else None
G20_CONTROLLER_CONFIG_SHA='ad85a5406e9499ad0e7685e92f7f90d0e1605efc2e44235aa2238bb24cec2dae'
G20_CORE_IMAGE_PAIRS=[{'image':CORE_G19,'image_id':CORE_G19},{'image':CORE_G20,'image_id':CORE_G20}]
G14_CONTROLLER_CONFIG_SHA='90fb39778f79963af7a515401df0e66d969de997d7762aed6f2c50284a733804'
CORE_G9=CORE_IMAGE_REF+'sha256:7f86e55cebd3dfcd3e1e027d8ddb573358ba8b42753348bfbda108bf6d39a0b6'
G9_CONTROLLER_CONFIG_SHA='3d8ed6cf0341d6fe36ff190ade585321a1c88274577b9ebb57f8e7c235654111'
G9_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g9pair-source-v1'
G9_PREDECESSOR_SOURCE_SHA='6defe12adc0cac920c767c09c49c25db589d9ec9a0dee5abc0f3cc03dfe18765'
G9_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g9pair.production.json')
G9_PREDECESSOR_CONFIG_SHA='af0ae4a82c5ee7504025cf4564b67ea941cc99122677aa1fa8a82f96c6a44a87'
G9_PREDECESSOR_SCHEMA='Root_standing_R13_g9pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
R42_CORE_IMAGE_PAIRS=[{'image':CORE_417,'image_id':CORE_417},{'image':CORE_C423,'image_id':CORE_C423}]
F5_CORE_IMAGE_PAIRS=[{'image':CORE_C423,'image_id':CORE_C423},{'image':CORE_87CF,'image_id':CORE_87CF}]
G2_CORE_IMAGE_PAIRS=[{'image':CORE_87CF,'image_id':CORE_87CF},{'image':CORE_2C68,'image_id':CORE_2C68}]
G3_CORE_IMAGE_PAIRS=[{'image':CORE_2C68,'image_id':CORE_2C68},{'image':CORE_A9FA,'image_id':CORE_A9FA}]
G4_CORE_IMAGE_PAIRS=[{'image':CORE_A9FA,'image_id':CORE_A9FA},{'image':CORE_9913,'image_id':CORE_9913}]
G5_CORE_IMAGE_PAIRS=[{'image':CORE_9913,'image_id':CORE_9913},{'image':CORE_G5,'image_id':CORE_G5}]
G6_CORE_IMAGE_PAIRS=[{'image':CORE_CADC,'image_id':CORE_CADC},{'image':CORE_G6,'image_id':CORE_G6}]
G7_CORE_IMAGE_PAIRS=[{'image':CORE_G6,'image_id':CORE_G6},{'image':CORE_G7,'image_id':CORE_G7}]
G8_CORE_IMAGE_PAIRS=[{'image':CORE_G7,'image_id':CORE_G7},{'image':CORE_G8,'image_id':CORE_G8}]
G9_CORE_IMAGE_PAIRS=[{'image':CORE_G8,'image_id':CORE_G8},{'image':CORE_G9,'image_id':CORE_G9}]
CORE_G10=CORE_IMAGE_REF+'sha256:4fa5525f3b4bdac22a83260bac4fdd655106720b73ede11300f6f034451a6181'
G10_CONTROLLER_CONFIG_SHA='7b11191f9840a6ebf92f6f9332a438198d7b34b5546e69ca4869b624f8e7d6ed'
G10_CORE_IMAGE_PAIRS=[{'image':CORE_G9,'image_id':CORE_G9},{'image':CORE_G10,'image_id':CORE_G10}]
G11_CORE_IMAGE_PAIRS=[{'image':CORE_G10,'image_id':CORE_G10},{'image':CORE_G11,'image_id':CORE_G11}]
G12_CORE_IMAGE_PAIRS=[{'image':CORE_G11,'image_id':CORE_G11},{'image':CORE_G12,'image_id':CORE_G12}]
G13_CORE_IMAGE_PAIRS=[{'image':CORE_G12,'image_id':CORE_G12},{'image':CORE_G13,'image_id':CORE_G13}]
G14_CORE_IMAGE_PAIRS=[{'image':CORE_G13,'image_id':CORE_G13},{'image':CORE_G14,'image_id':CORE_G14}]
G15_CORE_IMAGE_PAIRS=[{'image':CORE_G14,'image_id':CORE_G14},{'image':CORE_G15,'image_id':CORE_G15}]
G16_CORE_IMAGE_PAIRS=[{'image':CORE_G15,'image_id':CORE_G15},{'image':CORE_G16,'image_id':CORE_G16}]
G13_CONTROLLER_CONFIG_SHA='2fafe364344596ec0ab4a87a1887c8a4bcc581b103937fedb807e624fc3e6ac0'
G12_CONTROLLER_CONFIG_SHA='7c05da2f2ab22a08abd57d5e514e71c7c378e03387a532a8189e1845e3865879'
G11_CONTROLLER_CONFIG_SHA='a3706d21323a4cce2ef1d0746a9daffd81c1dad538f028635765bcbc116c7777'
G16_CONTROLLER_CONFIG_SHA='0549d1941ebc50fd77cd3800c3b4afb78505d0de6daa76c4fd0b04a2f73abe7d'
PAIR_CHAIN=(('base',R42_CORE_IMAGE_PAIRS,BASE_CONFIG,BASE_CONFIG_SHA),('f5pair',F5_CORE_IMAGE_PAIRS,F5PAIR_CONFIG,F5PAIR_CONFIG_SHA),('g2pair',G2_CORE_IMAGE_PAIRS,G2PAIR_CONFIG,G2PAIR_CONFIG_SHA),('g3pair',G3_CORE_IMAGE_PAIRS,G3PAIR_CONFIG,G3PAIR_CONFIG_SHA),('g4pair',G4_CORE_IMAGE_PAIRS,G4PAIR_CONFIG,G4PAIR_CONFIG_SHA),('g5pair',G5_CORE_IMAGE_PAIRS,G5PAIR_CONFIG,G5PAIR_CONFIG_SHA),('g6pair',G6_CORE_IMAGE_PAIRS,G6PAIR_CONFIG,G6PAIR_CONFIG_SHA),('g7pair',G7_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g7pair.production.json'),'d68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'),('g8pair',G8_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g8pair.production.json'),'42b9d05dac25610678ebce295335ead8b6086a87527fcd5ad030413a37a2a1a5'),('g9pair',G9_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g9pair.production.json'),G9_CONTROLLER_CONFIG_SHA),('g10pair',G10_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g10pair.production.json'),G10_CONTROLLER_CONFIG_SHA),('g11pair',G11_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g11pair.production.json'),G11_CONTROLLER_CONFIG_SHA),('g12pair',G12_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g12pair.production.json'),G12_CONTROLLER_CONFIG_SHA),('g13pair',G13_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g13pair.production.json'),G13_CONTROLLER_CONFIG_SHA),('g14pair',G14_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g14pair.production.json'),G14_CONTROLLER_CONFIG_SHA),('g15pair',G15_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g15pair.production.json'),'9094bab152bae7be581b524fb32417c7cfb320ce1ad46f9a171347d3043fa4a5'),('g16pair',G16_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g16pair.production.json'),G16_CONTROLLER_CONFIG_SHA),('g17pair',G17_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g17pair.production.json'),G17_CONTROLLER_CONFIG_SHA),('g18pair',G18_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g18pair.production.json'),G18_CONTROLLER_CONFIG_SHA),('g19pair',G19_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g19pair.production.json'),G19_CONTROLLER_CONFIG_SHA),('g20pair',G20_CORE_IMAGE_PAIRS,NEW_CONFIG,None),)
ALLOWED_CORE_IMAGE_PAIRS=tuple(pairs for _,pairs,_,_ in PAIR_CHAIN)
F5PAIR_PREDECESSOR_SOURCE_SHA='d83f892b087b6c604928d9a21e47af5f6086124eeecadb08e6560f47e631afeb'
F5PAIR_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-f5pair.production.json')
F5PAIR_PREDECESSOR_SCHEMA='Root_standing_R13_f5pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
F5PAIR_PREDECESSOR_CONFIG_SHA='afcfe2e5cad8dbf59732fb805e7f6c4a709608f36ba77bc112ca6633c8e3833c'
G2PAIR_PREDECESSOR_SOURCE_SHA='9e45ade0254496bf04458b85d0214208bcbafcd4b7e4af7285388da9c63ec1da'
G2PAIR_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g2pair.production.json')
G2PAIR_PREDECESSOR_SCHEMA='Root_standing_R13_g2pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G2PAIR_PREDECESSOR_CONFIG_SHA='494a57d8d4995f9f52348e6153bca5e00a73b873fbd69e8e36c187407cc0f57f'
G3PAIR_PREDECESSOR_SOURCE_SHA='9e7d88e29a8dce5296f58df33db0ae2c7853db5d6801836ca9c1a4311f73d985'
G3PAIR_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g3pair.production.json')
G3PAIR_PREDECESSOR_SCHEMA='Root_standing_R13_g3pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G3PAIR_PREDECESSOR_CONFIG_SHA='2922be85534c7d93257a9d703af8509c72e585e5683edfd35496ff8294df40d9'
G4PAIR_PREDECESSOR_SOURCE_SHA='81f7f53b9e201955cf9d53c7a8b8a791ef5bb9a143343a4f28a93b72198a9b45'
G4PAIR_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g4pair.production.json')
G4PAIR_PREDECESSOR_SCHEMA='Root_standing_R13_g4pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G4PAIR_PREDECESSOR_CONFIG_SHA='385928fe10e25980b918ca44bacd5b7e8b901cd2cbcde2bae8304e58d8931997'
G5PAIR_PREDECESSOR_SOURCE_SHA='e38fe46112f471ff02565fa5fdead6315606c071cfdb074144795f1b9923c230'
G5PAIR_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g5pair.production.json')
G5PAIR_PREDECESSOR_SCHEMA='Root_standing_R13_g5pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G5PAIR_PREDECESSOR_CONFIG_SHA='180b38fa905099e57776e944eda2be856ccc89bc070ad6b67a9142ab380139ca'
G6_PREDECESSOR_SOURCE_SHA='6c2cc19f1f962d9d8eaec0cd5e6f813bf49004f8ff6fef9c9fe9f8f0310d8f1b'
G6_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g6pair.production.json')
G6_PREDECESSOR_SCHEMA='Root_standing_R13_g6pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G6_PREDECESSOR_CONFIG_SHA='be5b25495056bd25e1512827b5ccbe7236f84928b4d20515f5000383771dcc79'
G6_CONTROLLER_CONFIG_SHA='8b74f1de7e49e44b4ad140b59767e441cc6adaf6c0689d684ecdc301bcee6c5e'
G7_CONTROLLER_CONFIG_SHA='d68912a7e24b68e6cc51faeedba4c0987c65b2a14d439d18483706bd3fd18fbf'
G8_CONTROLLER_CONFIG_SHA='42b9d05dac25610678ebce295335ead8b6086a87527fcd5ad030413a37a2a1a5'
G15_CONTROLLER_CONFIG_SHA='9094bab152bae7be581b524fb32417c7cfb320ce1ad46f9a171347d3043fa4a5'
G8_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g8pair-source-v1'
G8_PREDECESSOR_SOURCE_SHA='8259638127d811079d6a461d3bd7407f8a53ff3ebb75e8061bf8538dcf6508b9'
G8_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g8pair.production.json')
G8_PREDECESSOR_CONFIG_SHA='a02690f5e7a8c000478ceca6c4f4715e7b589814bf93fc5cbefe3bd9126e08d3'
G8_PREDECESSOR_SCHEMA='Root_standing_R13_g8pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G7_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g7pair-source-v1'
G7_PREDECESSOR_SOURCE_SHA='2379e9cb0fcf36faf7dfe58e930d0eb6ae97ba4d177db6610a23583d0a00a8aa'
G7_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g7pair.production.json')
G7_PREDECESSOR_CONFIG_SHA='dd7d449ea8fdba60a43d6badb138ea9496e1342572f90633e62d7b87d9b44866'
G7_PREDECESSOR_SCHEMA='Root_standing_R13_g7pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
G6_BOOT_V2_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g6pair-boot-v2-source-v1'
G6_BOOT_V2_PREDECESSOR_SOURCE_SHA='f3152cc6d8c5d7edee2e5349db17fac4b8650a18423dfc207c04fcc116955e6d'
G6_BOOT_V2_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g6pair-boot-v2.production.json')
G6_BOOT_V2_PREDECESSOR_SCHEMA='Root_standing_R13_g6pair_boot_v2_successor_Core262_R43_network_boot_terminal_recovery_v1'
G6_BOOT_V2_PREDECESSOR_CONFIG_SHA='faa6b2cb3132ce2e0ee4304bd833d7f0f999850244014d355f1c33ed176ebb83'
PAIR_STANDING_CHAIN=(('f5pair',F5PAIR_PREDECESSOR_SOURCE_SHA,F5PAIR_PREDECESSOR_CONFIG,F5PAIR_PREDECESSOR_SCHEMA,F5PAIR_PREDECESSOR_CONFIG_SHA,F5PAIR_CONFIG_SHA),('g2pair',G2PAIR_PREDECESSOR_SOURCE_SHA,G2PAIR_PREDECESSOR_CONFIG,G2PAIR_PREDECESSOR_SCHEMA,G2PAIR_PREDECESSOR_CONFIG_SHA,G2PAIR_CONFIG_SHA),('g3pair',G3PAIR_PREDECESSOR_SOURCE_SHA,G3PAIR_PREDECESSOR_CONFIG,G3PAIR_PREDECESSOR_SCHEMA,G3PAIR_PREDECESSOR_CONFIG_SHA,G3PAIR_CONFIG_SHA),('g4pair',G4PAIR_PREDECESSOR_SOURCE_SHA,G4PAIR_PREDECESSOR_CONFIG,G4PAIR_PREDECESSOR_SCHEMA,G4PAIR_PREDECESSOR_CONFIG_SHA,G4PAIR_CONFIG_SHA),('g5pair',G5PAIR_PREDECESSOR_SOURCE_SHA,G5PAIR_PREDECESSOR_CONFIG,G5PAIR_PREDECESSOR_SCHEMA,G5PAIR_PREDECESSOR_CONFIG_SHA,G5PAIR_CONFIG_SHA),)
OLD_CONFIG=Path('/etc/dakasa/capacity-network/controller.r42-cold-unknown184014.production.json')
HUB_RUNTIME=ROOT/'source-r42-cold-unknown184014-v1'
HUB_SOURCE=ROOT/'network-boot-recovery-r42-source-v1/hub_boot_once.py'
HUB_CONFIG=Path('/etc/dakasa/capacity-network/hub-boot.r42.production.json')
R42_HUB_SEAL_SHA='2419808ffe2dea1bda4fee0ccc0cbe2817d573020b27888f01357af2e6853a16'
HUB13_SOURCE=ROOT/'network-boot-recovery-r13-hub-v1/hub_boot_once.py'
HUB13_CONFIG=Path('/etc/dakasa/capacity-network/hub-boot.r13.production.json')
HUB13_SEAL_FIELDS={'schema','execute','source_sha256','runtime_source_files_sha256','controller_config_sha256','host_machine_id_sha256','hub_wg_config_sha256','hub_public_key','peer_public_keys','historical_hub_source_sha256','historical_hub_seal_sha256','historical_initial_boot_id','installed_in_boot_id','predecessor_boot_intent_sha256','predecessor_boot_return_sha256','root_review_attestation'}
BASE_PATH=ROOT/'mss1240-transport-source-v1/mss_transport.py'
BASE_SHA='fa013d28e1514d2e368011b63d6c2d2dbdb0d4db904ada6dc0d1166e04788d9b'
HUB_SHA='8e3e1256f89d2b2b77d115550e23b49f75cebab7f30e54de8152dbf0579c58c5'
COVERAGE_SHA='eb7ed1fcbcc665cdc3603812a10103b4e19dd0b66693b99dc8cfeb15adceeb88'
JOURNAL_SHA='b0c153b69cc8275e1e330cb3c584b498c1685c1b999c4b5c7b972f164c96db6c'
INITIAL_BOOT='7d6b3ec1-139d-4089-bac1-4621cbff83d0'
PROOF_CACHE_SHA='c2e0b981a2843c15dd5907cc186e4c23a7d844a78c1ce4f7e2e3578704eb5b4b'
CURRENT_TAIL_SHA='c18809987960f9aea524240f7ea6886a1ed782e5c4001e68edac875bbbe3431d'
QUALIFICATION_INITIALIZER_SHA='d73ade12564ba7b672a4dbdf8225e99af13a64a9b8aff4a41fb1a0225bef9ec8'
CURRENT_READER_SHA='1124dfbfbd57c60decc4fdcb0233c03253e87a941f50c8fa5b6aad3e28ae30cd'
INITIAL_COLD_SHA='0e690f4b74303da774aa7d5a651444e7f74c8445428af38002192bf1079b5799'
R42_RUNTIME_HASHES={'nft_owner.py':'50afccf6e2d0725f33d5da9f49125ecf94a842ab00d0808b5a6af5a49c6f7232','transition_adoption.py':'40cd2b6cd76397d1544540a1e6ea8992ee8103cb43da67e8e064b93db4f60ed5','install_owned_once.py':'29195dbc473ded10ee7c2565fb7e605f9b52c3f59816002ffdd94db70ace03fc','brain_https.py':'15af040c378166c60f6ec6e7ca912b51d682fe4547a6de11ebfef5ef26cebedc','controller.py':'1f586f98f6265fc6cc37b662a3990a7555bed31f777038bfa82395cdbf1c75da','observations.py':'bc59af9e9bb60f7ace06021c4cb866b201d3bde1a757ba4587234736de138d33','dns_native.py':'53c65633595880123c155a105f5238f63276d1bc601b02fc0ddc18121667c177','kube_native.py':'9fae13d7a6f07781d43871af97e02b358487e87866ed49264104e87daf98eb08','original_process.py':'3dd813c9a74a62779b0db9fdc54179a1daab3fb9aa106dfeed4a886abf7e3e87','native_io.py':'1242740c98bd488047baa77cb0e93539af9279355dbff9c39b46a637e9105943','native_structure.py':'5ecd0bbf044138a69bc9f8267a1b2afc5a6a966e6597d3feaa436fb2f30aa078','whole_witness.py':'3c2ab7edd68f4fc16d9736608249fa0895ab25d1ce431383645a23dba94b8776','eks_https.py':'e25ed2a1ca7ce8236ebe9e18e5fa0c8298046c682b71fbd6b71e7224d103f57b'}
HUB_RUNTIME_HASHES=R42_RUNTIME_HASHES
RUNTIME_HASHES={'brain_https.py':'15af040c378166c60f6ec6e7ca912b51d682fe4547a6de11ebfef5ef26cebedc','controller.py':'1beed2de38f5fb4dadaf6224fc94bf4db0b320bff2008cc9ae47a0ae7325c20c','dns_native.py':'53c65633595880123c155a105f5238f63276d1bc601b02fc0ddc18121667c177','eks_https.py':'e25ed2a1ca7ce8236ebe9e18e5fa0c8298046c682b71fbd6b71e7224d103f57b','install_owned_once.py':'29195dbc473ded10ee7c2565fb7e605f9b52c3f59816002ffdd94db70ace03fc','kube_native.py':'9fae13d7a6f07781d43871af97e02b358487e87866ed49264104e87daf98eb08','native_io.py':'1242740c98bd488047baa77cb0e93539af9279355dbff9c39b46a637e9105943','native_structure.py':'8db8098a8d39d146a1ef95ddc9584fcf916b4110858c79722ac6a50904d9fb59','nft_owner.py':'054a16bfaf4370fd71f716c63986bafb2ccd3f4aa78eebf4cf8b58b51b1afdab','nl_apply.py':'019081131fba5f86eb87b955fc6fd5304c031353860117f7f9b74a14dd4f79e3','observations.py':'bc59af9e9bb60f7ace06021c4cb866b201d3bde1a757ba4587234736de138d33','original_process.py':'f0940634592b00dbff8d8547744b2a26e90cd23bc9a4eacdc8a0c1d0ccb1273f','transition_adoption.py':'eed800ed8acc35439358d7ff73a079342b7f1d138131534b4261f93d55e3cc6a','whole_witness.py':'3c2ab7edd68f4fc16d9736608249fa0895ab25d1ce431383645a23dba94b8776'}
CORE_CONTEXT_SHA='5f4d0f3a23485a0f1c09d275e811c89b14ccde220b89758efa45ba84e8fb34af'
STAGE_HELPERS=(('R42','R42_stage_reconstruction.py','36e3fc994ab45717ceebc498d14edb05e5f23ea372480e73125e0fb7529577b6'),('R41','R41_stage_reconstruction.py','5869ce56507326acaa4993d2b4f632437e73551618554499e71892d8c0a5479e'),('R40','R40_stage_reconstruction.py','03fba3e2e226e24e1efc74604c6dfa74b786b8ed38f273c7d77fe13c09b7661e'),('R39','R39_success_stage_reconstruction.py','593c3ea3bf881bce0082efce079af5c0b78695d3227f95cbfbc29c59ab9ada94'),('R38','R38_success_stage_reconstruction.py','e984f33248574665163a29d8b9f39eb5ea6146762e7230c95209b3e328250c40'))
MACHINE_SHA='313d1b454312ceac2bc8ff70a798c05b6772e389295de99c27ded3ef20657040'
WG_CONFIG_SHA='bfd2729ada7e3d971030b9ca50dc278c91af35a9e6e83ac0f1981eeac6b7aecc'
PROPS='LoadState,MainPID,ExecMainPID,ActiveState,SubState,NRestarts,InvocationID,ExecMainStartTimestampMonotonic,ControlGroup,Result,ExecMainCode,ExecMainStatus,FragmentPath,Restart,DropInPaths'
SCHEMA='Root_standing_R13_g15pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
FIELDS={'g6_boot_v2_predecessor_guardian_source_sha256','g6_boot_v2_predecessor_standing_config_sha256','g6_predecessor_guardian_source_sha256','g6_predecessor_standing_config_sha256','schema','guardian_source_sha256','controller_unit_sha256','hub_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','hub_boot_config_sha256','Root_review','R43_proofs','Core262_context_ref','proof_index_ref','context_sources','predecessor_guardian_source_sha256','predecessor_standing_config_sha256','hub_source_sha256','r13_predecessor_guardian_source_sha256','r13_predecessor_standing_config_sha256','pair_predecessor_standing_configs'}
HISTORICAL_G7_FIELDS=frozenset(FIELDS)
HISTORICAL_G6_FIELDS=HISTORICAL_G7_FIELDS-{'g6_boot_v2_predecessor_guardian_source_sha256','g6_boot_v2_predecessor_standing_config_sha256','g6_predecessor_guardian_source_sha256','g6_predecessor_standing_config_sha256'}
HISTORICAL_F315_FIELDS=HISTORICAL_G7_FIELDS-{'g6_boot_v2_predecessor_guardian_source_sha256','g6_boot_v2_predecessor_standing_config_sha256'}
FIELDS=FIELDS|{'g7_predecessor_guardian_source_sha256','g7_predecessor_standing_config_sha256'}
HISTORICAL_G8_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g8_predecessor_guardian_source_sha256','g8_predecessor_standing_config_sha256'}
HISTORICAL_G9_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g9_predecessor_guardian_source_sha256','g9_predecessor_standing_config_sha256'}
HISTORICAL_G10_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g10_predecessor_guardian_source_sha256','g10_predecessor_standing_config_sha256'}
G10_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g10pair-source-v1'
G10_PREDECESSOR_SOURCE_SHA='4283341a25e1a9c344cdf564f06604f560c14a7dc7e3738039f17cb9ee3c9bb7'
G10_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g10pair.production.json')
G10_PREDECESSOR_CONFIG_SHA='71647d59c2ea21c5d0dafd38d266e34d0f360c3aaf50bf5a628947a244e879ce'
G10_PREDECESSOR_SCHEMA='Root_standing_R13_g10pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
HISTORICAL_G11_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g11_predecessor_guardian_source_sha256','g11_predecessor_standing_config_sha256'}
G11_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g11pair-source-v1'
G11_PREDECESSOR_SOURCE_SHA='243fe177ed4be0ea7fe8be1e4472b1eee5c73db1cfd109c929cb297622959710'
G11_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g11pair.production.json')
G11_PREDECESSOR_CONFIG_SHA='b0baa40b8a479528882e352e190e17ce53989a702972edb60d36c60aeb471465'
G11_PREDECESSOR_SCHEMA='Root_standing_R13_g11pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
HISTORICAL_G12_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g12_predecessor_guardian_source_sha256','g12_predecessor_standing_config_sha256'}
G12_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g12pair-source-v1'
G12_PREDECESSOR_SOURCE_SHA='67f8a8ffed5af5acbf3523c6d83bf0a5422e9ddaae984e75b4d322cc2dba79db'
G12_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g12pair.production.json')
G12_PREDECESSOR_CONFIG_SHA='2d663d065a920772918d34308ecd71fac1ea36d1db41449107a93d7c1c8f0f17'
G12_PREDECESSOR_SCHEMA='Root_standing_R13_g12pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
HISTORICAL_G13_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g13_predecessor_guardian_source_sha256','g13_predecessor_standing_config_sha256'}
G13_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g13pair-source-v1'
G13_PREDECESSOR_SOURCE_SHA='f5f0e218f774deefe909e884988d845be93d8c746fc5047820f68759852e7d9f'
G13_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g13pair.production.json')
G13_PREDECESSOR_CONFIG_SHA='c8a04ab44b85f6e0c6ef5ffa89b422c49d6c64a5bb2de90358f56dc654818f3d'
G13_PREDECESSOR_SCHEMA='Root_standing_R13_g13pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
HISTORICAL_G14_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g14_predecessor_guardian_source_sha256','g14_predecessor_standing_config_sha256'}
G14_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g14pair-source-v2'
G14_PREDECESSOR_SOURCE_SHA='f2a791b3244b7542501b596423b98d881aaba5adf52e8117bb44ec196fa93e1e'
G14_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g14pair-v2.production.json')
G14_PREDECESSOR_CONFIG_SHA='e2c0ad81f395cbdd1d84224d393bf78e80ea5e1ed55cb1dbf37ab1d21bd6c950'
G14_PREDECESSOR_SCHEMA='Root_standing_R13_g14pair_successor_Core262_R43_network_boot_terminal_recovery_v1'
HISTORICAL_G15_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g15_predecessor_guardian_source_sha256','g15_predecessor_standing_config_sha256'}
G15_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g15pair-source-v1'
G15_PREDECESSOR_SOURCE_SHA='88afcd71d53b7f0f7f79bf1f8f0c4a31436e60cb9874c1ece77bfe3e835cc7b3'
G15_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g15pair.production.json')
G15_PREDECESSOR_CONFIG_SHA='db5267b302e2d928aa89ee3ab29310a7d15ea3f814c050a461a13a852a345d77'
HISTORICAL_G16_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g16_predecessor_guardian_source_sha256','g16_predecessor_standing_config_sha256'}
G16_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g15pair-source-v2'
G16_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g15pair-v2.production.json')
G16_PREDECESSOR_SOURCE_SHA='3b7bfc8b63d86daed56e66daf04e7bdbc37671ab557832cca9294abf59a8a725'
G16_PREDECESSOR_CONFIG_SHA='c981f3770ef9895c2d8af8822df5e75ea0a8e1d54527ae1d6266fe6e8e3bade1'
HISTORICAL_G17_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g17_predecessor_guardian_source_sha256','g17_predecessor_standing_config_sha256'}
G17_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g17pair-source-v1'
G17_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g17pair.production.json')
G17_PREDECESSOR_SOURCE_SHA='f7407c9b938ea00e5f73a7f976f15d8c208edad732bbad3ab80051338af9847a'
G17_PREDECESSOR_CONFIG_SHA='7d2f5e6f0baf80ddb7cf760bf9913fb09a51d74a3425d8aa0a01fd118b30bc89'
HISTORICAL_G18_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g18_predecessor_guardian_source_sha256','g18_predecessor_standing_config_sha256'}
G18_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g18pair-source-v1'
G18_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g18pair.production.json')
G18_PREDECESSOR_SOURCE_SHA='852c37d1c18098aadb60f40efc1594b5c4062197cca03c752dbac8bcffbb3973'
G18_PREDECESSOR_CONFIG_SHA='9bd033598c6b79fa10afa6fcf25860d57ac8fd856318f783765f0ed7f84e270a'
HISTORICAL_G19_FIELDS=frozenset(FIELDS)
FIELDS=FIELDS|{'g19_predecessor_guardian_source_sha256','g19_predecessor_standing_config_sha256'}
G19_PREDECESSOR_HERE=ROOT/'network-boot-recovery-r13-g19pair-source-v1'
G19_PREDECESSOR_CONFIG=Path('/etc/dakasa/capacity-network/network-recovery.r13-g19pair.production.json')
G19_PREDECESSOR_SOURCE_SHA='c091325ecebe1d9fbdab3a9fa379f6dd215df3cf6d8909e64aac2eca26fe2e09'
G19_PREDECESSOR_CONFIG_SHA='be152d7171a4eebe8e9b62cdbe28ca0eb0299b709377fd71032f20c4b1414577'


def require(ok, guard):
  if not ok:
    raise RuntimeError(guard)
def require_bound():
 require(PROPOSAL_BOUND is True and type(HEAD_NEW_CORE_DIGEST)is str and re.fullmatch('sha256:[a-f0-9]{64}',HEAD_NEW_CORE_DIGEST)is not None and HEAD_NEW_CORE_DIGEST!=HEAD_DIGEST_PLACEHOLDER and type(G20_CONTROLLER_CONFIG_SHA)is str and re.fullmatch('[a-f0-9]{64}',G20_CONTROLLER_CONFIG_SHA)is not None and G20_CONTROLLER_CONFIG_SHA!='0'*64 and type(HEAD_CORE_SOURCE)is str and re.fullmatch('[a-f0-9]{40}',HEAD_CORE_SOURCE)is not None and HEAD_CORE_SOURCE!='0'*40 and type(G9_PREDECESSOR_CONFIG_SHA)is str and re.fullmatch('[a-f0-9]{64}',G9_PREDECESSOR_CONFIG_SHA)is not None and G9_PREDECESSOR_CONFIG_SHA!='0'*64 and CORE_G20==CORE_IMAGE_REF+HEAD_NEW_CORE_DIGEST,'G15_CONCRETE_QUALIFIED_BINDING_REQUIRED')
def sha(raw):
  return hashlib.sha256(raw).hexdigest()
def wire(value):
  return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()
def loads(raw):
  def unique(rows):
    result = {}
    for key, value in rows:
      require(key not in result, 'NO_DUPLICATE_ROOT_JSON')
      result[key] = value
    return result
  return json.loads(raw, object_pairs_hook=unique,
           parse_constant=lambda _: require(False, 'NO_NONFINITE_ROOT_JSON'))
def read(path, cap=131072, mode=None):
  fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
  try:
    a = os.fstat(fd)
    require(stat.S_ISREG(a.st_mode) and a.st_uid == 0 and not stat.S_IMODE(a.st_mode) & 0o022,
        'ROOT_OWNED_OPERAND')
    require(mode is None or stat.S_IMODE(a.st_mode) == mode, 'EXACT_ROOT_MODE')
    data, size = [], 0
    while True:
      chunk = os.read(fd, min(65536, cap + 1 - size))
      if not chunk:
        break
      data.append(chunk)
      size += len(chunk)
      require(size <= cap, 'BOUNDED_FULL_FILE')
    b = os.fstat(fd)
    require((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_ctime_ns)
        == (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_ctime_ns), 'STABLE_FULL_EOF')
    return b''.join(data)
  finally:
    os.close(fd)
def directory(path):
  info = path.lstat()
  require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not path.is_symlink()
      and stat.S_IMODE(info.st_mode) == 0o700, 'ROOT_PRIVATE_DIRECTORY')
def once(path, raw):
  fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
  with os.fdopen(fd, 'wb') as stream:
    stream.write(raw)
    stream.flush()
    os.fsync(stream.fileno())
  fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
  try:
    os.fsync(fd)
  finally:
    os.close(fd)
def module(path, expected, original_source_path=None):
  raw = read(path)
  require(sha(raw) == expected, 'EXACT_REVIEWED_SOURCE')
  value = types.ModuleType('boot_recovery_' + path.stem)
  value.__file__ = str(path) if original_source_path is None else str(original_source_path)
  exec(compile(raw, value.__file__, 'exec'), value.__dict__)
  return value
def successor_controller_config_pure(old_raw, new_raw):
  """An R13-runtime config is the actual R42 config with ONLY the roster, the
    review and (optionally) the Core image pairs replaced.

    Anchor-free half, shared with derive_standing_config.py. Same schema, same
    execute seal and every other byte-level field unchanged. The R42 image pairs
    are the pinned R42_CORE_IMAGE_PAIRS; the new image pairs must be exactly one
    of the pinned ALLOWED_CORE_IMAGE_PAIRS (the pair sets of PAIR_CHAIN).
    """
  old, new = loads(old_raw), loads(new_raw)
  require(type(old) is dict and type(new) is dict and set(new) == set(old)
      and {'source_files_sha256', 'root_review_attestation', 'core_container_images', 'execute'} <= set(old)
      and old['source_files_sha256'] == R42_RUNTIME_HASHES and old['execute'] is True
      and old['core_container_images'] == R42_CORE_IMAGE_PAIRS, 'EXACT_ACTUAL_R42_THIRTEEN_CONFIG')
  review = new['root_review_attestation']
  require(new['source_files_sha256'] == RUNTIME_HASHES and type(review) is str and 80 <= len(review) <= 4096
      and review != old['root_review_attestation']
      and any(new['core_container_images'] == pinned for pinned in ALLOWED_CORE_IMAGE_PAIRS)
      and all(new[k] == old[k] for k in set(old) - {'source_files_sha256', 'root_review_attestation', 'core_container_images'}),
      'R13_CONFIG_ONLY_FOURTEEN_SOURCES_NEW_REVIEW_AND_PINNED_CORE_PAIR_CHANGED')
  return new_raw
def f5pair_controller_config_pure(old_raw, base_raw, new_raw):
  """The f5-pair config is the R13 base config with ONLY the Core pairs (to the
    pinned F5 pair) and the review replaced. Anchor-free; shared with
    derive_standing_config.py and cutover/derive_f5pair_controller_config.py."""
  require(sha(base_raw) == BASE_CONFIG_SHA, 'EXACT_INSTALLED_R13_BASE_CONFIG')
  successor_controller_config_pure(old_raw, base_raw)
  successor_controller_config_pure(old_raw, new_raw)
  base, new = loads(base_raw), loads(new_raw)
  require(base['core_container_images'] == R42_CORE_IMAGE_PAIRS, 'R13_BASE_KEEPS_R42_CORE_PAIRS')
  review = new['root_review_attestation']
  require(new['core_container_images'] == F5_CORE_IMAGE_PAIRS and review != base['root_review_attestation']
      and all(new[k] == base[k] for k in set(base) - {'root_review_attestation', 'core_container_images'}),
      'F5PAIR_CONFIG_ONLY_PINNED_CORE_PAIR_AND_NEW_REVIEW_CHANGED')
  return new_raw
def pair_chain_digests():
  """The pinned chain is well formed (pure, constants only): each link's pairs
    pass kube_native's closed shape, each link keeps the previous link's newest
    image as its oldest (so the running Core stays admitted across a swap), and
    no image digest is ever re-admitted after it was dropped."""
  require_bound()
  require(HEAD_NEW_CORE_DIGEST != HEAD_DIGEST_PLACEHOLDER
      and re.fullmatch('sha256:[a-f0-9]{64}', HEAD_NEW_CORE_DIGEST) is not None, 'HEAD_CORE_DIGEST_SET')
  require(all(re.fullmatch('[a-f0-9]{64}', entry[4]) is not None and entry[4] != '0' * 64
        and entry[5] is not None and entry[5] != '0' * 64 for entry in PAIR_STANDING_CHAIN),
      'PAIR_STANDING_CHAIN_PINS_SET')
  require(len(PAIR_CHAIN) >= 2 and PAIR_CHAIN[0][0] == 'base' and PAIR_CHAIN[0][1] == R42_CORE_IMAGE_PAIRS
      and PAIR_CHAIN[0][3] == BASE_CONFIG_SHA and PAIR_CHAIN[-1][2] == NEW_CONFIG and PAIR_CHAIN[-1][3] is None
      and all(link[3] is not None for link in PAIR_CHAIN[:-1])
      and len({link[0] for link in PAIR_CHAIN}) == len(PAIR_CHAIN)
      and len({str(link[2]) for link in PAIR_CHAIN}) == len(PAIR_CHAIN), 'PINNED_PAIR_CHAIN_SHAPE')
  seen = []
  for index, (_, pairs, _, _) in enumerate(PAIR_CHAIN):
    require(type(pairs) is list and len(pairs) == 2
        and all(type(p) is dict and set(p) == {'image', 'image_id'} and p['image'] == p['image_id']
            and p['image'].startswith(CORE_IMAGE_REF + 'sha256:')
            and re.fullmatch('[a-f0-9]{64}', p['image'].rsplit(':', 1)[1]) is not None
            and p['image'].rsplit(':', 1)[1] != '0' * 64 for p in pairs)
        and pairs[0]['image'] != pairs[1]['image'], 'PINNED_PAIR_CHAIN_KUBE_NATIVE_PAIRS')
    if index:
      previous = PAIR_CHAIN[index - 1][1]
      overlap=pairs[0]==previous[-1]
      if PAIR_CHAIN[index][0]=='g19pair':
        require(PAIR_CHAIN[index-1]==('g18pair',G18_CORE_IMAGE_PAIRS,Path('/etc/dakasa/capacity-network/controller.r13-netlink-g18pair.production.json'),G18_CONTROLLER_CONFIG_SHA) and pairs==G19_CORE_IMAGE_PAIRS and pairs[0]==G18_CORE_IMAGE_PAIRS[0],'G19_EXACT_C18_RETAINS_LIVE_CORE8')
        overlap=True
      require(overlap and pairs[1]['image'] not in seen, 'PINNED_PAIR_CHAIN_OVERLAP_AND_NO_READMISSION')
    seen.extend(p['image'] for p in pairs if p['image'] not in seen)
  return seen
def pair_chain_controller_config_pure(old_raw, chain_raws):
  """Every PAIR_CHAIN config, link by link (anchor-free; shared with
    derive_standing_config.py and controller/derive_g5pair_controller_config.py).

    chain_raws: the raw bytes of every link in PAIR_CHAIN order (base, f5pair,
    ..., head). Link 1 (f5pair) is proven against the base by the f5-pair
    Guardian's unchanged rule; every later link is its predecessor with ONLY the
    pinned pairs and a review new to the whole chain. Returns the head's bytes.
    """
  pair_chain_digests()
  require(type(chain_raws) in (list, tuple) and len(chain_raws) == len(PAIR_CHAIN), 'ONE_RAW_CONFIG_PER_PAIR_CHAIN_LINK')
  require(sha(old_raw) == R42_CONFIG_SHA, 'EXACT_INSTALLED_R42_CONFIG')
  f5pair_controller_config_pure(old_raw, chain_raws[0], chain_raws[1])
  reviews = [loads(old_raw)['root_review_attestation']]
  for index, ((_, pairs, _, pinned), raw) in enumerate(zip(PAIR_CHAIN, chain_raws)):
    require(pinned is None or sha(raw) == pinned, 'EXACT_PINNED_PAIR_CHAIN_CONFIG')
    successor_controller_config_pure(old_raw, raw)
    new = loads(raw)
    require(new['core_container_images'] == pairs, 'PAIR_CHAIN_LINK_HAS_ITS_PINNED_PAIRS')
    review = new['root_review_attestation']
    require(review not in reviews, 'PAIR_CHAIN_LINK_REVIEW_NEW_TO_THE_CHAIN')
    if index:
      previous = loads(chain_raws[index - 1])
      require(set(new) == set(previous)
          and all(new[k] == previous[k] for k in set(previous) - {'root_review_attestation', 'core_container_images'}),
          'PAIR_CHAIN_LINK_ONLY_PINNED_CORE_PAIR_AND_NEW_REVIEW_CHANGED')
    reviews.append(review)
  return chain_raws[-1]
def successor_controller_config(old_raw, chain_raws, actual_anchor):
  """Replaces d211's future_controller_config: one reviewed roster transition
    (R42 -> R13 base) and the pinned Core-pair chain (base -> f5pair -> ... ->
    head), no other."""
  require(sha(old_raw) == actual_anchor['controller_config_sha256'], 'EXACT_ACTUAL_R42_CONFIG')
  require(loads(old_raw)['core_container_images'] == actual_anchor['approved_core_pairs'], 'SAME_R42_EXACT_IMAGE_PAIR')
  return pair_chain_controller_config_pure(old_raw, chain_raws)
def read_pair_chain():
  """The installed bytes of every PAIR_CHAIN config, in chain order."""
  require_bound()
  return [read(path, 32768, 0o600) for _, _, path, _ in PAIR_CHAIN]
def future_hub_config(old_raw, runtime_roster, root_review):
  """Pure successor of Root's original stable key/route Hub seal."""
  value = loads(old_raw)
  require(value['schema'] == 'root_fixed_original_hub_boot_owner_v1'
      and value['execute'] is True and value['source_sha256'] == '61acf63a013637c41af8814028c5fb90550f5baa9ea482efe014a9e6fd504fba'
      and value['host_machine_id_sha256'] == MACHINE_SHA
      and value['hub_wg_config_sha256'] == WG_CONFIG_SHA
      and value['initial_boot_id'] == INITIAL_BOOT and value['initial_ifindex'] == 2825,
      'ORIGINAL_ROOT_STABLE_HUB_INSTALLATION')
  del value['r5_source_files_sha256']
  value.update(schema='root_fixed_original_hub_boot_owner_v2_current_runtime',
                 source_sha256=HUB_SHA, runtime_source_files_sha256=runtime_roster,
                 root_review_attestation=root_review)
  require(type(root_review) is str and 120 <= len(root_review) <= 4096, 'EXPLICIT_ROOT_HUB_REVIEW')
  return wire(value)
def exact_ref(value):
  require(type(value)is dict and set(value)=={'path','sha256'}and type(value['path'])is str and value['path'].startswith('/')and re.fullmatch('[a-f0-9]{64}',str(value['sha256'])),'EXACT_PUBLIC_ORIGINAL_OR_COPY_REF')
def standing_config(source_sha,controller_unit_sha,hub_unit_sha,cold_unit_sha,guardian_unit_sha,new_controller_raw,new_hub_raw,root_review,*,R43_proofs,Core262_context_ref,proof_index_ref,context_sources,hub_source_sha,r13_predecessor_standing_sha):
 value={'g15_predecessor_guardian_source_sha256':G15_PREDECESSOR_SOURCE_SHA,'g15_predecessor_standing_config_sha256':G15_PREDECESSOR_CONFIG_SHA,'g14_predecessor_guardian_source_sha256':G14_PREDECESSOR_SOURCE_SHA,'g14_predecessor_standing_config_sha256':G14_PREDECESSOR_CONFIG_SHA,'g13_predecessor_guardian_source_sha256':G13_PREDECESSOR_SOURCE_SHA,'g13_predecessor_standing_config_sha256':G13_PREDECESSOR_CONFIG_SHA,'g12_predecessor_guardian_source_sha256':G12_PREDECESSOR_SOURCE_SHA,'g12_predecessor_standing_config_sha256':G12_PREDECESSOR_CONFIG_SHA,'g11_predecessor_guardian_source_sha256':G11_PREDECESSOR_SOURCE_SHA,'g11_predecessor_standing_config_sha256':G11_PREDECESSOR_CONFIG_SHA,'g10_predecessor_guardian_source_sha256':G10_PREDECESSOR_SOURCE_SHA,'g10_predecessor_standing_config_sha256':G10_PREDECESSOR_CONFIG_SHA,'g9_predecessor_guardian_source_sha256':G9_PREDECESSOR_SOURCE_SHA,'g9_predecessor_standing_config_sha256':G9_PREDECESSOR_CONFIG_SHA,'g8_predecessor_guardian_source_sha256':G8_PREDECESSOR_SOURCE_SHA,'g8_predecessor_standing_config_sha256':G8_PREDECESSOR_CONFIG_SHA,'g7_predecessor_guardian_source_sha256':G7_PREDECESSOR_SOURCE_SHA,'g7_predecessor_standing_config_sha256':G7_PREDECESSOR_CONFIG_SHA,'g6_boot_v2_predecessor_guardian_source_sha256':G6_BOOT_V2_PREDECESSOR_SOURCE_SHA,'g6_boot_v2_predecessor_standing_config_sha256':G6_BOOT_V2_PREDECESSOR_CONFIG_SHA,'g6_predecessor_guardian_source_sha256':G6_PREDECESSOR_SOURCE_SHA,'g6_predecessor_standing_config_sha256':G6_PREDECESSOR_CONFIG_SHA,'schema':SCHEMA,'pair_predecessor_standing_configs':pair_predecessor_refs(),'r13_predecessor_guardian_source_sha256':R13_PREDECESSOR_SOURCE_SHA,'r13_predecessor_standing_config_sha256':r13_predecessor_standing_sha,'hub_source_sha256':hub_source_sha,'predecessor_guardian_source_sha256':PREDECESSOR_SOURCE_SHA,'predecessor_standing_config_sha256':PREDECESSOR_CONFIG_SHA,'guardian_source_sha256':source_sha,'controller_unit_sha256':controller_unit_sha,'hub_unit_sha256':hub_unit_sha,'cold_unit_sha256':cold_unit_sha,'guardian_unit_sha256':guardian_unit_sha,'new_controller_config_sha256':sha(new_controller_raw),'hub_boot_config_sha256':sha(new_hub_raw),'Root_review':root_review,'R43_proofs':R43_proofs,'Core262_context_ref':Core262_context_ref,'proof_index_ref':proof_index_ref,'context_sources':context_sources,'g16_predecessor_guardian_source_sha256':G16_PREDECESSOR_SOURCE_SHA,'g16_predecessor_standing_config_sha256':G16_PREDECESSOR_CONFIG_SHA,'g17_predecessor_guardian_source_sha256':G17_PREDECESSOR_SOURCE_SHA,'g17_predecessor_standing_config_sha256':G17_PREDECESSOR_CONFIG_SHA,'g18_predecessor_guardian_source_sha256':G18_PREDECESSOR_SOURCE_SHA,'g18_predecessor_standing_config_sha256':G18_PREDECESSOR_CONFIG_SHA}
 value.update(g19_predecessor_guardian_source_sha256=G19_PREDECESSOR_SOURCE_SHA,g19_predecessor_standing_config_sha256=G19_PREDECESSOR_CONFIG_SHA)
 validate(value);return value
def validate(value):
 require_bound()
 refs={'R43_proofs','Core262_context_ref','proof_index_ref','context_sources','pair_predecessor_standing_configs'}
 require(type(value)is dict and set(value)==FIELDS and value['schema']==SCHEMA and type(value['Root_review'])is str and 120<=len(value['Root_review'])<=4096 and all(type(value[k])is str and re.fullmatch('[a-f0-9]{64}',value[k])for k in FIELDS-{'schema','Root_review',*refs}),'CLOSED_STANDING_ROOT_AUTHORITY')
 require(value['predecessor_guardian_source_sha256']==PREDECESSOR_SOURCE_SHA and value['predecessor_standing_config_sha256']==PREDECESSOR_CONFIG_SHA,'EXPLICIT_D211_PREDECESSOR_BINDING')
 require(value['r13_predecessor_guardian_source_sha256']==R13_PREDECESSOR_SOURCE_SHA,'EXPLICIT_R13_PREDECESSOR_BINDING')
 require(value['pair_predecessor_standing_configs']==pair_predecessor_refs(),'EXPLICIT_PAIR_PREDECESSOR_CHAIN_BINDING')
 require(value['g6_predecessor_guardian_source_sha256']==G6_PREDECESSOR_SOURCE_SHA and value['g6_predecessor_standing_config_sha256']==G6_PREDECESSOR_CONFIG_SHA and value['new_controller_config_sha256']==G20_CONTROLLER_CONFIG_SHA,'EXPLICIT_G6_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
 require(value['g6_boot_v2_predecessor_guardian_source_sha256']==G6_BOOT_V2_PREDECESSOR_SOURCE_SHA and value['g6_boot_v2_predecessor_standing_config_sha256']==G6_BOOT_V2_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G6_BOOT_V2_PREDECESSOR_BINDING')
 require(value['g7_predecessor_guardian_source_sha256']==G7_PREDECESSOR_SOURCE_SHA and value['g7_predecessor_standing_config_sha256']==G7_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G7_PREDECESSOR_BINDING')
 require(value['g8_predecessor_guardian_source_sha256']==G8_PREDECESSOR_SOURCE_SHA and value['g8_predecessor_standing_config_sha256']==G8_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G8_PREDECESSOR_BINDING')
 require(value['g9_predecessor_guardian_source_sha256']==G9_PREDECESSOR_SOURCE_SHA and value['g9_predecessor_standing_config_sha256']==G9_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G9_PREDECESSOR_BINDING')
 require(value['g10_predecessor_guardian_source_sha256']==G10_PREDECESSOR_SOURCE_SHA and value['g10_predecessor_standing_config_sha256']==G10_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G10_PREDECESSOR_BINDING')
 require(value['g11_predecessor_guardian_source_sha256']==G11_PREDECESSOR_SOURCE_SHA and value['g11_predecessor_standing_config_sha256']==G11_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G11_PREDECESSOR_BINDING')
 require(value['g12_predecessor_guardian_source_sha256']==G12_PREDECESSOR_SOURCE_SHA and value['g12_predecessor_standing_config_sha256']==G12_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G12_PREDECESSOR_BINDING')
 require(value['g13_predecessor_guardian_source_sha256']==G13_PREDECESSOR_SOURCE_SHA and value['g13_predecessor_standing_config_sha256']==G13_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G13_PREDECESSOR_BINDING')
 require(value['g14_predecessor_guardian_source_sha256']==G14_PREDECESSOR_SOURCE_SHA and value['g14_predecessor_standing_config_sha256']==G14_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G14_PREDECESSOR_BINDING')
 require(value['g15_predecessor_guardian_source_sha256']==G15_PREDECESSOR_SOURCE_SHA and value['g15_predecessor_standing_config_sha256']==G15_PREDECESSOR_CONFIG_SHA,'EXPLICIT_G15_PREDECESSOR_BINDING')
 proofs=value['R43_proofs'];require(type(proofs)is dict and set(proofs)=={'return_ref','original_SSM_caller_ref','request_ref','recipe_ref','stage_caller_refs'}and type(proofs['stage_caller_refs'])is list and 0<=len(proofs['stage_caller_refs'])<=16,'ALL_ACTUAL_R43_ORIGINAL_EXECUTION_PROOFS_REQUIRED')
 for ref in(proofs['return_ref'],proofs['original_SSM_caller_ref'],proofs['request_ref'],proofs['recipe_ref'],*proofs['stage_caller_refs'],value['Core262_context_ref'],value['proof_index_ref']):exact_ref(ref)
 require(value['proof_index_ref']['path']==str(PREDECESSOR_HERE/'PROOF-INDEX.PUBLIC.json'),'FIXED_ROOT_PROOF_INDEX_PATH')
 require(type(value['context_sources'])is dict and set(value['context_sources'])=={'network_anchor_source_ref','network_qualification_source_ref','Core_context_source_ref','Root_factual_Source_review_ref'},'EXACT_EXPLICIT_OWNING_CONTEXT_SOURCES')
 for r in value['context_sources'].values():exact_ref(r)
 require(value['g16_predecessor_guardian_source_sha256']==G16_PREDECESSOR_SOURCE_SHA and value['g16_predecessor_standing_config_sha256']==G16_PREDECESSOR_CONFIG_SHA,'EXACT_G16_PREFIX')
 require(value['g17_predecessor_guardian_source_sha256']==G17_PREDECESSOR_SOURCE_SHA and value['g17_predecessor_standing_config_sha256']==G17_PREDECESSOR_CONFIG_SHA,'EXACT_G17_PREFIX')
 require(value['g18_predecessor_guardian_source_sha256']==G18_PREDECESSOR_SOURCE_SHA and value['g18_predecessor_standing_config_sha256']==G18_PREDECESSOR_CONFIG_SHA,'EXACT_G18_PREFIX')
 require(value['g19_predecessor_guardian_source_sha256']==G19_PREDECESSOR_SOURCE_SHA and value['g19_predecessor_standing_config_sha256']==G19_PREDECESSOR_CONFIG_SHA,'EXACT_G19_PREFIX')
def r13_predecessor_standing(config):
  """The installed R13 Guardian standing config this successor names, by bytes.

    It must be the R13 netlink authority over the SAME Hub and the R13 base
    controller config; its records then count as this successor's own."""
  raw = read(R13_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == config['r13_predecessor_standing_config_sha256'], 'EXACT_INSTALLED_R13_PREDECESSOR_STANDING_CONFIG')
  value = loads(raw)
  require(type(value) is dict and value.get('schema') == R13_PREDECESSOR_SCHEMA
      and value['guardian_source_sha256'] == R13_PREDECESSOR_SOURCE_SHA
      and value['new_controller_config_sha256'] == BASE_CONFIG_SHA
      and value['predecessor_guardian_source_sha256'] == PREDECESSOR_SOURCE_SHA
      and value['predecessor_standing_config_sha256'] == PREDECESSOR_CONFIG_SHA
      and value['hub_source_sha256'] == config['hub_source_sha256']
      and value['hub_boot_config_sha256'] == config['hub_boot_config_sha256']
      and value['hub_unit_sha256'] == config['hub_unit_sha256'], 'R13_PREDECESSOR_SAME_HUB_AND_R13_BASE_CONFIG')
  return value
def pair_predecessor_refs(limit=None):
  """The closed standing-field value naming PAIR_STANDING_CHAIN (prefix up to limit)."""
  return [{'generation': g, 'guardian_source_sha256': source, 'standing_config_sha256': standing}
      for g, source, _, _, standing, _ in PAIR_STANDING_CHAIN[:limit]]
def pair_predecessor_standings(config):
  """Every installed predecessor pair Guardian standing config, by bytes and shape.

    Each must be the pinned authority over the SAME Hub, the same d211 and R13
    predecessors and its own pinned PAIR_CHAIN config; its records then count
    as this successor's own. Returns the (source, standing) authority pairs."""
  chain_shas = {link[3] for link in PAIR_CHAIN if link[3] is not None}
  out = []
  for index, (_, source, path, schema, standing, config_sha) in enumerate(PAIR_STANDING_CHAIN):
    raw = read(path, 32768, 0o600)
    require(sha(raw) == standing, 'EXACT_INSTALLED_PAIR_PREDECESSOR_STANDING_CONFIG')
    value = loads(raw)
    require(type(value) is dict and value.get('schema') == schema
        and value['guardian_source_sha256'] == source
        and value['new_controller_config_sha256'] == config_sha and config_sha in chain_shas
        and value['predecessor_guardian_source_sha256'] == PREDECESSOR_SOURCE_SHA
        and value['predecessor_standing_config_sha256'] == PREDECESSOR_CONFIG_SHA
        and value['r13_predecessor_guardian_source_sha256'] == R13_PREDECESSOR_SOURCE_SHA
        and value['r13_predecessor_standing_config_sha256'] == config['r13_predecessor_standing_config_sha256']
        and value.get('pair_predecessor_standing_configs', []) == pair_predecessor_refs(index)
        and value['hub_source_sha256'] == config['hub_source_sha256']
        and value['hub_boot_config_sha256'] == config['hub_boot_config_sha256']
        and value['hub_unit_sha256'] == config['hub_unit_sha256'], 'PAIR_PREDECESSOR_SAME_HUB_R13_D211_AND_PINNED_CONFIG')
    out.append((source, standing))
  return out
def g6_predecessor_standing(config):
  """Authenticate G6's exact standing bytes without adding a Core pair.

    Its Cold/boot/recovery/full120 records keep their original source pair and
    count toward the SAME limits. Neither the standing nor any ledger changes.
    """
  require(config['g6_predecessor_guardian_source_sha256'] == G6_PREDECESSOR_SOURCE_SHA
      and config['g6_predecessor_standing_config_sha256'] == G6_PREDECESSOR_CONFIG_SHA,
      'EXPLICIT_G6_INITIALIZER_PREDECESSOR_AUTHORITY')
  raw = read(G6_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G6_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G6_STANDING_CONFIG')
  prior = loads(raw)
  require(type(prior) is dict and set(prior) == HISTORICAL_G6_FIELDS
      and prior['schema'] == G6_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G6_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G6_CONTROLLER_CONFIG_SHA
      and config['new_controller_config_sha256'] == G16_CONTROLLER_CONFIG_SHA
      and prior['predecessor_guardian_source_sha256'] == PREDECESSOR_SOURCE_SHA
      and prior['predecessor_standing_config_sha256'] == PREDECESSOR_CONFIG_SHA
      and prior['r13_predecessor_guardian_source_sha256'] == R13_PREDECESSOR_SOURCE_SHA
      and prior['r13_predecessor_standing_config_sha256'] == config['r13_predecessor_standing_config_sha256']
      and prior['pair_predecessor_standing_configs'] == pair_predecessor_refs()
      and all(prior[key] == config[key] for key in ('hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256', 'R43_proofs', 'Core262_context_ref', 'proof_index_ref', 'context_sources')),
      'G6_SAME_AUTHENTICATED_ANCESTRY_HUB_AND_HISTORICAL_CONTROLLER')
  return G6_PREDECESSOR_SOURCE_SHA, G6_PREDECESSOR_CONFIG_SHA
def g6_boot_v2_predecessor_standing(config):
  """Authenticate the actual boot-v2 predecessor without rewriting G6 history.

    Both original authority pairs retain the same proof paths and recovery
    budgets. Neither supplies current network health for another lifetime.
    """
  require(type(config) is dict
      and config.get('g6_boot_v2_predecessor_guardian_source_sha256') == G6_BOOT_V2_PREDECESSOR_SOURCE_SHA
      and config.get('g6_boot_v2_predecessor_standing_config_sha256') == G6_BOOT_V2_PREDECESSOR_CONFIG_SHA
      and config.get('g6_predecessor_guardian_source_sha256') == G6_PREDECESSOR_SOURCE_SHA
      and config.get('g6_predecessor_standing_config_sha256') == G6_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G6_BOOT_V2_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G6_BOOT_V2_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20))
      == G6_BOOT_V2_PREDECESSOR_SOURCE_SHA, 'EXACT_INSTALLED_G6_BOOT_V2_SOURCE')
  raw = read(G6_BOOT_V2_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G6_BOOT_V2_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G6_BOOT_V2_STANDING_CONFIG')
  prior = loads(raw)
  require(type(prior) is dict and set(prior) == HISTORICAL_F315_FIELDS
      and prior['schema'] == G6_BOOT_V2_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G6_BOOT_V2_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G6_CONTROLLER_CONFIG_SHA
      and prior['g6_predecessor_guardian_source_sha256'] == G6_PREDECESSOR_SOURCE_SHA
      and prior['g6_predecessor_standing_config_sha256'] == G6_PREDECESSOR_CONFIG_SHA
      and prior['predecessor_guardian_source_sha256'] == PREDECESSOR_SOURCE_SHA
      and prior['predecessor_standing_config_sha256'] == PREDECESSOR_CONFIG_SHA
      and prior['r13_predecessor_guardian_source_sha256'] == R13_PREDECESSOR_SOURCE_SHA
      and prior['r13_predecessor_standing_config_sha256'] == config['r13_predecessor_standing_config_sha256']
      and prior['pair_predecessor_standing_configs'] == pair_predecessor_refs()
      and all(prior[key] == config[key] for key in ('hub_source_sha256', 'hub_boot_config_sha256', 'hub_unit_sha256', 'R43_proofs', 'Core262_context_ref', 'proof_index_ref', 'context_sources')),
      'G6_BOOT_V2_SAME_CLOSED_CANONICAL_G6_ANCESTRY_HUB_AND_HISTORICAL_CONTROLLER')
  return G6_BOOT_V2_PREDECESSOR_SOURCE_SHA, G6_BOOT_V2_PREDECESSOR_CONFIG_SHA
def prior_boot_start_callers_quiescent(records, boot_id, unit, authorities):
  """Pure same-Boot/unit prior-CLI closure gate; status zero is not required.

    authorities: the closed (source_sha256, standing_config_sha256) pairs whose
    records count, i.e. this successor's own and d211's. All count to the limit.
    """
  require(type(records) is list and unit in (COLD, HUB, UNIT) and type(authorities) is frozenset, 'EXACT_BOOT_PRIOR_CALLER_SCOPE')
  matched = 0
  for record in records:
    possible = record['possible_start']
    if possible.get('boot_id') != boot_id or possible.get('unit') != unit:
      continue
    matched += 1
    caller = record['original_caller']
    require(possible['schema'] == 'Root_boot_pre_effect_one_original_unit_START_possible_v1'
        and (possible['source_sha256'], possible['standing_config_sha256']) in authorities,
        'SAME_BOOT_UNIT_SOURCE_AND_CONFIG_PRIOR_START')
    require(type(caller) is dict
        and caller['schema'] == 'Root_boot_original_unit_START_caller_v1'
        and caller['boot_id'] == boot_id and caller['source_sha256'] == possible['source_sha256']
        and caller['possible_START_ref'] == record['possible_start_ref'],
        'DURABLE_PRIOR_ORIGINAL_BOOT_START_CALLER_JOIN')
    original = caller['original_native_call']
    facts = original['original_transport']
    require(original['argv'] == ['/usr/bin/systemctl', 'start', unit]
        and facts.get('local_child_joined') is True
        and facts.get('all_local_FDs_closed') is True,
        'ALL_PRIOR_SAME_UNIT_START_CLIENTS_JOINED_AND_FDS_CLOSED')
  require(matched < 3, 'AT_MOST_THREE_DISTINCT_PRE_EFFECT_BOOT_ATTEMPTS_PER_UNIT')
  return matched
def g7_predecessor_standing(config):
  """Authenticate actual G7 separately from canonical G6 and boot-v2."""
  require(type(config) is dict
      and config.get('g7_predecessor_guardian_source_sha256') == G7_PREDECESSOR_SOURCE_SHA
      and config.get('g7_predecessor_standing_config_sha256') == G7_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G7_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G7_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G7_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G7_SOURCE')
  raw = read(G7_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G7_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G7_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G7_FIELDS
      and prior['schema'] == G7_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G7_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G7_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == '85b8dcd254d46755fdbd568d7d01c2c2cf2d7e309bf3b0b7ac751ef9cb680ec9'
      and prior['cold_unit_sha256'] == '8263c0b187f822c26f9e00f4a202ec19c9bbc07071cd7cd20e89858a20a01b2c'
      and prior['guardian_unit_sha256'] == 'cee6732c6f313e946c617e786686de7027560cf830e8b26d01a62d6f7a9ef729'
      and all(prior[k] == config[k] for k in HISTORICAL_G7_FIELDS - changed_head_fields),
      'G7_SAME_CLOSED_CANONICAL_G6_BOOT_V2_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G7_PREDECESSOR_SOURCE_SHA, G7_PREDECESSOR_CONFIG_SHA
def g8_predecessor_standing(config):
  """Authenticate the actual G8 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g8_predecessor_guardian_source_sha256') == G8_PREDECESSOR_SOURCE_SHA
      and config.get('g8_predecessor_standing_config_sha256') == G8_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G8_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G8_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G8_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G8_SOURCE')
  raw = read(G8_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G8_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G8_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G8_FIELDS
      and prior['schema'] == G8_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G8_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G8_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == '131f34b8dbb59a2d46d94fb7a403671f106d9cb4d8b299a6a10ac61189f0dc50'
      and prior['cold_unit_sha256'] == '6f9fec6f4616df549fb8103c4220ee299ec97146fcc0bfef351cd216e12c985e'
      and prior['guardian_unit_sha256'] == 'aae825c944adfc4e4b79d55bed3fe618b441b64dd3660295ab2bfb9ac4d7e81a'
      and all(prior[k] == config[k] for k in HISTORICAL_G8_FIELDS - changed_head_fields),
      'G8_SAME_CLOSED_FOUR_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G8_PREDECESSOR_SOURCE_SHA, G8_PREDECESSOR_CONFIG_SHA
def g9_predecessor_standing(config):
  """Authenticate the actual G9 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g9_predecessor_guardian_source_sha256') == G9_PREDECESSOR_SOURCE_SHA
      and config.get('g9_predecessor_standing_config_sha256') == G9_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G9_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G9_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G9_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G9_SOURCE')
  raw = read(G9_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G9_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G9_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G9_FIELDS
      and prior['schema'] == G9_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G9_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G9_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == 'a6a4bdcda5270a7000dc8399c1eb5e84fc762ceac9f6ad3845c4a334eaea6c0d'
      and prior['cold_unit_sha256'] == '4b49a3ec10cb131242e7a17d8c0026aa6a48e1e0d2d1ec3c3610ae3763406879'
      and prior['guardian_unit_sha256'] == '038d72711a76ccd98d71127f7746a41dc0c4fda27f255f566bee6161aa8a2531'
      and all(prior[k] == config[k] for k in HISTORICAL_G9_FIELDS - changed_head_fields),
      'G9_SAME_CLOSED_FIVE_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G9_PREDECESSOR_SOURCE_SHA, G9_PREDECESSOR_CONFIG_SHA
def g10_predecessor_standing(config):
  """Authenticate the actual G10 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g10_predecessor_guardian_source_sha256') == G10_PREDECESSOR_SOURCE_SHA
      and config.get('g10_predecessor_standing_config_sha256') == G10_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G10_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G10_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G10_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G10_SOURCE')
  raw = read(G10_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G10_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G10_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G10_FIELDS
      and prior['schema'] == G10_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G10_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G10_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == 'bd738a47c5157f4d913df1629352ba472ef4b8fa3bad2fe57d33ffc60c1e5312'
      and prior['cold_unit_sha256'] == '4a7783d3e67439b1e03493e4360e4a5cd003ecddb6444a02fb8967ba58c4f3d9'
      and prior['guardian_unit_sha256'] == 'dc4ce5e9bafe9eccc2e817a4fdb674f63390fa0043a8323a23e5035015b2e5e4'
      and all(prior[k] == config[k] for k in HISTORICAL_G10_FIELDS - changed_head_fields),
      'G10_SAME_CLOSED_SIX_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G10_PREDECESSOR_SOURCE_SHA, G10_PREDECESSOR_CONFIG_SHA
def g11_predecessor_standing(config):
  """Authenticate the actual G11 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g11_predecessor_guardian_source_sha256') == G11_PREDECESSOR_SOURCE_SHA
      and config.get('g11_predecessor_standing_config_sha256') == G11_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G11_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G11_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G11_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G11_SOURCE')
  raw = read(G11_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G11_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G11_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G11_FIELDS
      and prior['schema'] == G11_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G11_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G11_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == '692e1b0b2e68bced3fba3d34b5fb72ded99af6d0293db2dd4141c3c95e654fdc'
      and prior['cold_unit_sha256'] == '4ef35578e59bb413bfd49a4d7779d4b370c38730d2bbf2440ad28c0b6ae77926'
      and prior['guardian_unit_sha256'] == '116f0a55960f83fe7eeb315e3e94c67ec1e4b55cfb946a0480c803819266f209'
      and all(prior[k] == config[k] for k in HISTORICAL_G11_FIELDS - changed_head_fields),
      'G11_SAME_CLOSED_SEVEN_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G11_PREDECESSOR_SOURCE_SHA, G11_PREDECESSOR_CONFIG_SHA
def g12_predecessor_standing(config):
  """Authenticate the actual G12 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g12_predecessor_guardian_source_sha256') == G12_PREDECESSOR_SOURCE_SHA
      and config.get('g12_predecessor_standing_config_sha256') == G12_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G12_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G12_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G12_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G12_SOURCE')
  raw = read(G12_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G12_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G12_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G12_FIELDS
      and prior['schema'] == G12_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G12_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G12_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == '85202467a404116ee883d06347a3d80bd3c89e7519f08d41d4f4ddcb3ecf21c3'
      and prior['cold_unit_sha256'] == 'bf7bd7b2e65cc549f5bf24895a78fbdefb934d1a3ff3c9cd685f6d0d1ba492f0'
      and prior['guardian_unit_sha256'] == '6a6cf26d314437a206d9f17bec7a4c728466edb81b937511907a163b64b28494'
      and all(prior[k] == config[k] for k in HISTORICAL_G12_FIELDS - changed_head_fields),
      'G12_SAME_CLOSED_EIGHT_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G12_PREDECESSOR_SOURCE_SHA, G12_PREDECESSOR_CONFIG_SHA
def g13_predecessor_standing(config):
  """Authenticate the actual G13 authority without relabelling its records."""
  require_bound()
  require(type(config) is dict
      and config.get('g13_predecessor_guardian_source_sha256') == G13_PREDECESSOR_SOURCE_SHA
      and config.get('g13_predecessor_standing_config_sha256') == G13_PREDECESSOR_CONFIG_SHA
      and config.get('new_controller_config_sha256') == G16_CONTROLLER_CONFIG_SHA,
      'EXPLICIT_G13_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G13_PREDECESSOR_HERE / 'network_guardian.py', 1 << 20)) == G13_PREDECESSOR_SOURCE_SHA,
      'EXACT_INSTALLED_G13_SOURCE')
  raw = read(G13_PREDECESSOR_CONFIG, 32768, 0o600)
  require(sha(raw) == G13_PREDECESSOR_CONFIG_SHA, 'EXACT_INSTALLED_G13_STANDING')
  prior = loads(raw)
  changed_head_fields = {'schema', 'guardian_source_sha256', 'controller_unit_sha256',
                           'cold_unit_sha256', 'guardian_unit_sha256',
                           'new_controller_config_sha256', 'Root_review'}
  require(type(prior) is dict and set(prior) == HISTORICAL_G13_FIELDS
      and prior['schema'] == G13_PREDECESSOR_SCHEMA
      and prior['guardian_source_sha256'] == G13_PREDECESSOR_SOURCE_SHA
      and prior['new_controller_config_sha256'] == G13_CONTROLLER_CONFIG_SHA
      and prior['controller_unit_sha256'] == '329deeba023d8d64f807015a4da663179252d10b505472aaf84f5017433829ca'
      and prior['cold_unit_sha256'] == '93602222a20d01a012b20c3757aa6eb19d2d6bf61e9718a11fe71a85bee3779f'
      and prior['guardian_unit_sha256'] == '8916ddb4c8ddc32a616d4e30d589e78b4c2460d045c908ecfb3d5b75f138d009'
      and all(prior[k] == config[k] for k in HISTORICAL_G13_FIELDS - changed_head_fields),
      'G13_SAME_CLOSED_NINE_AXIS_PREFIX_HUB_AND_ORIGINAL_REFS')
  return G13_PREDECESSOR_SOURCE_SHA, G13_PREDECESSOR_CONFIG_SHA
def g14_predecessor_standing(config):
  require_bound()
  require(type(config) is dict and config.get('g14_predecessor_guardian_source_sha256')==G14_PREDECESSOR_SOURCE_SHA and (config.get('g14_predecessor_standing_config_sha256')==G14_PREDECESSOR_CONFIG_SHA) and (config.get('new_controller_config_sha256')==G16_CONTROLLER_CONFIG_SHA),'EXPLICIT_G14_AUTHORITY_AND_CURRENT_G15_CONTROLLER')
  require(sha(read(G14_PREDECESSOR_HERE/'network_guardian.py',1<<20))==G14_PREDECESSOR_SOURCE_SHA,'EXACT_INSTALLED_G14_SOURCE')
  raw=read(G14_PREDECESSOR_CONFIG,32768,384)
  require(sha(raw)==G14_PREDECESSOR_CONFIG_SHA,'EXACT_INSTALLED_G14_STANDING')
  prior=loads(raw)
  changed_head_fields={'schema','guardian_source_sha256','controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','Root_review'}
  require(type(prior) is dict and set(prior)==HISTORICAL_G14_FIELDS and (prior['schema']==G14_PREDECESSOR_SCHEMA) and (prior['guardian_source_sha256']==G14_PREDECESSOR_SOURCE_SHA) and (prior['new_controller_config_sha256']==G14_CONTROLLER_CONFIG_SHA) and (prior['controller_unit_sha256']=='996834aef6c6b11ee4a9df9f3e6fd19c3524fe32eae60b12f655ab281c828674') and (prior['cold_unit_sha256']=='c435868896aec1eb9346e091d7ef2fe64aff1bcbda114a00946772a07b79cdfb') and (prior['guardian_unit_sha256']=='09bb0bdcbd593aaf5df65022f7824f6646903b8ebffb953c5b383b7e687093c5') and all((prior[k]==config[k] for k in HISTORICAL_G14_FIELDS-changed_head_fields)),'G14_EXACT_PRIOR_AUTHORITY')
  return (G14_PREDECESSOR_SOURCE_SHA,G14_PREDECESSOR_CONFIG_SHA)
def g15_predecessor_standing(c):
  require_bound()
  require(c.get('g15_predecessor_guardian_source_sha256')==G15_PREDECESSOR_SOURCE_SHA and c.get('g15_predecessor_standing_config_sha256')==G15_PREDECESSOR_CONFIG_SHA and c.get('new_controller_config_sha256')==G16_CONTROLLER_CONFIG_SHA,'EXACT_G15_AUTHORITY_AND_C16')
  require(sha(read(G15_PREDECESSOR_HERE/'network_guardian.py',1<<20))==G15_PREDECESSOR_SOURCE_SHA,'G15_SOURCE_BYTES')
  raw=read(G15_PREDECESSOR_CONFIG,32768,384)
  require(sha(raw)==G15_PREDECESSOR_CONFIG_SHA,'G15_STANDING_BYTES')
  p=loads(raw)
  changed={'guardian_source_sha256','controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','Root_review'}
  require(type(p)is dict and set(p)==HISTORICAL_G15_FIELDS and p['schema']==SCHEMA and p['guardian_source_sha256']==G15_PREDECESSOR_SOURCE_SHA and p['new_controller_config_sha256']==G15_CONTROLLER_CONFIG_SHA and tuple(p[k]for k in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256'))==('cd4ef325410d157c31cfe9ec0f2c1a4f842cc7761c29551895325e8a79386623','fb1b3c49e89938e0f1a34e6e82edeef1a264cc98fa95f2e3864fe5b2fd4a8561','5aaa41b31b482fe758febf128328730b88fc4a6cdb7f8f7cf5b6d01766910390') and all(p[k]==c[k]for k in HISTORICAL_G15_FIELDS-changed),'G15_WHOLE_PRIOR_AUTHORITY')
  return G15_PREDECESSOR_SOURCE_SHA,G15_PREDECESSOR_CONFIG_SHA
def g16_predecessor_config(c):
  require_bound()
  require(type(c)is dict and c.get('new_controller_config_sha256')==G17_CONTROLLER_CONFIG_SHA and c.get('g16_predecessor_guardian_source_sha256')==G16_PREDECESSOR_SOURCE_SHA and c.get('g16_predecessor_standing_config_sha256')==G16_PREDECESSOR_CONFIG_SHA,'G16_C17_PREFIX')
  require(sha(read(G16_PREDECESSOR_HERE/'network_guardian.py',1<<20))==G16_PREDECESSOR_SOURCE_SHA,'G16_SOURCE')
  raw=read(G16_PREDECESSOR_CONFIG,32768,384)
  require(sha(raw)==G16_PREDECESSOR_CONFIG_SHA,'G16_STANDING')
  p=loads(raw);changed={'guardian_source_sha256','controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','Root_review'}
  require(type(p)is dict and set(p)==HISTORICAL_G16_FIELDS and p['schema']==SCHEMA and p['guardian_source_sha256']==G16_PREDECESSOR_SOURCE_SHA and p['new_controller_config_sha256']==G16_CONTROLLER_CONFIG_SHA and tuple(p[k]for k in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256'))==('c7f9bb7557013464237b679ebcde507af60ed20b794ea5ed15679fa73060823b','b60c1ad3307a4bbcf0b324119ae272cc270c7d68d1e51363ae0a6b5aefe308e2','b7d3e0d9a2bf9ad7d91796ec6cc810ada0ccd03086016056391373a3f2bb8f1a')and all(p[k]==c[k]for k in HISTORICAL_G16_FIELDS-changed),'G16_WHOLE_PREFIX')
  return p
def g16_predecessor_standing(c):
  g16_predecessor_config(c)
  return G16_PREDECESSOR_SOURCE_SHA,G16_PREDECESSOR_CONFIG_SHA
def _pair_predecessor_config(c,next_sha,here,source_sha,path,pin,fields,cfg,units,key,guards):
  require_bound()
  require(type(c)is dict and c.get('new_controller_config_sha256')==next_sha and c.get(key+'_predecessor_guardian_source_sha256')==source_sha and c.get(key+'_predecessor_standing_config_sha256')==pin,guards[0])
  require(sha(read(here/'network_guardian.py',1<<20))==source_sha,guards[1])
  raw=read(path,32768,384)
  require(sha(raw)==pin,guards[2])
  p=loads(raw);changed={'guardian_source_sha256','controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256','new_controller_config_sha256','Root_review'}
  require(type(p)is dict and set(p)==fields and p['schema']==SCHEMA and p['guardian_source_sha256']==source_sha and p['new_controller_config_sha256']==cfg and tuple(p[k]for k in ('controller_unit_sha256','cold_unit_sha256','guardian_unit_sha256'))==units and all(p[k]==c[k]for k in fields-changed),guards[3])
  return p
def g17_predecessor_config(c):
 return _pair_predecessor_config(c,G18_CONTROLLER_CONFIG_SHA,G17_PREDECESSOR_HERE,G17_PREDECESSOR_SOURCE_SHA,G17_PREDECESSOR_CONFIG,G17_PREDECESSOR_CONFIG_SHA,HISTORICAL_G17_FIELDS,G17_CONTROLLER_CONFIG_SHA,('b71682b08f04e0e057b839dd06e2c2dad3674b91f4d34fc968e1c7b8ab999149', 'cea597842b8648e3d763f530b0cafe4f9f2ea4b34b0c30c00503d9926f0d9584', 'b9b087825a3be2052693608b32c4a80dcbc4cb96ce4b03df96d183b4d973a437'),'g17',('G17_C18_PREFIX', 'G17_SOURCE', 'G17_STANDING', 'G17_WHOLE_PREFIX'))
def g18_predecessor_config(c):
 return _pair_predecessor_config(c,G19_CONTROLLER_CONFIG_SHA,G18_PREDECESSOR_HERE,G18_PREDECESSOR_SOURCE_SHA,G18_PREDECESSOR_CONFIG,G18_PREDECESSOR_CONFIG_SHA,HISTORICAL_G18_FIELDS,G18_CONTROLLER_CONFIG_SHA,('253cb7270f401b96e6d8149c98cb2b467197701a37482193a4c1851b92a0f318', '13ed8beaf73ffea86329429c5f2f51218c743b22fdc7e27e81ef2cc011d45a7e', '278168ae96d0fceee88ce09cf5c4211be4424692dcedfad49dd666c4ab1424be'),'g18',('G18_C19_PREFIX', 'G18_SOURCE', 'G18_STANDING', 'G18_WHOLE_PREFIX'))
def g19_predecessor_config(c):
 return _pair_predecessor_config(c,G20_CONTROLLER_CONFIG_SHA,G19_PREDECESSOR_HERE,G19_PREDECESSOR_SOURCE_SHA,G19_PREDECESSOR_CONFIG,G19_PREDECESSOR_CONFIG_SHA,HISTORICAL_G19_FIELDS,G19_CONTROLLER_CONFIG_SHA,('aa642a595105b43161ad0fa736acfa5a167d0dbf490527247695607ad97222c6', '0de44ac60069b4daa65341910c98b3f19a067496640c2ddf7e27d27c56f320ff', 'c1c7fad3775cca296fd938a0f5ad5d0bff3669e196625ee10f153b2e7e494ee6'),'g19',('G19_C20_PREFIX', 'G19_SOURCE', 'G19_STANDING', 'G19_WHOLE_PREFIX'))

class Owner:
  def __init__(self,source_sha):
   require_bound()
   self.invocation_started=time.monotonic()
   self.current_read_capture=None
   require(os.geteuid()==0 and Path(__file__)==SELF and sha(read(SELF))==source_sha,'EXACT_ROOT_INSTALLED_GUARDIAN_SOURCE')
   self.sha=source_sha
   self.raw_config=read(CONFIG,32768,0o600)
   self.config=loads(self.raw_config)
   validate(self.config)
   self.immediate_predecessor_config=g19_predecessor_config(self.config)
   self.current_predecessor_config=g18_predecessor_config(self.immediate_predecessor_config)
   self.head_predecessor_config=g17_predecessor_config(self.current_predecessor_config)
   self.predecessor_config=g16_predecessor_config(self.head_predecessor_config)
   require(self.config['guardian_source_sha256']==source_sha,'STANDING_SAME_SOURCE')
   r13_predecessor_standing(self.predecessor_config)
   g6_predecessor_standing(self.predecessor_config)
   g6_boot_v2_predecessor_standing(self.predecessor_config)
   g7_predecessor_standing(self.predecessor_config)
   g8_predecessor_standing(self.predecessor_config)
   g9_predecessor_standing(self.predecessor_config)
   g10_predecessor_standing(self.predecessor_config)
   g11_predecessor_standing(self.predecessor_config)
   g12_predecessor_standing(self.predecessor_config)
   g13_predecessor_standing(self.predecessor_config)
   g14_predecessor_standing(self.predecessor_config)
   g15_predecessor_standing(self.predecessor_config)
   self.authorities=frozenset({(source_sha,sha(self.raw_config)),(G18_PREDECESSOR_SOURCE_SHA,G18_PREDECESSOR_CONFIG_SHA),(G17_PREDECESSOR_SOURCE_SHA,G17_PREDECESSOR_CONFIG_SHA),(G16_PREDECESSOR_SOURCE_SHA,G16_PREDECESSOR_CONFIG_SHA),(PREDECESSOR_SOURCE_SHA,PREDECESSOR_CONFIG_SHA),(R13_PREDECESSOR_SOURCE_SHA,self.config['r13_predecessor_standing_config_sha256']),*pair_predecessor_standings(self.predecessor_config),g6_predecessor_standing(self.predecessor_config),g6_boot_v2_predecessor_standing(self.predecessor_config),g7_predecessor_standing(self.predecessor_config),g8_predecessor_standing(self.predecessor_config),g9_predecessor_standing(self.predecessor_config),g10_predecessor_standing(self.predecessor_config),g11_predecessor_standing(self.predecessor_config),g12_predecessor_standing(self.predecessor_config),g13_predecessor_standing(self.predecessor_config),g14_predecessor_standing(self.predecessor_config),g15_predecessor_standing(self.predecessor_config)})
   self.B=module(BASE_PATH,BASE_SHA)
   self.C=module(ROOT/'r33-compat-bridge-r2/bridge_contract.py',self.B.BRIDGE_SHA)
   self.n=module(ROOT/'r33-compat-bridge-r2/frozen_native.py',self.B.NATIVE_SHA)
   self.coverage=module(HERE/'coverage.py',COVERAGE_SHA)
   self.journal_contract=module(HERE/'journal_contract.py',JOURNAL_SHA)
   self.hub=module(HUB_SOURCE,HUB_SHA)
   self.boot=self.C.instance()
   require(re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}',self.boot),'ACTUAL_BOOT')
   directory(LEDGER)
   self.calls=[]
   self.insert_remaining=set()
   self.start_admitted=False
   self.journal_identity=None
   self.recovering_identity=None
   self.anchor=self.actual_R42_anchor()
   self.initial_identity=self.anchor['identity']
   self.static()
   self.deadline=time.monotonic()+60

  def actual_R42_anchor(self):


    helper=module(HERE/'proof_cache.py',PROOF_CACHE_SHA)
    g=types.SimpleNamespace(require=require,read=read,loads=loads,sha=sha,wire=wire,exact_ref=exact_ref,HERE=PREDECESSOR_HERE)
    return helper.qualify(self,g)

  def static(self):
   require(read(CONFIG,32768,0o600)==self.raw_config,'UNCHANGED_STANDING_ROOT_AUTHORITY')
   require(g19_predecessor_config(self.config)==self.immediate_predecessor_config and g18_predecessor_config(self.immediate_predecessor_config)==self.current_predecessor_config and g17_predecessor_config(self.current_predecessor_config)==self.head_predecessor_config and g16_predecessor_config(self.head_predecessor_config)==self.predecessor_config,'UNCHANGED_G19_G18_G17_G16_PREFIX')
   for unit,key in((UNIT,'controller_unit_sha256'),(HUB,'hub_unit_sha256'),(COLD,'cold_unit_sha256'),(GUARDIAN,'guardian_unit_sha256')):
    require(sha(read('/etc/systemd/system/'+unit,32768))==self.config[key],'EXACT_REVIEWED_FUTURE_SERVICE_UNITS')
   require(sha(read('/etc/systemd/system.control/'+UNIT+'.d/50-CPUQuota.conf',4096))==self.C.DROPIN_SHA,'UNCHANGED_CPU100_DROPIN')
   roster=dict(RUNTIME_HASHES)
   require({p.name for p in RUNTIME.iterdir()}==set(roster)and all(sha(read(RUNTIME/name))==pin for name,pin in roster.items()),'EXACT_R13_FOURTEEN_RUNTIME_SOURCES')
   actual=self.actual_R42_anchor()
   require(actual==self.anchor,'SAME_IMMUTABLE_R42_ORIGINAL_ANCHOR')
   expected=successor_controller_config(read(OLD_CONFIG,32768,0o600),read_pair_chain(),actual)
   require(sha(expected)==self.config['new_controller_config_sha256'],'EXACT_REVIEWED_PAIR_CHAIN_HEAD_CONTROLLER_CONFIG')
   r13_predecessor_standing(self.predecessor_config)
   g6_predecessor_standing(self.predecessor_config)
   pair_predecessor_standings(self.predecessor_config)
   g6_boot_v2_predecessor_standing(self.predecessor_config)
   g7_predecessor_standing(self.predecessor_config)
   g8_predecessor_standing(self.predecessor_config)
   g9_predecessor_standing(self.predecessor_config)
   g10_predecessor_standing(self.predecessor_config)
   g11_predecessor_standing(self.predecessor_config)
   g12_predecessor_standing(self.predecessor_config)
   g14_predecessor_standing(self.predecessor_config)
   seal=self.hub_seal()
   require(seal['host_machine_id_sha256']==MACHINE_SHA and seal['hub_wg_config_sha256']==WG_CONFIG_SHA and sha(read('/etc/machine-id',4096))==MACHINE_SHA,'STABLE_SAME_HUB_MACHINE_KEY_CONFIG_AND_SOURCE47')
   self.hub.validate_public_peers(seal['peer_public_keys'],seal['hub_public_key'])
   require(sha(read(self.hub.CONF,65536,0o600))==WG_CONFIG_SHA,'UNCHANGED_PRIVATE_WG_CONFIGURATION')
   for path in('/usr/sbin/iptables','/usr/sbin/iptables-save'):
    executable=self.C.executable(path)
    require(executable['sha256']==self.C.FRONTEND_SHA and executable['resolved_path']=='/usr/sbin/xtables-nft-multi','SAME_EXISTING_NFT_FRONTEND')
   return seal

  def hub_seal(self):
    """The standing Hub seal of the configured profile, fully checked."""
    old_raw = read(HUB_CONFIG, 32768, 0o600)
    require(sha(old_raw) == R42_HUB_SEAL_SHA, 'UNCHANGED_INSTALLED_R42_HUB_SEAL')
    old = loads(old_raw)
    require(old['schema'] == 'root_fixed_original_hub_boot_owner_v2_current_runtime'
        and old['execute'] is True and old['source_sha256'] == HUB_SHA
        and old['runtime_source_files_sha256'] == R42_RUNTIME_HASHES, 'EXACT_R42_HUB_SEAL')
    if self.config['hub_source_sha256'] == HUB_SHA:

      hub_roster = dict(HUB_RUNTIME_HASHES)
      require({p.name for p in HUB_RUNTIME.iterdir()}==set(hub_roster)and all(sha(read(HUB_RUNTIME/name))==pin for name,pin in hub_roster.items()),'EXACT_STANDING_HUB_R42_THIRTEEN_RUNTIME_SOURCES')
      require(self.config['hub_boot_config_sha256'] == R42_HUB_SEAL_SHA, 'EXACT_FUTURE_HUB_SEAL')
      return old

    require(sha(read(HUB13_SOURCE)) == self.config['hub_source_sha256'], 'EXACT_REVIEWED_SUCCESSOR_HUB_SOURCE')
    raw = read(HUB13_CONFIG, 32768, 0o600)
    require(sha(raw) == self.config['hub_boot_config_sha256'], 'EXACT_FUTURE_HUB_SEAL')
    seal = loads(raw)
    uuid = '[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}'
    require(type(seal) is dict and set(seal) == HUB13_SEAL_FIELDS
        and seal['schema'] == 'root_fixed_original_hub_boot_owner_v3_r13_runtime' and seal['execute'] is True
        and seal['source_sha256'] == self.config['hub_source_sha256']
        and seal['runtime_source_files_sha256'] == RUNTIME_HASHES


        and seal['controller_config_sha256'] == BASE_CONFIG_SHA
        and seal['historical_hub_source_sha256'] == HUB_SHA and seal['historical_hub_seal_sha256'] == R42_HUB_SEAL_SHA
        and seal['historical_initial_boot_id'] == old['initial_boot_id']
        and seal['hub_public_key'] == old['hub_public_key'] and seal['peer_public_keys'] == old['peer_public_keys']
        and seal['hub_wg_config_sha256'] == old['hub_wg_config_sha256']
        and seal['host_machine_id_sha256'] == old['host_machine_id_sha256']
        and type(seal['installed_in_boot_id']) is str and re.fullmatch(uuid, seal['installed_in_boot_id'])


        and all(type(seal[k]) is str and re.fullmatch('[a-f0-9]{64}', seal[k])
            for k in ('predecessor_boot_intent_sha256', 'predecessor_boot_return_sha256'))
        and type(seal['root_review_attestation']) is str and len(seal['root_review_attestation']) >= 80,
        'EXACT_R13_SUCCESSOR_HUB_SEAL_BOUND_TO_R42_ANCESTOR_AND_R13_CONFIG')
    return seal

  def call(self, role, argv, codes=(0,), cap=8 << 20, seconds=6):
    mss_checks = [['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *v]
           for v in self.B.rules().values()]
    bridge_checks = [['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *v]
                         for v in self.C.functional_rules(self.B.BRIDGE_OPERATION).values()]
    pure = argv in mss_checks + bridge_checks or argv in (
      ['/usr/sbin/iptables-save', '-c', '-t', 'mangle'], ['/usr/sbin/iptables-save', '-c', '-t', 'filter'],
      ['/usr/sbin/nft', '-a', '-j', 'list', 'ruleset'],
      ['/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network'],
      ['/usr/sbin/ip', '-d', '-j', 'link', 'show', 'dev', 'wg-capacity'],
      ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'wg-capacity'],
      ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all']) or (
        len(argv) == 4 and argv[:2] == ['/usr/bin/systemctl', 'show']
        and argv[2] in (UNIT, HUB, COLD, GUARDIAN) and argv[3].startswith('--property=')) or (
        len(argv) == 4 and argv[:3] == [str(self.hub.WG_BINARY), 'show', 'wg-capacity']
        and argv[3] in ('allowed-ips', 'public-key', 'listen-port'))
    journal = False
    if self.journal_identity is not None:
      base = self.journal_argv(self.journal_identity)
      journal = argv == base or (argv[:len(base)] == base and len(argv) == len(base) + 1
        and (argv[-1].startswith('--after-cursor=') or argv[-1] in ('--lines=1', '--lines=512')))
    insert = tuple(argv) in self.insert_remaining
    start = self.start_admitted in (UNIT, HUB, COLD) and argv == ['/usr/bin/systemctl', 'start', self.start_admitted]
    require(pure or journal or insert or start, 'ONLY_READS_EXACT_EIGHT_COLD_INSERTS_OR_ONE_TERMINAL_START')
    if insert:
      self.insert_remaining.remove(tuple(argv))
    if start:
      self.start_admitted = False
    raw, facts = self.n.native(argv, deadline=min(self.deadline - 1, time.monotonic() + seconds),
                                   env=self.B.SAFE, cap=cap, diagnostic_path=None)
    self.calls.append({'role': role, 'argv': argv, 'original_transport': facts,
                           'stdout_sha256': sha(raw), 'stdout_bytes': len(raw)})
    require(type(facts['exit_code']) is int and facts['exit_code'] in codes
        and facts['wait_zero'] is (facts['exit_code'] == 0)
        and facts['captured_output_truncated'] is False
        and all(facts[k] for k in ('native_started', 'stdout_EOF', 'stderr_EOF',
                                           'all_local_FDs_closed', 'local_child_joined')),
        'SAME_ORIGINAL_NATIVE_EXPECTED_STATUS_EOF_CLOSE_JOIN')
    if self.current_read_capture is not None:
      require(len(self.current_read_capture)<128 and sum(row['bytes']for row in self.current_read_capture)+len(raw)<=32<<20,'BOUNDED_COMPLETE_ORIGINAL_CURRENT_READ_CAPTURE')
      self.current_read_capture.append({'role':role,'argv':list(argv),'original_call_index':len(self.calls)-1,'sha256':sha(raw),'bytes':len(raw),'body':raw})
    return raw

  def properties(self, unit=UNIT):
    raw = self.call('identity-' + unit, ['/usr/bin/systemctl', 'show', unit, '--property=' + PROPS])
    pairs = [row.split('=', 1) for row in raw.decode('ascii').splitlines()]
    require(all(len(row) == 2 for row in pairs) and len(pairs) == len(PROPS.split(',')), 'FULL_UNIT_PROPERTIES')
    value = dict(pairs)
    require(set(value) == set(PROPS.split(',')) and value['LoadState'] == 'loaded'
        and value['FragmentPath'] == '/etc/systemd/system/' + unit and value['NRestarts'] == '0'
        and value['Restart'] == 'no', 'EXACT_LOADED_NO_IMPLICIT_RESTART_UNIT')
    expected_dropin = '/etc/systemd/system.control/' + UNIT + '.d/50-CPUQuota.conf' if unit == UNIT else ''
    require(value['DropInPaths'] == expected_dropin, 'ONLY_UNCHANGED_CONTROLLER_CPU_DROPIN')
    return value

  def identity(self):
    props = self.properties()
    require(props['ActiveState'] == 'active' and props['SubState'] == 'running'
        and props['Result'] == 'success' and props['ExecMainStatus'] == '0'
        and props['ControlGroup'] == '/system.slice/' + UNIT
        and props['MainPID'].isdigit() and int(props['MainPID']) > 1
        and re.fullmatch('[a-f0-9]{32}', props['InvocationID']), 'ACTUAL_CONTROLLER_RUNNING_R0')
    pid = int(props['MainPID'])
    proc = read('/proc/' + str(pid) + '/stat', 4096)
    ticks = proc[proc.rfind(b')') + 1:].split()[19]
    require(ticks.isdigit(), 'ACTUAL_PROCESS_START_TICKS')
    command = read('/proc/' + str(pid) + '/cmdline', 4096)
    anchor=self.initial_identity
    initial=(self.boot==anchor['boot_id']and pid==anchor['pid']and int(ticks)==anchor['start_ticks']and props['InvocationID']==anchor['InvocationID']and props['ExecMainStartTimestampMonotonic']==anchor['ExecMainStartTimestampMonotonic']and sha(command)==anchor['cmdline_sha256'])
    future=b'\0'.join(x.encode()for x in ['/usr/bin/python3','-B',str(RUNTIME/'controller.py'),'--config',str(NEW_CONFIG),'--run'])+b'\0'
    require(command==future,'EXACT_R13_RUNTIME_COMMAND_FOR_FRESH_LIFETIME')
    require(os.sched_getscheduler(pid) == os.SCHED_OTHER and os.sched_getparam(pid).sched_priority == 0,
        'NORMAL_SCHEDULER_NO_RT')
    require(read('/proc/' + str(pid) + '/stat', 4096)[proc.rfind(b')') + 1:].split()[19] == ticks,
        'SAME_UNREUSED_CONTROLLER_PID')
    return {'boot_id': self.boot, 'pid': pid, 'start_ticks': int(ticks),
        'InvocationID': props['InvocationID'],
        'ExecMainStartTimestampMonotonic': props['ExecMainStartTimestampMonotonic'],
        'cmdline_sha256': sha(command), 'initial_R42_admitted_lifetime': initial}

  def key(self, identity):
    return sha(wire(identity))

  def wg(self):
    return self.wg_snapshot(self.static())

  def wg_snapshot(self, seal):
    require(sha(read(self.hub.WG_BINARY, 8 << 20)) == self.hub.WG_SHA, 'SAME_ORIGINAL_WG_BINARY')
    values = loads(self.call('public-WG-link', ['/usr/sbin/ip', '-d', '-j', 'link', 'show', 'dev', 'wg-capacity']))
    require(len(values) == 1, 'ONE_ACTUAL_WG_INTERFACE')
    link = values[0]
    require(type(link['ifindex']) is int and link.get('ifalias') == self.hub.ALIAS
        and link['mtu'] == 1280 and 'UP' in link['flags']
        and link.get('linkinfo', {}).get('info_kind') == 'wireguard', 'EXACT_NATIVE_HUB_INTERFACE')
    addresses = loads(self.call('public-WG-addresses', ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'dev', 'wg-capacity']))
    require(len(addresses) == 1 and addresses[0]['ifindex'] == link['ifindex']
        and len(addresses[0]['addr_info']) == 3
        and {v['local'] for v in addresses[0]['addr_info']} == set(self.hub.VIPS)
        and all(v['family'] == 'inet' and v['prefixlen'] == 32 and v['scope'] == 'global'
            for v in addresses[0]['addr_info']), 'EXACT_THREE_FIXED_VIPS')
    allowed = self.call('public-WG-peer-bindings', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'allowed-ips']).decode().splitlines()
    require(len(allowed) == 16 and {v.split()[1].removesuffix('/32'): v.split()[0] for v in allowed}
        == seal['peer_public_keys'], 'EXACT_SIXTEEN_STANDING_PUBLIC_PEERS')
    require(self.call('public-WG-key', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'public-key']).decode().strip()
        == seal['hub_public_key']
        and self.call('public-WG-listen', [str(self.hub.WG_BINARY), 'show', 'wg-capacity', 'listen-port']).strip()
        == b'51820', 'SAME_ORIGINAL_HUB_PUBLIC_IDENTITY')
    self.hub.route_shape(loads(self.call('full-routes-RAM', ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])), True)
    return {'ifindex': link['ifindex'], 'hub_public_key': seal['hub_public_key'],
        'peer_public_keys': seal['peer_public_keys'], 'mtu': 1280, 'VIP_count': 3, 'route_count': 16}

  def kernel(self, measurement=None, allow_absent=False):
    raw = self.call('full-native-ruleset', ['/usr/sbin/nft', '-a', '-j', 'list', 'ruleset'])
    owned, all_rows = self.C._objects(raw)
    if owned:
      require(sha(self.C._structure(owned, keep_handles=False)) == self.C.AST47, 'ACTUAL_SOURCE_COMPILED47')
    else:
      require(allow_absent and measurement is None, 'ACTUAL_SOURCE47_REQUIRED')
    source = read(RUNTIME / 'nft_owner.py')
    require(sha(source) == RUNTIME_HASHES['nft_owner.py'], 'UNCHANGED_RUNTIME_MARK_PREFLIGHT_SOURCE')
    node = next(x for x in ast.parse(source).body if isinstance(x, ast.FunctionDef) and x.name == 'ruleset_mark_preflight')
    namespace = {'TABLE': 'dakasa_capacity_network', 'require': require, 'json': json}
    exec(compile(ast.Module(body=[node], type_ignores=[]), 'actual_runtime_mark_guard', 'exec'), namespace)
    namespace['ruleset_mark_preflight'](all_rows)
    if allow_absent:
      return {'owned47_handle_structure_sha256': None if not owned else sha(self.C._structure(owned, keep_handles=True)),
          'unchanged_runtime_global_mark_preflight': True}
    handles, ordinals = {}, {}
    for row in owned:
      kind = next(iter(row))
      item = row[kind]
      if kind == 'rule':
        ordinal = ordinals.get(item['chain'], 0)
        ordinals[item['chain']] = ordinal + 1
        key = (kind, item['chain'], str(ordinal))
      else:
        key = (kind, item['name'])
      require(key not in handles, 'ONE_CURRENT_NATIVE_OBJECT')
      handles[key] = item['handle']
    if measurement is not None:
      require(measurement['compiled_native_ast_sha256'] == self.C.AST47
          and [{'key': list(k), 'handle': v} for k, v in sorted(handles.items())]
          == measurement['initial_original_structure_handles'], 'SAME_HONEST_ORIGINAL_INITIALIZER47_HANDLES_BY_EXPLICIT_KIND')
      kind=measurement['initial_structure_proof_kind']
      require((kind=='original_native_apply_echo'and measurement['initial_original_echo_handles']==measurement['initial_original_structure_handles']and measurement['initial_original_read_handles']is None)or(kind=='original_owned_read_adoption'and measurement['initial_original_echo_handles']is None and measurement['initial_original_read_handles']==measurement['initial_original_structure_handles']),'NO_READ_ADOPTION_ECHO_ALIAS')
    text = self.call('native-dynamic-expiries', ['/usr/sbin/nft', '-a', 'list', 'table', 'inet', 'dakasa_capacity_network'])
    observed = time.monotonic()
    return self.coverage.kernel_text(text), observed

  def transport(self):
    raw = self.call('full-filter', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
    rules = self.C.functional_rules(self.B.BRIDGE_OPERATION)
    rows = self.C.bridge_lines(raw, rules)
    require(len(rows) == 4, 'FOUR_EXISTING_FUNCTIONAL_BRIDGE_RULES')
    for role, rule in rules.items():
      self.call('bridge-present-' + role, ['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *rule])
    mang = self.B.mangle(self.call('full-mangle', ['/usr/sbin/iptables-save', '-c', '-t', 'mangle']))
    require(len(mang['owned_rules']) == 4, 'FOUR_EXISTING_FUNCTIONAL_MSS_RULES')
    for role, rule in self.B.rules().items():
      self.call('mss-present-' + role, ['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *rule])
    return {'bridge_operation': self.B.BRIDGE_OPERATION, 'MSS_operation': self.B.OPERATION,
        'full_filter_without_only_counters_sha256': self.C.full_filter(raw)['complete_structure_without_only_counters_sha256'],
        'other_mangle_structure_sha256': mang['other_structure_sha256'],
        'four_bridge_and_four_MSS_original_checks_zero': True}

  def cold_guard(self):
    require(self.boot != INITIAL_BOOT, 'COLD_RESTORE_ONLY_LATER_BOOT')
    require(not Path('/sys/class/net/wg-capacity').exists(), 'COLD_RESTORE_BEFORE_ANY_WG_INTERFACE')
    own = self.properties(COLD)
    require(own['MainPID'] == own['ExecMainPID'] == str(os.getpid())
        and own['ActiveState'] == 'activating' and own['SubState'] == 'start'
        and own['InvocationID'] == os.environ.get('INVOCATION_ID')
        and own['ControlGroup'] == '/system.slice/' + COLD
        and read('/proc/self/cgroup', 4096) == ('0::/system.slice/' + COLD + '\n').encode(),
        'OWN_COLD_ONESHOT_NATIVE_IDENTITY')
    for unit in (UNIT, HUB):
      props = self.properties(unit)
      require(props['MainPID'] == props['ExecMainPID'] == props['ExecMainStartTimestampMonotonic'] == '0'
          and props['ActiveState'] == 'inactive' and props['SubState'] == 'dead'
          and props['InvocationID'] == '', 'BOTH_SERVICES_NEVER_STARTED_THIS_BOOT')
      path = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
      require(not path.exists() or read(path, 4096).strip() == b'', 'NO_SERVICE_CHILD_OR_OLD_LIFETIME')
      raw = self.call('cold-required-order-' + unit, ['/usr/bin/systemctl', 'show', unit, '--property=Requires,After'])
      values = dict(row.split('=', 1) for row in raw.decode().splitlines())
      require(COLD in values['Requires'].split() and COLD in values['After'].split(), 'EFFECTIVE_REQUIRED_ORDERED_COLD_DEPENDENCY')
    self.static()

  def current15_context(self):
    reader=module(HERE/'current15_bounded_reader.py',CURRENT_READER_SHA)
    tail=module(HERE/'current15_bounded_tail_contract.py',CURRENT_TAIL_SHA)
    return types.SimpleNamespace(require=require,loads=loads,sha=sha,wire=wire,read=read,once=once,LEDGER=LEDGER,INITIAL_BOOT=INITIAL_BOOT,COLD=COLD,HUB=HUB,reader=reader,tail=tail)

  def current15_readonly(self):
    g=self.current15_context()
    return g.reader.observe(self,g)

  def initial_boot_read_adoption(self):
    with self.maintenance():
      helper=module(HERE/'initial_boot_Cold_read_adoption.py',INITIAL_COLD_SHA)
      value,self.initial_cold_read_return_ref=helper.read_adopt(self,self.current15_context(),self.invocation_started)
      return value

  def cold_restore(self):
    if self.boot == INITIAL_BOOT:
      return self.initial_boot_read_adoption()
    self.deadline = time.monotonic() + 60
    self.cold_guard()
    kernel_before = self.kernel(allow_absent=True)
    b = self.C.functional_rules(self.B.BRIDGE_OPERATION)
    m = self.B.rules()
    filter_before = self.call('cold-filter-before', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
    require(not self.C.bridge_lines(filter_before, b), 'NO_COLD_BRIDGE_PARTIAL_OR_FOREIGN_OWNERSHIP')
    filter_sha = self.C.full_filter(filter_before)['complete_structure_without_only_counters_sha256']
    mang_before = self.B.mangle(self.call('cold-mangle-before', ['/usr/sbin/iptables-save', '-c', '-t', 'mangle']))
    require(not mang_before['owned_rules'], 'NO_COLD_MSS_PARTIAL_OR_FOREIGN_OWNERSHIP')
    inserts = []
    for role, rule in b.items():
      self.call('cold-bridge-absent-' + role, ['/usr/sbin/iptables', '-w', '2', '-C', 'FORWARD', *rule], (1,))
    for role, rule in m.items():
      self.call('cold-mss-absent-' + role, ['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-C', 'POSTROUTING', *rule], (1,))
    for role in reversed(list(b)):
      inserts.append(['/usr/sbin/iptables', '-w', '2', '-I', 'FORWARD', '1', *b[role]])
    for role in reversed(list(m)):
      inserts.append(['/usr/sbin/iptables', '-w', '2', '-t', 'mangle', '-I', 'POSTROUTING', '1', *m[role]])
    self.cold_guard()
    marker = LEDGER / (self.boot + '-COLD-POSSIBLE-SEND.PUBLIC.json')
    once(marker, wire({'schema': 'Root_standing_network_cold_eight_possible_send_v1',
      'boot_id': self.boot, 'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
      'exact_eight_commands': inserts, 'unknown_or_partial_retry_authorized': False}))
    self.cold_guard()
    self.insert_remaining = {tuple(argv) for argv in inserts}
    try:
      for i, argv in enumerate(inserts):
        self.call('cold-one-insert-' + str(i + 1), argv)
    finally:
      self.insert_remaining.clear()
    result = self.transport()
    after = self.call('cold-filter-after', ['/usr/sbin/iptables-save', '-c', '-t', 'filter'])
    other_filter_after = self.C.without_bridge(after, b)




    other_snapshots = {'filter_before_sha256': filter_sha,
      'filter_after_without_our_four_sha256': other_filter_after,
      'mangle_before_without_our_four_sha256': mang_before['other_structure_sha256'],
      'mangle_after_without_our_four_sha256': result['other_mangle_structure_sha256'],
      'other_ordered_filter_equal_observed': filter_sha == other_filter_after,
      'other_ordered_mangle_equal_observed': mang_before['other_structure_sha256'] == result['other_mangle_structure_sha256'],
      'foreign_concurrent_changes_not_attributed_or_authorized_by_this_owner': True}
    require(self.kernel(allow_absent=True) == kernel_before, 'INET47_AND_GLOBAL_MARK_OWNER_PRESERVED_ACROSS_COLD_INSERTS')
    self.cold_guard()
    require(time.monotonic() < self.deadline - 1, 'ORIGINAL_COLD_OWNER_BUDGET')
    value = {'schema': 'Root_original_network_cold_eight_return_v1', 'boot_id': self.boot,
                 'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
                 'original_native_calls': self.calls, 'transport': result, 'insert_count': 8,
                 'complete_other_structure_observations': other_snapshots,
                 'old_original_install_results_reclassified': False,
                 'WG_routes_marks_inet47_or_service_mutations': 0,
                 'controller_lifetime_or_Guest_business_qualified': False}
    once(LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json'), wire(value))
    return value

  def journal_argv(self, identity):
    return ['/usr/bin/journalctl', '-o', 'json', '--all', '--no-pager',
      '--output-fields=_PID,_SYSTEMD_INVOCATION_ID,MESSAGE,__MONOTONIC_TIMESTAMP,__CURSOR,_BOOT_ID',
      '_PID=' + str(identity['pid']), '_SYSTEMD_INVOCATION_ID=' + identity['InvocationID'],
      '_BOOT_ID=' + self.boot.replace('-', '')]

  def full_journal(self, identity):
    self.journal_identity = identity
    argv = self.journal_argv(identity)
    raw = self.call('new-lifetime-full-journal', argv, cap=64 << 20, seconds=15)
    now = time.monotonic()
    seen, previous = set(), 0
    for line in raw.splitlines():
      cursor, stamp = self.journal_contract.journal_row(loads(line), identity['pid'],
        identity['InvocationID'], self.boot.replace('-', ''))
      require(cursor not in seen and previous <= stamp and stamp / 1000000 <= now,
          'ALL_ORIGINAL_JOURNAL_ROWS_SAME_BOOT_LIFETIME_FORWARD_CLOCK')
      seen.add(cursor)
      previous = stamp
    measured = self.coverage.journal(raw, identity['pid'], identity['InvocationID'], now, minimum_original_batches=1)
    anchor = self.journal_contract.journal_anchor(raw, identity['pid'], identity['InvocationID'],
                                                     self.boot.replace('-', ''), now)
    return raw, measured, anchor, argv

  def qualify_new_lifetime(self, identity, original_deadline=None, START_ref=None):
    self.calls = []
    self.deadline = min(time.monotonic() + 210, original_deadline) if original_deadline is not None else time.monotonic() + 210
    original_work_deadline = self.deadline
    wg = self.wg()
    self.transport()


    warm_end = time.monotonic() + 30
    while True:
      require(self.identity() == identity, 'SAME_NEW_CONTROLLER_DURING_INITIAL_WARMUP')
      kernel, _ = self.kernel()
      if kernel['all_four_backends_and_reverse_sources_positive']:
        break
      require(time.monotonic() + 3 < warm_end, 'NEW_LIFETIME_BOUNDED_COLD_WARMUP')
      time.sleep(2)
    first_read = time.monotonic()
    first_transport = self.transport()
    first_sample = {'started': first_read, 'finished': time.monotonic(), 'transport': first_transport}
    epoch = time.monotonic()
    end = epoch + 120
    require(end + 35 < original_work_deadline, 'NEW_FULL120_AND_FINAL_READS_FIT_ORIGINAL_OPERATION_BUDGET')
    key = self.key(identity)
    once(LEDGER / (key + '-FIXED120-START.PUBLIC.json'), wire({
      'schema': 'Root_new_network_lifetime_original_fixed120_start_v1',
      'source_sha256': self.sha, 'identity': identity, 'start': epoch, 'end': end,
      'original_work_deadline': original_work_deadline, 'old_R35_R36_epoch_reused_or_reset': False}))
    samples = [first_sample]
    while True:
      started = time.monotonic()
      require(self.identity() == identity, 'SAME_NEW_PHYSICAL_CONTROLLER_ACROSS120')
      transport = self.transport()
      samples.append({'started': started, 'finished': time.monotonic(), 'transport': transport})
      if time.monotonic() >= end:
        break
      time.sleep(min(5, max(0, end - time.monotonic())))
    require(samples[0]['started'] <= samples[0]['finished'] <= epoch
        and epoch - samples[0]['finished'] < 1 and samples[-1]['finished'] >= end
        and all(row['finished'] - row['started'] < 20 for row in samples)
        and all(0 <= b['started'] - a['finished'] <= 5.5 for a, b in zip(samples, samples[1:])),
        'ACTUAL_PERIODIC_FUNCTIONAL_EIGHT_RULE_READS_SPAN_NEW120')
    raw, measured, anchor, argv = self.full_journal(identity)
    require(self.identity() == identity and self.wg() == wg, 'SAME_CONTROLLER_WG_PUBLIC_SHAPE_AFTER120')
    kernel, observed = self.kernel(measured)
    suffix = self.call('new-lifetime-one-closing-cursor', argv + ['--after-cursor=' + anchor['cursor']],
                           cap=64 << 20, seconds=8)
    measured, closing = self.journal_contract.closing_journal(measured, suffix,
      identity['pid'], identity['InvocationID'], self.boot.replace('-', ''), anchor,
      time.monotonic(), self.coverage)
    finished = time.monotonic()
    current = measured['current_continuous_window']
    require(end <= finished < original_work_deadline and current is not None
        and current['start'] <= epoch and current['observed_until'] >= end
        and current['observed_seconds'] >= 120 and measured['qualified_15_seconds'] is True
        and current['start'] <= observed <= current['observed_until'] <= finished < current['guaranteed_until']
        and kernel['all_four_backends_and_reverse_sources_positive'], 'NEW_ORIGINAL120_NO_GAP_AND_STRICT_CURRENT15')
    journal_path = LEDGER / (key + '-ORIGINAL-PREFIX.JSONL')
    suffix_path = LEDGER / (key + '-ORIGINAL-CLOSING.JSONL')
    once(journal_path, raw)
    once(suffix_path, suffix)
    value = {'schema': 'Root_new_network_lifetime_original120_current15_return_v1',
      'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
      'identity': identity, 'start': epoch, 'end': end, 'finished': finished,
      'original_work_deadline': original_work_deadline, 'measurement': measured,
      'kernel': kernel, 'kernel_observed': observed, 'closing_cursor': closing,
      'periodic_transport_samples': samples, 'WG_public_shape': wg,
      'original_native_calls': self.calls,
      'original_START_caller_ref': START_ref,
      'original_prefix_ref': {'path': str(journal_path), 'sha256': sha(raw)},
      'original_suffix_ref': {'path': str(suffix_path), 'sha256': sha(suffix)},
      'network_original120_and_current15': True,
      'original_R35_R36_or_unknown_native_success_reclassified': False,
      'Guest_TLS_Core_capacity_business_or_savings_authority': False}
    once(LEDGER / (key + '-QUALIFIED.PUBLIC.json'), wire(value))
    return value

  def original_qualification_measurement(self, identity):
    helper = module(HERE / 'qualification_initializer.py', QUALIFICATION_INITIALIZER_SHA)
    g = types.SimpleNamespace(require=require, read=read, loads=loads, sha=sha, LEDGER=LEDGER)
    return helper.extract(self, g, identity)

  def original_qualification_exists(self, identity):
    return self.original_qualification_measurement(identity) is not None

  @contextlib.contextmanager
  def maintenance(self):
    directory(RUN)
    path = RUN / 'guardian-maintenance.lock'
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
      info = os.fstat(fd)
      require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
          and stat.S_IMODE(info.st_mode) == 0o600, 'SAME_ROOT_SHARED_MAINTENANCE_MUTEX')
      fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
      yield
      require((info.st_dev, info.st_ino) == (path.lstat().st_dev, path.lstat().st_ino), 'UNCHANGED_MAINTENANCE_LOCK')
    finally:
      os.close(fd)

  def failed(self, expected):
    props = self.properties()
    require(props['MainPID'] == '0' and props['ActiveState'] == 'failed'
        and props['SubState'] == 'failed' and props['Result'] != 'success'
        and props['ExecMainPID'] == str(expected['pid'])
        and props['InvocationID'] == expected['InvocationID']
        and props['ExecMainStartTimestampMonotonic'] == expected['ExecMainStartTimestampMonotonic'],
        'EXACT_OBSERVED_TERMINAL_PREDECESSOR')
    require(not Path('/proc/' + str(expected['pid'])).exists(), 'TERMINAL_PHYSICAL_PID_ABSENT')
    cgroup = Path('/sys/fs/cgroup/system.slice') / UNIT / 'cgroup.procs'
    require(not cgroup.exists() or read(cgroup, 65536).strip() == b'', 'ALL_CONTROLLER_NATIVE_CHILDREN_JOINED_OR_ABSENT')
    return props

  def terminal_after_own_START(self, predecessor):
    """A real new unit execution may fail before an OS PID sample is possible.

        Its original possible-START and exact unit are known; the original
        caller may have returned nonzero or unknown. No missing OS start tick,
        command observation or original success is invented. This record
        only permits a later quiescent recovery, never lifetime qualification.
        """
    props = self.properties()
    require(props['ActiveState'] == 'failed' and props['SubState'] == 'failed'
        and props['MainPID'] == '0' and props['ExecMainPID'].isdigit()
        and int(props['ExecMainPID']) > 1 and int(props['ExecMainPID']) != predecessor['pid']
        and re.fullmatch('[a-f0-9]{32}', props['InvocationID'])
        and props['InvocationID'] != predecessor['InvocationID']
        and props['ExecMainStartTimestampMonotonic'].isdigit(), 'ACTUAL_NEW_FAILED_UNIT_EXECUTION_AFTER_OWN_START')
    value = {'boot_id': self.boot, 'pid': int(props['ExecMainPID']), 'start_ticks': None,
                 'InvocationID': props['InvocationID'],
                 'ExecMainStartTimestampMonotonic': props['ExecMainStartTimestampMonotonic'],
                 'cmdline_sha256': None, 'initial_R42_admitted_lifetime': False,
                 'OS_process_never_sampled_before_terminal_exit': True}
    self.failed(value)
    return value

  def boot_terminal_predecessor(self):



    require(self.boot != INITIAL_BOOT, 'BOOT_TERMINAL_DISCOVERY_ONLY_NEW_BOOT')
    for unit in (COLD, HUB):
      props = self.properties(unit)
      require(props['ActiveState'] == 'active' and props['SubState'] == 'exited'
          and props['MainPID'] == '0' and props['Result'] == 'success'
          and props['ExecMainStatus'] == '0' and props['ExecMainPID'].isdigit()
          and int(props['ExecMainPID']) > 1 and re.fullmatch('[a-f0-9]{32}', props['InvocationID']),
          'ORIGINAL_COLD_AND_HUB_SYSTEMD_EXECUTIONS_BOTH_ZERO_THIS_BOOT')
    cold = loads(read(LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json'), 1 << 20, 0o600))
    require(cold['schema'] == 'Root_original_network_cold_eight_return_v1'
        and cold['boot_id'] == self.boot
        and (cold['source_sha256'], cold['standing_config_sha256']) in self.authorities, 'OWN_ACTUAL_SAME_BOOT_COLD_RETURN')
    hub_raw = read(RUN / ('hub-boot-' + self.boot + '-RETURN.json'), 32768, 0o600)
    hub = loads(hub_raw)
    seal = self.static()


    installed_boot_r42_return = (self.config['hub_source_sha256'] != HUB_SHA
        and self.boot == seal['installed_in_boot_id'] and hub['seal_sha256'] == R42_HUB_SEAL_SHA
        and sha(hub_raw) == seal['predecessor_boot_return_sha256'])
    require(hub['schema'] == 'original_fixed_hub_boot_return_v2_current_runtime'
        and hub['boot_id'] == self.boot
        and (hub['seal_sha256'] == self.config['hub_boot_config_sha256'] or installed_boot_r42_return)
        and hub['mode'] == 'CREATE_ABSENT_HUB_ON_NEW_NATIVE_BOOT', 'OWN_ACTUAL_SAME_BOOT_HUB_RETURN')
    self.wg()
    self.transport()
    self.kernel()
    value = self.terminal_after_own_START({'pid': 0, 'InvocationID': ''})
    value['initial_systemd_boot_job_failed_before_watcher_OS_sample'] = True
    return value

  def never_started(self, unit):
    props = self.properties(unit)
    require(props['MainPID'] == props['ExecMainPID'] == props['ExecMainStartTimestampMonotonic'] == '0'
        and props['ActiveState'] in ('inactive', 'failed'), 'NO_FIRST_BOOT_SERVICE_EXECUTION_YET')
    return props

  def joined_unit(self, unit, props):
    require(props['MainPID'] == '0' and props['ActiveState'] in ('inactive', 'failed')
        and props['SubState'] in ('dead', 'failed'), 'QUIESCENT_BOOT_PREDECESSOR_UNIT')
    if props['ExecMainPID'] != '0':
      require(props['ExecMainPID'].isdigit() and not Path('/proc/' + props['ExecMainPID']).exists(),
          'PREVIOUS_BOOT_OWNER_PHYSICAL_PID_ABSENT')
    group = Path('/sys/fs/cgroup/system.slice') / unit / 'cgroup.procs'
    require(not group.exists() or read(group, 65536).strip() == b'', 'ALL_PREVIOUS_BOOT_OWNER_NATIVE_CHILDREN_ABSENT')

  def successful_boot_unit(self, unit):
    props = self.properties(unit)
    return (props['ActiveState'] == 'active' and props['SubState'] == 'exited'
        and props['MainPID'] == '0' and props['Result'] == 'success'
        and props['ExecMainStatus'] == '0')

  def boot_start_service_once(self, unit, predecessor):


    require(unit in (COLD, HUB, UNIT), 'ONLY_EXACT_FIXED_BOOT_START_UNITS')
    key = sha(wire({'boot': self.boot, 'unit': unit, 'predecessor': predecessor}))
    prefix = self.boot + '-BOOT-' + unit + '-'
    attempts = list(LEDGER.glob(prefix + '*-POSSIBLE-START.PUBLIC.json'))
    require(len(attempts) < 3, 'AT_MOST_THREE_DISTINCT_PRE_EFFECT_BOOT_ATTEMPTS_PER_UNIT')
    marker = LEDGER / (prefix + key + '-POSSIBLE-START.PUBLIC.json')
    if marker.exists():
      return False
    prior = []
    for path in attempts:
      raw = read(path, 32768, 0o600)
      caller_path = path.with_name(path.name.replace('-POSSIBLE-START.PUBLIC.json',
                             '-ORIGINAL-CALLER.PUBLIC.json'))


      caller = loads(read(caller_path, 32768, 0o600))
      prior.append({'possible_start': loads(raw),
             'possible_start_ref': {'path': str(path), 'sha256': sha(raw)},
             'original_caller': caller})
    require(prior_boot_start_callers_quiescent(prior, self.boot, unit,
          self.authorities) == len(attempts), 'ALL_FIXED_PATH_PRIOR_BOOT_CALLERS_AUTHENTICATED')
    once(marker, wire({'schema': 'Root_boot_pre_effect_one_original_unit_START_possible_v1',
      'source_sha256': self.sha, 'standing_config_sha256': sha(self.raw_config),
      'boot_id': self.boot, 'unit': unit, 'predecessor': predecessor,
      'started_monotonic': time.monotonic(), 'same_possible_START_retry': False}))
    self.start_admitted = unit
    error = None
    argv = ['/usr/bin/systemctl', 'start', unit]
    try:
      self.call('one-boot-START-' + unit, argv, seconds=70 if unit != UNIT else 12)
    except Exception as caught:
      error = caught
    call = next((row for row in reversed(self.calls) if row['role'] == 'one-boot-START-' + unit), None)
    if call is None:
      call = {'role': 'one-boot-START-' + unit, 'argv': argv,
          'original_transport': dict(getattr(self.n.native, 'last_custody', {}) or {}),
          'stdout_sha256': None, 'stdout_bytes': None,
          'original_native_exception_before_stdout_return': True}
    once(LEDGER / (prefix + key + '-ORIGINAL-CALLER.PUBLIC.json'), wire({
      'schema': 'Root_boot_original_unit_START_caller_v1', 'boot_id': self.boot,
      'source_sha256': self.sha, 'possible_START_ref': {'path': str(marker), 'sha256': sha(read(marker, 32768, 0o600))},
      'original_native_call': call, 'expected_zero': error is None,
      'exception_class': None if error is None else type(error).__name__}))
    return error is None

  def bootstrap_never_started(self):
    """Complete the local boot jobs, never retry an existing kernel intent.

        Hub imports current controller helpers but performs no Core/API/DNS
        read: Source47 initialization is empty. A local pre-intent failure can
        therefore be retried as a distinct real unit execution after quiescence.
        """
    require(self.boot != INITIAL_BOOT, 'AUTONOMOUS_BOOT_ONLY_LATER_BOOT')
    self.deadline = time.monotonic() + 90
    self.never_started(UNIT)
    RUN.mkdir(mode=0o700, exist_ok=True)
    directory(RUN)
    with self.maintenance():
      self.static()
      self.never_started(UNIT)
      if not self.successful_boot_unit(COLD):
        require(not Path('/sys/class/net/wg-capacity').exists(), 'NO_INTERFACE_BEFORE_COLD_BOOT_RETRY')
        self.never_started(HUB)
        props = self.properties(COLD)
        self.joined_unit(COLD, props)
        marker = LEDGER / (self.boot + '-COLD-POSSIBLE-SEND.PUBLIC.json')
        returned = LEDGER / (self.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json')
        require(not marker.exists() and not returned.exists(), 'NO_COLD_KERNEL_INTENT_OR_RETURN_RETRY')
        self.boot_start_service_once(COLD, props)
        return False
      if not self.successful_boot_unit(HUB):
        require(not Path('/sys/class/net/wg-capacity').exists(), 'NO_INTERFACE_BEFORE_HUB_BOOT_RETRY')
        props = self.properties(HUB)
        self.joined_unit(HUB, props)
        require(not (RUN / ('hub-boot-' + self.boot + '-INTENT.json')).exists()
            and not (RUN / ('hub-boot-' + self.boot + '-RETURN.json')).exists(),
            'NO_HUB_KERNEL_INTENT_OR_RETURN_RETRY')
        self.hub.route_shape(loads(self.call('boot-full-routes-RAM',
          ['/usr/sbin/ip', '-j', '-4', 'route', 'show', 'table', 'all'])), False)
        self.boot_start_service_once(HUB, props)
        return False



      self.wg()
      self.transport()
      self.kernel()
      props = self.never_started(UNIT)
      self.joined_unit(UNIT, props)
      self.boot_start_service_once(UNIT, props)
      return True

  def recover_terminal(self, expected):
    self.calls = []
    self.deadline = time.monotonic() + 240
    self.recovering_identity = None
    with self.maintenance():
      self.static()
      before = self.failed(expected)
      self.wg()
      self.transport()
      self.kernel()
      lock = os.open(RUN / 'controller.lock', os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
      try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require(self.failed(expected) == before, 'SAME_TERMINAL_PREDECESSOR_UNDER_CONTROLLER_LOCK')
        key = self.key(expected)
        existing = list(LEDGER.glob(self.boot + '-RECOVERY-*-POSSIBLE-START.PUBLIC.json'))
        require(len(existing) < 3, 'THREE_DISTINCT_TERMINAL_RECOVERIES_MAXIMUM_PER_BOOT')
        for path in existing:
          previous = loads(read(path, 32768, 0o600))
          require((previous['source_sha256'], previous['standing_config_sha256']) in self.authorities
              and previous['boot_id'] == self.boot
              and 0 <= previous['started_monotonic'] <= time.monotonic(), 'SAME_BOOT_ORIGINAL_RECOVERY_CLOCK')
          if time.monotonic() - previous['started_monotonic'] < 300:
            return expected, None
        marker = LEDGER / (self.boot + '-RECOVERY-' + key + '-POSSIBLE-START.PUBLIC.json')
        once(marker, wire({'schema': 'Root_terminal_predecessor_one_new_START_possible_v1',
          'boot_id': self.boot, 'predecessor': expected, 'source_sha256': self.sha,
          'standing_config_sha256': sha(self.raw_config), 'started_monotonic': time.monotonic(),
          'old_unknown_hot_batch_replayed_or_qualified': False}))
      finally:
        os.close(lock)
      require(self.failed(expected) == before, 'SAME_TERMINAL_PREDECESSOR_IMMEDIATELY_BEFORE_START')
      self.start_admitted = UNIT
      start_error = None
      start_argv = ['/usr/bin/systemctl', 'start', UNIT]
      try:
        self.call('one-terminal-controller-START', start_argv, seconds=12)
      except Exception as error:
        start_error = error
      original_call = next((row for row in reversed(self.calls)
        if row['role'] == 'one-terminal-controller-START'), None)
      if original_call is None:
        original_call = {'role': 'one-terminal-controller-START', 'argv': start_argv,
          'original_transport': dict(getattr(self.n.native, 'last_custody', {}) or {}),
          'stdout_sha256': None, 'stdout_bytes': None,
          'original_native_exception_before_stdout_return': True}
      start_raw = wire({'schema': 'Root_terminal_recovery_original_controller_START_caller_v1',
        'source_sha256': self.sha, 'predecessor': expected,
        'possible_START_ref': {'path': str(marker), 'sha256': sha(read(marker, 32768, 0o600))},
        'original_native_call': original_call,
        'original_START_returned_expected_zero': start_error is None,
        'original_exception_class': None if start_error is None else type(start_error).__name__})
      start_path = LEDGER / (key + '-ORIGINAL-START-CALLER.PUBLIC.json')
      once(start_path, start_raw)
      if start_error is not None:



        facts = original_call['original_transport']
        if facts.get('local_child_joined') is True and facts.get('all_local_FDs_closed') is True:
          try:
            self.recovering_identity = self.terminal_after_own_START(expected)
          except Exception:
            pass
        raise start_error
      try:
        current = self.identity()
      except Exception:
        self.recovering_identity = self.terminal_after_own_START(expected)
        raise RuntimeError('NEW_UNIT_FAILED_BEFORE_RUNNING_OS_IDENTITY_COULD_BE_SAMPLED') from None
      require(current['InvocationID'] != expected['InvocationID'] and current['pid'] != expected['pid']
          and current['initial_R42_admitted_lifetime'] is False, 'DISTINCT_FRESH_REVIEWED_CONTROLLER_LIFETIME')
      self.recovering_identity = current
      result = self.qualify_new_lifetime(current, self.deadline,
        {'path': str(start_path), 'sha256': sha(start_raw)})
      return current, result

  def watch(self):

    fd = os.open(LEDGER / 'guardian.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
      known = dict(self.initial_identity) if self.boot==self.initial_identity['boot_id']else None
      while True:
        self.calls = []
        self.static()
        self.deadline = time.monotonic() + 60
        props = self.properties()
        if (known is None and self.boot != INITIAL_BOOT and props['MainPID'] == '0'
            and props['ExecMainPID'] == '0' and props['ExecMainStartTimestampMonotonic'] == '0'
            and props['ActiveState'] in ('inactive', 'failed')):
          try:
            self.bootstrap_never_started()
          except BlockingIOError:
            pass
          except Exception as error:
            print(wire({'schema': 'Root_network_guardian_local_boot_HOLD_v1',
              'source_sha256': self.sha, 'boot_id': self.boot,
              'guard': str(error)[:180], 'error_class': type(error).__name__,
              'kernel_intent_or_unknown_native_replayed': False}).decode(), end='', flush=True)
          time.sleep(10)
          continue
        if props['ActiveState'] == 'failed' and known is None and self.boot != INITIAL_BOOT:
          known = self.boot_terminal_predecessor()
        if props['ActiveState'] == 'active' and props['SubState'] == 'running':
          current = self.identity()
          if current != known:
            known = current
            measured = self.original_qualification_exists(current)
            started = (LEDGER / (self.key(current) + '-FIXED120-START.PUBLIC.json')).exists()
            if not current['initial_R42_admitted_lifetime'] and not measured and not started:
              try:
                self.qualify_new_lifetime(current)
              except Exception as error:



                once(LEDGER / (self.key(current) + '-QUALIFICATION-HOLD.PUBLIC.json'), wire({
                  'schema': 'Root_new_lifetime_original_window_HOLD_v1',
                  'source_sha256': self.sha, 'identity': current,
                  'error_class': type(error).__name__, 'guard': str(error)[:180],
                  'original_native_calls': self.calls, 'epoch_replayed': False}))
                continue
          try:
            observed,prefix,suffix,reads=self.current15_readonly()
            require(observed['identity']==current,'SAME_CURRENT_WATCHER_LIFETIME')
            invocation=os.environ.get('INVOCATION_ID','')
            require(re.fullmatch('[a-f0-9]{32}',invocation),'OWN_CURRENT_GUARDIAN_INVOCATION')
            key=self.boot+'-GUARDIAN-'+invocation+'-FIRST-CURRENT15'
            path=LEDGER/(key+'-RETURN.PUBLIC.json')
            if not path.exists():
              g=self.current15_context();first_ref=g.reader.persist(self,g,observed,prefix,suffix,reads,key)
            else:first_ref={'path':str(path),'sha256':sha(read(path,1<<20,0o600))}
            value={'schema':'Root_network_guardian_current_operational_descriptor_v1','source_sha256':self.sha,'identity':current,'read_finished_monotonic':observed['finished_monotonic'],'kernel_observed':observed['kernel_observed'],'all_four_backends_currently_positive':observed['kernel']['all_four_backends_and_reverse_sources_positive'],'transport':observed['transport'],'current15':observed['measurement'],'first_own_current15_original_ref':first_ref,'first_ref_is_historical_after_first_sample':True,'mutations_this_sample':0,'historical120_is_not_current15_or_Guest_business_authority':True,'unobserved_lifetime_continuity_claimed':False}
            print(wire(value).decode(),end='',flush=True)
          except Exception as error:
            print(wire({'schema':'Root_network_guardian_current15_HOLD_v1','source_sha256':self.sha,'identity':current,'error_class':type(error).__name__,'guard':str(error)[:180],'mutations_this_sample':0,'current15_or_business_authority':False}).decode(),end='',flush=True)
        elif props['ActiveState'] == 'failed' and known is not None:
          try:
            known, result = self.recover_terminal(known)
            if result is not None:
              print(wire({'schema': 'Root_guardian_new_lifetime_return_ref_v1',
                'identity': known, 'return_ref': {'path': str(LEDGER / (self.key(known) + '-QUALIFIED.PUBLIC.json')),
                'sha256': sha(wire(result))}}).decode(), end='', flush=True)
          except BlockingIOError:
            pass
          except Exception as error:
            if self.recovering_identity is not None:
              known = self.recovering_identity
            print(wire({'schema': 'Root_network_guardian_terminal_recovery_HOLD_v1',
              'source_sha256': self.sha, 'predecessor_or_new_identity': known,
              'guard': str(error)[:180], 'error_class': type(error).__name__,
              'old_unknown_native_success_inferred': False, 'same_possible_START_replayed': False}).decode(), end='', flush=True)
        elif props['ActiveState'] == 'inactive':

          known = None
        else:
          require(props['ActiveState'] in ('activating', 'deactivating'), 'UNADMITTED_CHANGED_OR_UNKNOWN_SERVICE_STATE')
        time.sleep(5)
    finally:
      os.close(fd)
def main():
  require_bound()
  p = argparse.ArgumentParser()
  mode = p.add_mutually_exclusive_group(required=True)
  mode.add_argument('--cold-restore', action='store_true')
  mode.add_argument('--watch', action='store_true')
  mode.add_argument('--read-once', action='store_true')
  p.add_argument('--source-sha256', required=True)
  args = p.parse_args()
  owner = Owner(args.source_sha256)
  if args.cold_restore:
    value = owner.cold_restore()
    if owner.boot == INITIAL_BOOT:
      print(wire({'schema':'Root_initial_boot_Cold_read_adoption_descriptor_v1','boot_id':owner.boot,'insert_count':0,'original_return_ref':owner.initial_cold_read_return_ref,'old301128_failed_reclassified':False,'cold_kernel_restoration_or_new120_qualified':False}).decode(),end='',flush=True)
    else:
      print(wire({'schema': value['schema'], 'boot_id': value['boot_id'], 'insert_count': 8,
          'original_return_ref': {'path': str(LEDGER / (owner.boot + '-COLD-ORIGINAL-RETURN.PUBLIC.json')),
                      'sha256': sha(wire(value))}}).decode(), end='', flush=True)
  elif args.read_once:
    identity = owner.identity()
    wg = owner.wg()
    transport = owner.transport()
    kernel, observed = owner.kernel()
    require(owner.identity() == identity, 'SAME_ACTUAL_LIFETIME_DURING_READONLY')
    print(wire({'schema': 'Root_network_recovery_readonly_prepared_current_return_v1',
      'identity': identity, 'WG': wg, 'transport': transport, 'kernel': kernel,
      'kernel_observed': observed, 'original_native_calls': owner.calls, 'mutations': 0,
      'new_runtime_or_new_boot_executed_or_qualified': False}).decode(), end='', flush=True)
  else:
    owner.watch()
if __name__ == '__main__':
  main()
