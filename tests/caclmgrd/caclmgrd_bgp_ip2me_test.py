"""
Regression test for kamelnetworks/sonic-buildimage#71.

BGP peers configured outside CONFIG_DB BGP_NEIGHBOR (vtysh / split mode) must
still be able to open a TCP/179 session to an interface IP from a front-panel
port. caclmgrd's ip2me rules drop every packet to an interface IP that no
earlier rule accepted, so without a BGP permit the SYN is dropped.

The expectations are checked by walking the generated INPUT chain with a
synthetic packet, so they hold for any shape of fix (blanket permit, per
interface permit, ...) and don't prescribe the BGP ACL semantics decided in
kamelnetworks/sonic-buildimage#38.
"""
import ipaddress
import os
import sys

from swsscommon import swsscommon
from parameterized import parameterized
from sonic_py_common.general import load_module_from_source
from unittest import TestCase, mock
from pyfakefs.fake_filesystem_unittest import patchfs

from .test_bgp_ip2me_vectors import CACLMGRD_BGP_IP2ME_CONFIG_VECTOR
from tests.common.mock_configdb import MockConfigDb

DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'

NS_PREFIX = ['ip', 'netns', 'exec']


class Packet(object):
    """A synthetic inbound packet, as iptables' INPUT chain would see it."""
    def __init__(self, src, dst, iif, proto='tcp', dport=179, ctstate='NEW', icmp_type=None):
        self.src = ipaddress.ip_address(src)
        self.dst = ipaddress.ip_address(dst)
        self.iif = iif
        self.proto = proto
        self.dport = dport
        self.ctstate = ctstate
        self.icmp_type = icmp_type

    @property
    def tool(self):
        return 'iptables' if self.src.version == 4 else 'ip6tables'


def _rule_matches(rule, packet):
    """
    Evaluate one "-A INPUT ..." rule's match options against the packet.
    Returns (matches, target). Raises on any option this evaluator does not
    understand, so an unexpected rule shape fails the test loudly instead of
    being silently mis-evaluated.
    """
    tokens = list(rule)
    target = None
    matches = True
    negate = False
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == '!':
            negate = True
            i += 1
            continue

        def arg():
            return tokens[i + 1]

        if tok in ('-s', '-d'):
            net = ipaddress.ip_network(arg(), strict=False)
            addr = packet.src if tok == '-s' else packet.dst
            hit = (addr.version == net.version and addr in net)
            consumed = 2
        elif tok == '-i':
            hit = (packet.iif == arg())
            consumed = 2
        elif tok == '-p':
            proto = arg()
            hit = (packet.proto == proto or (packet.proto == 'icmpv6' and proto == 'ipv6-icmp'))
            consumed = 2
        elif tok == '--dport':
            lo, _, hi = arg().partition(':')
            hi = hi or lo
            hit = (packet.dport is not None and int(lo) <= packet.dport <= int(hi))
            consumed = 2
        elif tok == '--ctstate':
            hit = (packet.ctstate in arg().split(','))
            consumed = 2
        elif tok in ('--icmp-type', '--icmpv6-type'):
            hit = (packet.icmp_type == arg())
            consumed = 2
        elif tok == '-m':
            # Match extension loader (conntrack, comment, ...). Its options are
            # handled individually above / below.
            hit = True
            consumed = 2
        elif tok == '--comment':
            hit = True
            consumed = 2
        elif tok == '-j':
            target = arg()
            hit = True
            consumed = 2
        elif tok == '--reject-with':
            hit = True
            consumed = 2
        else:
            raise AssertionError("evaluator does not understand option {!r} in rule {!r}".format(tok, rule))

        if negate:
            hit = not hit
            negate = False
        matches = matches and hit
        i += consumed

    if target is None:
        raise AssertionError("rule without target: {!r}".format(rule))
    return matches, target


def input_chain_verdict(cmds, packet):
    """
    Walk the generated commands for the packet's address family and return the
    verdict of the first INPUT rule that matches, or the chain policy if none
    does. Only the host namespace (no "ip netns exec" prefix) is considered.
    """
    policy = None
    for cmd in cmds:
        cmd = list(cmd)
        if cmd[:3] == NS_PREFIX:
            continue
        if not cmd or cmd[0] != packet.tool:
            continue
        if cmd[1:3] == ['-P', 'INPUT']:
            policy = cmd[3]
            continue
        if cmd[1] == '-I' and cmd[2] == 'INPUT':
            raise AssertionError("evaluator does not support -I in the generated ruleset: {!r}".format(cmd))
        if cmd[1:3] != ['-A', 'INPUT']:
            continue
        matches, target = _rule_matches(cmd[3:], packet)
        if matches and target in ('ACCEPT', 'DROP', 'REJECT'):
            return target
    return policy


class TestCaclmgrdBgpIp2Me(TestCase):
    """
    Test that inbound BGP to an interface IP is not dropped by the ip2me rules
    when the peer is not in BGP_NEIGHBOR.
    """
    def setUp(self):
        swsscommon.ConfigDBConnector = MockConfigDb
        test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.dirname(test_path)
        scripts_path = os.path.join(modules_path, "scripts")
        sys.path.insert(0, modules_path)
        caclmgrd_path = os.path.join(scripts_path, 'caclmgrd')
        self.caclmgrd = load_module_from_source('caclmgrd', caclmgrd_path)
        self.maxDiff = None

    def _generate(self, config_db, fs):
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)  # fake database_config.json
        MockConfigDb.set_config_db(config_db)
        manager = self.caclmgrd.ControlPlaneAclManager
        manager.get_namespace_mgmt_ip = mock.MagicMock()
        manager.get_namespace_mgmt_ipv6 = mock.MagicMock()
        manager.get_chain_list = mock.MagicMock(return_value=["INPUT", "FORWARD", "OUTPUT"])
        manager.get_chassis_midplane_interface_ip = mock.MagicMock(return_value='')
        manager.generate_allow_internal_docker_ip_traffic_commands = mock.MagicMock(return_value=[])
        manager.generate_allow_internal_chasis_midplane_traffic = mock.MagicMock(return_value=[])
        # generate_block_ip2me_traffic_iptables_commands is deliberately NOT mocked.
        daemon = manager("caclmgrd")
        cmds, _ = daemon.get_acl_rules_and_translate_to_iptables_commands('', MockConfigDb())
        return cmds

    # --- Evaluator sanity checks. These pass today and mirror the hardware
    # --- evidence in the issue (ping works, established sessions survive).

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_ip2me_drop_is_generated(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        cmds = [tuple(c) for c in cmds]
        self.assertIn(('iptables', '-A', 'INPUT', '-d', '10.200.0.1/32', '-j', 'DROP'), cmds)
        self.assertIn(('ip6tables', '-A', 'INPUT', '-d', 'fc00:200::1/128', '-j', 'DROP'), cmds)

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_icmp_echo_to_interface_ip_accepted(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        ping = Packet('10.200.0.0', '10.200.0.1', 'Ethernet0', proto='icmp', dport=None, icmp_type='echo-request')
        self.assertEqual('ACCEPT', input_chain_verdict(cmds, ping))

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_established_bgp_to_interface_ip_accepted(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        established = Packet('10.200.0.0', '10.200.0.1', 'Ethernet0', ctstate='ESTABLISHED')
        self.assertEqual('ACCEPT', input_chain_verdict(cmds, established))

    # --- The bug (#71): a new BGP session from a front-panel port to an
    # --- interface IP, with the peer configured in vtysh only.

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_bgp_syn_to_ipv4_interface_ip_accepted(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        syn = Packet('10.200.0.0', '10.200.0.1', 'Ethernet0')
        self.assertEqual('ACCEPT', input_chain_verdict(cmds, syn),
                         "TCP/179 SYN to a front-panel interface IP must not be dropped by ip2me")

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_bgp_syn_to_ipv6_interface_ip_accepted(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        syn = Packet('fc00:200::', 'fc00:200::1', 'Ethernet0')
        self.assertEqual('ACCEPT', input_chain_verdict(cmds, syn),
                         "TCP/179 SYN to a front-panel IPv6 interface IP must not be dropped by ip2me")

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_bgp_syn_to_loopback_ip_accepted(self, _name, test_data, fs):
        """Multihop/EVPN sessions between loopbacks (SONIX lab design)."""
        cmds = self._generate(test_data["config_db"], fs)
        syn = Packet('10.1.0.2', '10.1.0.1', 'Ethernet0')
        self.assertEqual('ACCEPT', input_chain_verdict(cmds, syn),
                         "TCP/179 SYN to a loopback IP via a front-panel port must not be dropped by ip2me")

    # --- The issue's stated test also requires the permit to keep upstream's
    # --- management exclusion: the same SYN arriving on eth0 is not accepted.

    @parameterized.expand(CACLMGRD_BGP_IP2ME_CONFIG_VECTOR)
    @patchfs
    def test_bgp_syn_to_interface_ip_via_mgmt_port_not_accepted(self, _name, test_data, fs):
        cmds = self._generate(test_data["config_db"], fs)
        syn = Packet('172.18.0.50', '10.200.0.1', 'eth0')
        self.assertNotEqual('ACCEPT', input_chain_verdict(cmds, syn),
                            "TCP/179 to an interface IP arriving on eth0 must not be accepted")
