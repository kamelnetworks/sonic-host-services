import os
import sys

from swsscommon import swsscommon
from parameterized import parameterized
from unittest import TestCase, mock
from pyfakefs.fake_filesystem_unittest import patchfs
from sonic_py_common.general import load_module_from_source

from .test_bgp_mgmt_exclusion_vectors import CACLMGRD_BGP_FALLBACK_TEST_VECTOR
from tests.common.mock_configdb import MockConfigDb

DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'


def _is_bgp_permit(cmd):
    """True if cmd is an INPUT ACCEPT rule for TCP destination port 179."""
    return (cmd[0] in ('iptables', 'ip6tables')
            and (('-A' in cmd and cmd[cmd.index('-A') + 1] == 'INPUT')
                 or ('-I' in cmd and cmd[cmd.index('-I') + 1] == 'INPUT'))
            and '-p' in cmd and cmd[cmd.index('-p') + 1] == 'tcp'
            and '--dport' in cmd and cmd[cmd.index('--dport') + 1] == '179'
            and '-j' in cmd and cmd[cmd.index('-j') + 1] == 'ACCEPT')


def _is_scoped(cmd):
    """
    True if the permit is limited in any way that keeps it off the
    management port: a source match (-s), an ingress interface match (-i)
    or upstream's management exclusion ('!', '-i', 'eth0').
    """
    if '-s' in cmd:
        return True
    for i, tok in enumerate(cmd):
        if tok == '-i':
            return True
        if tok == '!' and cmd[i + 1:i + 3] == ['-i', 'eth0']:
            return True
    return False


class TestCaclmgrdBgpMgmtExclusion(TestCase):
    """
    Verify the TCP/179 permits caclmgrd emits when only a BGP_PEER_GROUP or
    BGP_PEER_RANGE is configured (kamelnetworks/sonic-buildimage#30).

    Upstream caclmgrd emitted one blanket permit wrapped in
    exclude_mgmt_port(): "-p tcp --dport 179 ! -i eth0 -j ACCEPT". The fork
    replaced it with per-session permits derived from BGP_NEIGHBOR plus a
    fallback that accepts TCP/179 from every source on every interface as
    soon as any peer group or range exists.

    The assertion is intentionally minimal: a permit may be scoped by source,
    by ingress interface or by the management exclusion, whichever
    kamelnetworks/sonic-buildimage#38 settles on, but it must not be
    completely unscoped.
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

    def _build_daemon(self):
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ip = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ipv6 = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.generate_block_ip2me_traffic_iptables_commands = mock.MagicMock(return_value=[])
        self.caclmgrd.ControlPlaneAclManager.get_chain_list = mock.MagicMock(return_value=["INPUT", "FORWARD", "OUTPUT"])
        self.caclmgrd.ControlPlaneAclManager.get_chassis_midplane_interface_ip = mock.MagicMock(return_value='')
        return self.caclmgrd.ControlPlaneAclManager("caclmgrd")

    def _generate(self, test_data, fs):
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)
        MockConfigDb.set_config_db(test_data["config_db"])
        caclmgrd_daemon = self._build_daemon()
        rules, _ = caclmgrd_daemon.get_acl_rules_and_translate_to_iptables_commands('', MockConfigDb())
        return [list(r) for r in rules]

    @parameterized.expand(CACLMGRD_BGP_FALLBACK_TEST_VECTOR)
    @patchfs
    def test_bgp_fallback_permit_is_not_unscoped(self, _test_name, test_data, fs):
        """No automatic TCP/179 permit may accept from any source on any interface."""
        rules = self._generate(test_data, fs)
        bgp_permits = [r for r in rules if _is_bgp_permit(r)]
        self.assertTrue(bgp_permits, "expected at least one automatic BGP permit")
        unscoped = [' '.join(r) for r in bgp_permits if not _is_scoped(r)]
        self.assertEqual(
            unscoped, [],
            "TCP/179 permits with neither a source, an ingress interface nor "
            "the management exclusion: {}".format(unscoped))
