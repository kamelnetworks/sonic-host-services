import os
import sys

from swsscommon import swsscommon
from parameterized import parameterized
from unittest import TestCase, mock
from pyfakefs.fake_filesystem_unittest import patchfs
from sonic_py_common.general import load_module_from_source

from .test_bgp_session_vectors import CACLMGRD_BGP_SESSION_TEST_VECTOR
from tests.common.mock_configdb import MockConfigDb

DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'


def _is_bgp_permit(cmd):
    """True if cmd is an INPUT ACCEPT rule for TCP destination port 179."""
    return ('-A' in cmd and cmd[cmd.index('-A') + 1] == 'INPUT'
            and '-p' in cmd and cmd[cmd.index('-p') + 1] == 'tcp'
            and '--dport' in cmd and cmd[cmd.index('--dport') + 1] == '179'
            and '-j' in cmd and cmd[cmd.index('-j') + 1] == 'ACCEPT')


def _has_match(cmd, match):
    """True if the option/value pair `match` appears in cmd (e.g. ['-s', '10.0.0.1'])."""
    opt, val = match
    return any(cmd[i] == opt and cmd[i + 1] == val for i in range(len(cmd) - 1))


class TestCaclmgrdBgpSession(TestCase):
    """
    Verify the per-session BGP TCP/179 permits caclmgrd derives from
    CONFIG_DB BGP_NEIGHBOR (kamelnetworks fork).

    See kamelnetworks/sonic-buildimage#28 and #9.
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
        try:
            rules, _ = caclmgrd_daemon.get_acl_rules_and_translate_to_iptables_commands('', MockConfigDb())
        except ValueError as e:
            self.fail("ACL rule generation aborted on BGP_NEIGHBOR {}: {!r}".format(
                sorted(test_data["config_db"]["BGP_NEIGHBOR"]), e))
        return [list(r) for r in rules]

    @parameterized.expand(CACLMGRD_BGP_SESSION_TEST_VECTOR)
    @patchfs
    def test_generation_does_not_abort(self, _test_name, test_data, fs):
        """A malformed or interface-valued local_addr must never abort the whole ruleset."""
        self._generate(test_data, fs)

    @parameterized.expand(CACLMGRD_BGP_SESSION_TEST_VECTOR)
    @patchfs
    def test_every_configured_peer_gets_a_permit(self, _test_name, test_data, fs):
        """Each BGP_NEIGHBOR entry yields a TCP/179 INPUT ACCEPT rule matching that peer."""
        rules = self._generate(test_data, fs)
        bgp_permits = [r for r in rules if _is_bgp_permit(r)]
        for binary, match in test_data["expected_permits"]:
            self.assertTrue(
                any(r[0] == binary and _has_match(r, match) for r in bgp_permits),
                "No {} TCP/179 ACCEPT rule matching {} in: {}".format(
                    binary, ' '.join(match), bgp_permits))
