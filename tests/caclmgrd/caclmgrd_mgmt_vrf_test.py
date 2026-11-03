import os
import sys
import threading

from swsscommon import swsscommon
from parameterized import parameterized
from sonic_py_common.general import load_module_from_source
from unittest import TestCase, mock
from unittest.mock import MagicMock, patch
from pyfakefs.fake_filesystem_unittest import patchfs

from tests.common.mock_configdb import MockConfigDb


DBCONFIG_PATH = '/var/run/redis/sonic-db/database_config.json'

STATE_DB_ID = 6
CONFIG_DB_ID = 4


def localhost_rules(intf):
    """The localhost ACCEPT pair caclmgrd emits for a VRF master interface."""
    return (
        ('iptables', '-A', 'INPUT', '-s', '127.0.0.1', '-i', intf, '-j', 'ACCEPT'),
        ('ip6tables', '-A', 'INPUT', '-s', '::1', '-i', intf, '-j', 'ACCEPT'),
    )


MGMT_VRF_RULES = localhost_rules('mgmt')

# (table, key, op, fvs): CONFIG_DB events that must trigger a rule rebuild
VRF_CHANGE_EVENTS = [
    ("mgmt_vrf_set", "MGMT_VRF_CONFIG", "vrf_global", "SET", [("mgmtVrfEnabled", "true")]),
    ("mgmt_vrf_del", "MGMT_VRF_CONFIG", "vrf_global", "DEL", []),
    ("vrf_set", "VRF", "Vrf_red", "SET", []),
    ("vrf_del", "VRF", "Vrf_red", "DEL", []),
]


class TestCaclmgrdMgmtVrf(TestCase):
    """
        Localhost traffic inside VRFs (kamelnetworks/sonic-buildimage#36):
        MGMT_VRF_CONFIG|vrf_global.mgmtVrfEnabled is a ConfigDB string and must be
        compared, not used as a Python truth value, and changes to MGMT_VRF_CONFIG
        and VRF must regenerate the control plane ACL rules.
    """
    def setUp(self):
        swsscommon.ConfigDBConnector = MockConfigDb
        test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.dirname(test_path)
        scripts_path = os.path.join(modules_path, "scripts")
        sys.path.insert(0, modules_path)
        caclmgrd_path = os.path.join(scripts_path, 'caclmgrd')
        self.caclmgrd = load_module_from_source('caclmgrd', caclmgrd_path)

    def setup_daemon(self, config_db):
        MockConfigDb.set_config_db(config_db)
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ip = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ipv6 = mock.MagicMock()
        self.caclmgrd.ControlPlaneAclManager.generate_block_ip2me_traffic_iptables_commands = mock.MagicMock(return_value=[])
        self.caclmgrd.ControlPlaneAclManager.generate_allow_internal_docker_ip_traffic_commands = mock.MagicMock(return_value=[])
        self.caclmgrd.ControlPlaneAclManager.generate_allow_internal_chasis_midplane_traffic = mock.MagicMock(return_value=[])
        self.caclmgrd.ControlPlaneAclManager.get_chain_list = mock.MagicMock(return_value=["INPUT", "FORWARD", "OUTPUT"])
        self.caclmgrd.ControlPlaneAclManager.get_chassis_midplane_interface_ip = mock.MagicMock(return_value='')
        return self.caclmgrd.ControlPlaneAclManager("caclmgrd")

    def host_rules(self, extra_tables):
        config_db = {"DEVICE_METADATA": {"localhost": {}}, "FEATURE": {}}
        config_db.update(extra_tables)
        daemon = self.setup_daemon(config_db)
        cmds, _ = daemon.get_acl_rules_and_translate_to_iptables_commands('', MockConfigDb())
        return [tuple(c) for c in cmds]

    @patchfs
    def test_mgmt_vrf_enabled_true_emits_rules(self, fs):
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)
        rules = self.host_rules({"MGMT_VRF_CONFIG": {"vrf_global": {"mgmtVrfEnabled": "true"}}})
        for rule in MGMT_VRF_RULES:
            self.assertIn(rule, rules)

    @patchfs
    def test_mgmt_vrf_enabled_false_emits_no_rules(self, fs):
        """ConfigDB stores booleans as strings: 'false' is not enabled."""
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)
        rules = self.host_rules({"MGMT_VRF_CONFIG": {"vrf_global": {"mgmtVrfEnabled": "false"}}})
        for rule in MGMT_VRF_RULES:
            self.assertNotIn(rule, rules)

    @patchfs
    def test_mgmt_vrf_absent_emits_no_rules(self, fs):
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)
        rules = self.host_rules({})
        for rule in MGMT_VRF_RULES:
            self.assertNotIn(rule, rules)

    @patchfs
    def test_vrf_table_emits_rules_per_vrf(self, fs):
        if not os.path.exists(DBCONFIG_PATH):
            fs.create_file(DBCONFIG_PATH)
        rules = self.host_rules({"VRF": {"Vrf_red": {}, "Vrf_blue": {"vni": "100"}}})
        for vrf in ("Vrf_red", "Vrf_blue"):
            for rule in localhost_rules(vrf):
                self.assertIn(rule, rules)
        for rule in MGMT_VRF_RULES:
            self.assertNotIn(rule, rules)

    @parameterized.expand(VRF_CHANGE_EVENTS)
    @patch("caclmgrd.swsscommon")
    @patch("caclmgrd.threading.Thread")
    @patch("os.geteuid", return_value=0)
    def test_run_regenerates_rules_on_vrf_change(self, test_name, table, key, op, fvs,
                                                 mock_geteuid, mock_thread, mock_swsscommon):
        """A CONFIG_DB event on MGMT_VRF_CONFIG or VRF must schedule an ACL rebuild."""
        mock_swsscommon.ConfigDBConnector = MockConfigDb
        MockConfigDb.set_config_db({"DEVICE_METADATA": {"localhost": {}}, "FEATURE": {}})
        mock_swsscommon.CFG_ACL_TABLE_TABLE_NAME = "ACL_TABLE"
        mock_swsscommon.CFG_ACL_RULE_TABLE_NAME = "ACL_RULE"
        mock_swsscommon.SonicDBConfig.getDbId.side_effect = \
            lambda db_name: STATE_DB_ID if db_name == "STATE_DB" else CONFIG_DB_ID

        # Every SubscriberStateTable the daemon creates is recorded by table name;
        # only the table under test has an event queued, all others are empty.
        subscribed = {}
        pending = [(key, op, fvs)]

        def subscriber_table(conn, table_name, *args):
            tbl = MagicMock(name="SubscriberStateTable({})".format(table_name))
            tbl.getTableNameSeparator.return_value = "|"
            if table_name == table:
                tbl.pop.side_effect = lambda: pending.pop(0) if pending else ('', None, None)
            else:
                tbl.pop.return_value = ('', None, None)
            subscribed.setdefault(table_name, []).append(tbl)
            return tbl
        mock_swsscommon.SubscriberStateTable.side_effect = subscriber_table

        # One CONFIG_DB event in the host namespace, then leave the select loop.
        mock_swsscommon.Select.OBJECT = 1
        mock_swsscommon.Select.return_value.select.side_effect = [(1, MagicMock()), StopIteration]
        redis_conn = mock_swsscommon.CastSelectableToRedisSelectObj.return_value.getDbConnector.return_value
        redis_conn.getNamespace.return_value = ""
        redis_conn.getDbId.return_value = CONFIG_DB_ID

        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ip = MagicMock()
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ipv6 = MagicMock()
        manager = self.caclmgrd.ControlPlaneAclManager("caclmgrd")
        manager.log_info = MagicMock()
        manager.update_control_plane_acls = MagicMock()

        with self.assertRaises(StopIteration):
            manager.run()

        self.assertIn(table, subscribed, "caclmgrd does not subscribe to {}".format(table))
        self.assertEqual(pending, [], "{} event was never consumed".format(table))
        self.assertEqual(manager.num_changes[""], 1, "{} {} did not count as an ACL change".format(table, op))
        mock_thread.assert_called_once()
        self.assertEqual(mock_thread.call_args.kwargs["target"], manager.check_and_update_control_plane_acls)
        mock_thread.return_value.start.assert_called_once()
