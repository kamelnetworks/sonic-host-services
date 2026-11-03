"""
    caclmgrd must regenerate the control plane ACLs when the BGP tables that
    feed the per-session TCP/179 permits change (kamelnetworks/sonic-buildimage#29).

    The daemon's run() loop is driven with a mocked swsscommon: one mock
    SubscriberStateTable per CONFIG_DB table name (whatever connector or
    namespace it is created for), one Select that fires once for CONFIG_DB and
    then stops the daemon. If the daemon never subscribes to a table, an event
    in that table can never be popped and no regeneration is scheduled.
"""
import copy
import os
import sys
import threading
from swsscommon import swsscommon

from parameterized import parameterized
from sonic_py_common.general import load_module_from_source
from unittest import TestCase
from unittest.mock import MagicMock, patch

from .test_bgp_subscription_vectors import (CACLMGRD_BGP_SUBSCRIPTION_CONFIG_DB,
                                            CACLMGRD_BGP_SUBSCRIPTION_TEST_VECTOR)
from tests.common.mock_configdb import MockConfigDb

STATE_DB_ID = 6
CONFIG_DB_ID = 4
EMPTY_POP = ('', None, None)
BGP_TABLES = ("BGP_NEIGHBOR", "BGP_PEER_RANGE", "BGP_PEER_GROUP")


class StopDaemon(Exception):
    """Raised from Select.select() to leave caclmgrd's endless run() loop."""


class TestCaclmgrdBgpSubscription(TestCase):
    def setUp(self):
        swsscommon.ConfigDBConnector = MockConfigDb
        test_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        modules_path = os.path.dirname(test_path)
        scripts_path = os.path.join(modules_path, "scripts")
        sys.path.insert(0, modules_path)
        caclmgrd_path = os.path.join(scripts_path, "caclmgrd")
        self.caclmgrd = load_module_from_source("caclmgrd", caclmgrd_path)

    def _run_daemon(self, mock_swsscommon, events_by_table):
        """
        Run caclmgrd.run() until Select.select() has delivered one CONFIG_DB
        event and the following select() call stops the daemon. Returns the
        manager and the {table_name: subscriber mock} dict.
        """
        MockConfigDb.set_config_db(copy.deepcopy(CACLMGRD_BGP_SUBSCRIPTION_CONFIG_DB))
        mock_swsscommon.ConfigDBConnector = MockConfigDb
        mock_swsscommon.CFG_ACL_TABLE_TABLE_NAME = "ACL_TABLE"
        mock_swsscommon.CFG_ACL_RULE_TABLE_NAME = "ACL_RULE"
        mock_swsscommon.SonicDBConfig.getDbId.side_effect = lambda db_name: (
            STATE_DB_ID if db_name == "STATE_DB" else CONFIG_DB_ID
        )
        mock_swsscommon.Select.OBJECT = 1

        subscribers = {}
        pending = {table: list(events) for table, events in events_by_table.items()}

        def make_subscriber(connector, table, *args, **kwargs):
            if table not in subscribers:
                sub = MagicMock(name="SubscriberStateTable({})".format(table))
                sub.getTableNameSeparator.return_value = "|"
                queue = pending.get(table, [])
                sub.pop.side_effect = lambda: queue.pop(0) if queue else EMPTY_POP
                subscribers[table] = sub
            return subscribers[table]

        mock_swsscommon.SubscriberStateTable.side_effect = make_subscriber

        # One CONFIG_DB readiness notification for the default namespace, then stop.
        mock_swsscommon.Select.return_value.select.side_effect = [
            (mock_swsscommon.Select.OBJECT, MagicMock()),
            StopDaemon(),
        ]
        redis_select = mock_swsscommon.CastSelectableToRedisSelectObj.return_value
        redis_select.getDbConnector.return_value.getNamespace.return_value = ""
        redis_select.getDbConnector.return_value.getDbId.return_value = CONFIG_DB_ID

        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ip = MagicMock(return_value="10.0.0.1")
        self.caclmgrd.ControlPlaneAclManager.get_namespace_mgmt_ipv6 = MagicMock(return_value="fc00::1")
        manager = self.caclmgrd.ControlPlaneAclManager("caclmgrd")
        manager.log_info = MagicMock()
        manager.log_error = MagicMock()
        manager.UPDATE_DELAY_SECS = 0
        manager.update_control_plane_acls = MagicMock()

        with self.assertRaises(StopDaemon):
            manager.run()

        # The debounce thread (if any) applies the regeneration; wait for it.
        update_thread = manager.update_thread[""]
        if update_thread is not None:
            update_thread.join(timeout=10)
            self.assertFalse(update_thread.is_alive(), "ACL update thread did not finish")
        self.assertIsNone(manager.thread_exceptions[""])
        return manager, subscribers

    @patch("caclmgrd.swsscommon")
    @patch("os.geteuid", return_value=0)
    def test_subscribes_to_bgp_tables(self, mock_geteuid, mock_swsscommon):
        """
        The per-session BGP permits are read from BGP_NEIGHBOR, BGP_PEER_RANGE
        and BGP_PEER_GROUP, so the daemon has to subscribe to those tables.
        """
        manager, subscribers = self._run_daemon(mock_swsscommon, {})
        missing = [table for table in BGP_TABLES if table not in subscribers]
        self.assertEqual(missing, [],
                         "caclmgrd never subscribes to {}; it only watches {}".format(
                             missing, sorted(str(t) for t in subscribers)))

    @parameterized.expand(CACLMGRD_BGP_SUBSCRIPTION_TEST_VECTOR)
    @patch("caclmgrd.swsscommon")
    @patch("os.geteuid", return_value=0)
    def test_table_change_regenerates_acls(self, test_name, test_data, mock_geteuid, mock_swsscommon):
        """
        A single add/change/delete event in the given table must result in a
        control plane ACL regeneration after the initial one at startup.
        """
        manager, subscribers = self._run_daemon(
            mock_swsscommon, {test_data["table"]: [test_data["event"]]})

        startup_calls = 1
        regenerations = manager.update_control_plane_acls.call_count - startup_calls
        if test_data["regenerates"]:
            self.assertGreaterEqual(
                regenerations, 1,
                "{} event {} in {} did not trigger a control plane ACL regeneration "
                "(subscribed tables: {})".format(test_data["event"][1], test_data["event"][0],
                                                  test_data["table"],
                                                  sorted(str(t) for t in subscribers)))
            # The regeneration must go through the per-namespace debounce path,
            # which re-reads CONFIG_DB and resets the change counter.
            self.assertEqual(manager.num_changes[""], 0)
            self.assertIsNone(manager.update_thread[""])
        else:
            self.assertEqual(regenerations, 0)
