#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import testutil
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

from hostapd import HostapdCLI

class Test(unittest.TestCase):

    def test_connection_success(self):
        hostapd = HostapdCLI(config='ssidEAP-TTLS-CHAP.conf')

        self.assertIsNotNone(hostapd)

        wd = IWD()

        psk_agent = PSKAgent('abc', ('user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidEAP-TTLS-CHAP')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        hostapd.eapol_reauth(device.address)

        hostapd.wait_for_event('CTRL-EVENT-EAP-STARTED')
        hostapd.wait_for_event('CTRL-EVENT-EAP-SUCCESS')

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('ssidEAP-TTLS-CHAP.8021x')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
