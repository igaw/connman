#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD

class Test(unittest.TestCase):

    def connect_to_new_network(self, wd):
        devices = wd.list_devices(1)
        self.assertIsNotNone(devices)
        device = devices[0]

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('ssidNew')

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def list_removal_and_addition(self, wd):

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 4)

        for network in known_networks:
            if network.name == 'ssidTKIP':
                network.forget()

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 3)

        self.connect_to_new_network(wd)

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 4)

        IWD.copy_to_storage('known_networks/ssidPSK.psk')
        condition = 'len(obj.list_known_networks()) == 5'
        wd.wait_for_object_condition(wd, condition)

        expected = ['ssidNew', 'ssidOpen', 'ssidPSK', 'ssidEAP-TLS',
                    'Hotspot Network']
        self.assertEqual({n.name for n in wd.list_known_networks()},
                         set(expected))

        IWD.remove_from_storage('ssidPSK.psk')
        condition = 'len(obj.list_known_networks()) == 4'
        wd.wait_for_object_condition(wd, condition)

        for net in known_networks:
            net.forget()

        known_networks = wd.list_known_networks()
        self.assertEqual(len(known_networks), 0)

    def test_known_networks(self):
        wd = IWD(True)

        self.list_removal_and_addition(wd)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_storage('known_networks/ssidOpen.open')
        IWD.copy_to_storage('known_networks/ssidTKIP.psk')
        IWD.copy_to_storage('known_networks/ssidEAP-TLS.8021x')
        IWD.copy_to_hotspot('known_networks/hotspot.conf')

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
