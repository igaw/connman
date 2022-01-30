#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim

class Test(unittest.TestCase):

    def validate_connection(self, wd):
        hwsim = Hwsim()
        bss_radio = hwsim.get_radio('rad0')

        psk_agent = PSKAgent(["secret123", "secret123"])
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(4)

        # These devices aren't used in this test, this makes logs a bit nicer
        # since these devices would presumably start autoconnecting.
        devices[1].disconnect()
        devices[2].disconnect()
        devices[3].disconnect()

        self.assertIsNotNone(devices)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        network = device.get_ordered_network('ssidSAE')

        self.assertEqual(network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        rule0 = hwsim.rules.create()
        rule0.source = bss_radio.addresses[0]
        rule0.bidirectional = True
        rule0.drop = True
        rule0.prefix = 'b0'

        wd.wait(1)
        print(rule0)

        with self.assertRaises(iwd.FailedEx):
            network.network_object.connect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(network.network_object, condition)

        rule0.prefix = '00'
        with self.assertRaises(iwd.FailedEx):
            network.network_object.connect()

        wd.unregister_psk_agent(psk_agent)

    def test_connection_success(self):
        wd = IWD(True)

        self.validate_connection(wd)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
