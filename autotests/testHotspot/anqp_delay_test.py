#!/usr/bin/python3

import unittest
import sys
import os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
from hwsim import Hwsim
import testutil
from time import sleep

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        bss_radio = hwsim.get_radio('rad0')
        rule0 = hwsim.rules.create()
        rule0.source = bss_radio.addresses[0]
        rule0.bidirectional = True

        wd = IWD(True)

        hapd = HostapdCLI(config='ssidHotspot.conf')

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        # We are dependent on a periodic scan here. We want to wait for this
        # because this is the first opportunity IWD has to do ANQP. Once ANQP
        # has been done once the network is set up and we cannot simulate the
        # 'Connect() before ANQP' race condition anymore.
        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        # Force the case where ANQP does not finish before Connect() comes in
        rule0.delay = 100

        ordered_network.network_object.connect()

        rule0.delay = 1

        condition = 'obj.state == DeviceState.connected'
        wd.wait_for_object_condition(device, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname)

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        IWD.copy_to_hotspot('example.conf')
        conf = '[General]\nDisableANQP=0\n'
        os.system('echo "%s" > /tmp/main.conf' % conf)

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()
        os.remove('/tmp/main.conf')

if __name__ == '__main__':
    unittest.main(exit=True)
