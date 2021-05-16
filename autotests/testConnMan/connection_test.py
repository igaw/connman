#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from connman import ConnMan
import testutil
import pprint

class Test(unittest.TestCase):

    def test_connection_success(self):
        cm = ConnMan(start_connman_daemon =  True)
        man = cm.get_manager()
        print(man)

        # for service in man.get_services():
        #     print(service)
        #     pprint.pprint(dict((x, getattr(service, x)) for x in service.__class__.__dict__ if isinstance(service.__class__.__dict__[x], property)))


        service = cm.get_service_by_name('ssidOpen')
        print(service)

        # wd = IWD()

        # devices = wd.list_devices(1)
        # device = devices[0]

        # condition = 'not obj.scanning'
        # wd.wait_for_object_condition(device, condition)

        # device.scan()

        # condition = 'not obj.scanning'
        # wd.wait_for_object_condition(device, condition)

        # ordered_network = device.get_ordered_network('ssidOpen')

        # self.assertEqual(ordered_network.type, NetworkType.open)

        # condition = 'not obj.connected'
        # wd.wait_for_object_condition(ordered_network.network_object, condition)

        # ordered_network.network_object.connect()

        # condition = 'obj.state == DeviceState.connected'
        # wd.wait_for_object_condition(device, condition)

        # testutil.test_iface_operstate()
        # testutil.test_ifaces_connected()

        # device.disconnect()

        # condition = 'not obj.connected'
        # wd.wait_for_object_condition(ordered_network.network_object, condition)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
