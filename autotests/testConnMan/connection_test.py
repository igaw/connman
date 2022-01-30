#!/usr/bin/python3

import unittest
import sys
import os
import shutil

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

        #os.environ['DBUS_SYSTEM_BUS_ADDRESS'] = cm.namespace.dbus_address
        #os.execvp('/bin/bash', ['bash'])
        service = cm.get_service_by_name('ssidOpen', max_wait=500)
        print(service)

        print('Reset counters')
        service.reset_counters()
        print('Try to connect')
        service.connect()
        print(service)

    @classmethod
    def setUpClass(cls):
        os.mkdir('/tmp/connman')
        ConnMan.copy_to_storage('settings', storage_dir='/tmp/connman')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree('/tmp/connman')


if __name__ == '__main__':
    unittest.main(exit=True)
