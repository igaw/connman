#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
import validation
from validation import TestConnectAutoConnect
from iwd import IWD

class TestWpaNetwork(unittest.TestCase):
    '''
    The bellow test cases excesise the following connection scenarios:

    Network config is
    present at start time:  Connect:  AutoConnect:  Result:
    --------------------------------------------------------------------------
    False                   True                    Connection succeeds
    True                              True          Connection succeeds
    '''

    def test_wpa(self):
        tca = TestConnectAutoConnect()
        tca.validate('ssidHiddenWPA', False, None, True)
        tca.validate('ssidHiddenWPA', True, None, True)

        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
