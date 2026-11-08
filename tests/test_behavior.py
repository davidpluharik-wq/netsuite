import unittest
from netsuite import WifiScannerThread


class BehaviorTests(unittest.TestCase):
    def test_wifi_escaped_fields(self):
        fields = WifiScannerThread.split_terse_line(r'Office\:Guest:AA\:BB\:CC\:DD\:EE\:FF:6:82:WPA2:130 Mbit/s')
        self.assertEqual(fields[:2], ['Office:Guest', 'AA:BB:CC:DD:EE:FF'])
        self.assertEqual(len(fields), 6)
