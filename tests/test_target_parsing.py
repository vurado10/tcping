import unittest

import tcping


class TestTargetParsing(unittest.TestCase):
    def test_ip_parsing(self):
        result = tcping.parse_ip_range("1-2, 3.10.11-12.0")

        expecting = [
            "1.10.11.0",
            "1.10.12.0",
            "2.10.11.0",
            "2.10.12.0",
            "3.10.11.0",
            "3.10.12.0"
        ]

        self.assertCountEqual(expecting, result)


if __name__ == '__main__':
    unittest.main()
