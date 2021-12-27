import unittest

import package_parsers


class MyTestCase(unittest.TestCase):
    def test_parsing(self):
        package = b'E\x00\x00(\x00\x01\x00\x00@\x06\xf7\xc8\x01\x02' \
                  b'\x03\x04\x7f\x00\x00\x01\x00\x14\x00P\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00P\x12 \x00\x0ch\x00\x00'

        self.assertEqual("1.2.3.4", package_parsers.get_ipv4_source(package))
        self.assertEqual(True, package_parsers.is_tcp_syn_ack(package))
        self.assertEqual(20, package_parsers.get_tcp_source_port(package))
        self.assertEqual(6, package_parsers.get_ipv4_protocol_type(package))
        self.assertEqual(0, package_parsers.get_tcp_ack(package))

    def test_non_tcp_syn_ack(self):
        package = b'E\x00\x00(\x00\x01\x00\x00@\x06\xf7\xc8\x01\x02' \
                  b'\x03\x04\x7f\x00\x00\x01\x00\x14\x00P\x00\x00\x00' \
                  b'\x00\x00\x00\x00\x00P\x02 \x00\x0ch\x00\x00'

        self.assertEqual(False, package_parsers.is_tcp_syn_ack(package))


if __name__ == '__main__':
    unittest.main()
