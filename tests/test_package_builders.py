import unittest
import package_builders


class MyTestCase(unittest.TestCase):
    def test_checksum(self):
        package = b'E\x00\x00(\x00\x01\x00\x00@\x06\x00\x00\x01' \
                  b'\x02\x03\x04\x7f\x00\x00\x01\x00\x14\x00P\x00' \
                  b'\x00\x00\x00\x00\x00\x00\x00P\x12 \x00\x00\x00\x00\x00'
        ip_header = package[:20]
        tcp_header = package[20:]


        self.assertEqual(63432,
                         package_builders.calculate_checksum(ip_header))
        self.assertEqual(3176,
                         package_builders
                         .calculate_tcp_checksum(ip_header, tcp_header))


if __name__ == '__main__':
    unittest.main()
