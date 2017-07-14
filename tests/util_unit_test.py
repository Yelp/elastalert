from unittest import TestCase

from elastalert.util import parse_host


class UtilsTest(TestCase):
    def test_parse_host(self):
        self.assertEqual(parse_host("localhost", port="9200"), ["localhost:9200"])
        self.assertEqual(parse_host('host1:9200,host2:9200, host3:9300'), ["host1:9200",
                                                                           "host2:9200",
                                                                           "host3:9300"])
