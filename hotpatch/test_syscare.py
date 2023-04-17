import unittest
from unittest import mock

from .syscare import Syscare
from .syscare import SUCCEED, FAIL


class SyscareTestCase(unittest.TestCase):
    @mock.patch("hotpatch.syscare.cmd_output")
    def test_list_should_return_empty_when_cmd_output_nothing(self, mock_cmd):
        mock_cmd.return_value = "", FAIL
        result = Syscare().list()
        self.assertEqual(result, [])

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_list_should_return_empty_when_cmd_output_only_header(self, mock_cmd):
        mock_cmd.return_value = "Target  Name  Status\n", SUCCEED
        result = Syscare().list()
        self.assertEqual(result, [])

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_list_should_return_correct_result_when_cmd_output_correct(self, mock_cmd):
        mock_cmd.return_value = "Target  Name  Status\nredis-6.2.5-1.oe2203   CVE-2021-23675  ACTIVED\n", SUCCEED
        result = Syscare().list()
        expected_res = [{'Target': 'redis-6.2.5-1.oe2203',
                         'Name': 'CVE-2021-23675', 'Status': 'ACTIVED'}]
        self.assertEqual(result, expected_res)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_list_should_return_filtered_result_when_input_with_condition(self, mock_cmd):
        mock_cmd.return_value = "Target  Name  Status\nredis-6.2.5-1.oe2203   CVE-2021-23675  ACTIVED\n"\
                                "kernel-5.10.0-60.80.0.104.oe2203    modify-proc-version     DEACTIVED\n", SUCCEED
        result = Syscare().list(condition={"Status": "ACTIVED"})
        expected_res = [
            {'Target': 'redis-6.2.5-1.oe2203', 'Name': 'CVE-2021-23675', 'Status': 'ACTIVED'}]
        self.assertEqual(result, expected_res)


if __name__ == '__main__':
    unittest.main()
