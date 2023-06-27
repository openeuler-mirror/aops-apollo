import unittest
from unittest import mock

from hotpatch.syscare import Syscare, cmd_output
from hotpatch.syscare import SUCCEED, FAIL


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
        mock_cmd.return_value = "Target  Name  Status\nredis-6.2.5-1.oe2203   CVE-2021-23675  ACTIVED\n" \
                                "kernel-5.10.0-60.80.0.104.oe2203    modify-proc-version     DEACTIVED\n", SUCCEED
        result = Syscare().list(condition={"Status": "ACTIVED"})
        expected_res = [
            {'Target': 'redis-6.2.5-1.oe2203', 'Name': 'CVE-2021-23675', 'Status': 'ACTIVED'}]
        self.assertEqual(result, expected_res)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_status_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "ACTIVED", SUCCEED
        result, status_code = Syscare().status("redis-6.2.5-1/HP2")
        expected_res = "ACTIVED"
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_apply_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().apply("redis-6.2.5-1/HP2")
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_active_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().active("redis-6.2.5-1/HP2")
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_deactive_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().deactive("redis-6.2.5-1/HP2")
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_accept_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().accept("redis-6.2.5-1/HP2")
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_remove_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().remove("redis-6.2.5-1/HP2")
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_save_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().save()
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_restore_return_correct_result(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().restore()
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch('subprocess.Popen')
    def test_cmd_output_success(self, mock_popen):
        expected_output = "Hello"
        expected_returncode = SUCCEED
        mock_process = mock_popen.return_value
        mock_process.stdout.read.return_value = expected_output.encode('utf-8')
        mock_process.returncode = expected_returncode
        output, returncode = cmd_output(['echo', 'hello'])
        self.assertEqual(output, expected_output)
        self.assertEqual(returncode, expected_returncode)

    @mock.patch('subprocess.Popen')
    def test_cmd_output_fail(self, mock_popen):
        expected_output = "-bash: hello：command not found"
        expected_returncode = FAIL

        mock_process = mock_popen.return_value
        mock_process.stdout.read.return_value = expected_output.encode('utf-8')
        mock_process.stderr.read.return_value = expected_output.encode('utf-8')
        mock_process.returncode = expected_returncode
        output, returncode = cmd_output(['hello'])
        self.assertEqual(output, expected_output)
        self.assertEqual(returncode, expected_returncode)
        self.assertRaises(Exception)


if __name__ == '__main__':
    unittest.main()
