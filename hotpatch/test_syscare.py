#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
import unittest
from unittest import mock

from .syscare import Syscare, cmd_output
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
        mock_cmd.return_value = "Target  Name  Status\nredis-6.2.5-1.oe2203   CVE-2021-23675  ACTIVED\n" \
                                "kernel-5.10.0-60.80.0.104.oe2203    modify-proc-version     DEACTIVED\n", SUCCEED
        result = Syscare().list(condition={"Status": "ACTIVED"})
        expected_res = [
            {'Target': 'redis-6.2.5-1.oe2203', 'Name': 'CVE-2021-23675', 'Status': 'ACTIVED'}]
        self.assertEqual(result, expected_res)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_status_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "ACTIVED", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().status(patch_name)
        expected_res = "ACTIVED"
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_apply_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().apply(patch_name)
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_active_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().active(patch_name)
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_deactive_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().deactive(patch_name)
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_accept_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().accept(patch_name)
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_remove_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        patch_name = mock.MagicMock()
        result, status_code = Syscare().remove(patch_name)
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_save_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().save()
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch("hotpatch.syscare.cmd_output")
    def test_restore_should_return_correct(self, mock_cmd):
        mock_cmd.return_value = "", SUCCEED
        result, status_code = Syscare().restore()
        expected_res = ""
        expected_code = SUCCEED
        self.assertEqual(result, expected_res)
        self.assertEqual(status_code, expected_code)

    @mock.patch('subprocess.Popen')
    def test_cmd_output_should_return_correct_when_popen_return_success(self, mock_popen):
        expected_output = "Hello"
        expected_returncode = SUCCEED
        mock_process = mock_popen.return_value
        mock_process.stdout.read.return_value = expected_output.encode('utf-8')
        mock_process.returncode = expected_returncode
        output, returncode = cmd_output(['echo', 'hello'])
        self.assertEqual(output, expected_output)
        self.assertEqual(returncode, expected_returncode)

    @mock.patch('subprocess.Popen')
    def test_cmd_output_should_raise_exception_when_popen_excute_fail(self, mock_popen):
        expected_output = "-bash: hello：command not found"
        expected_returncode = FAIL
        mock_popen.side_effect = Exception('-bash: hello：command not found')
        cmd = mock.MagicMock()
        output, returncode = cmd_output(cmd)
        self.assertEqual(output, expected_output)
        self.assertEqual(returncode, expected_returncode)


if __name__ == '__main__':
    unittest.main()
