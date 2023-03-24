#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN 'AS IS' BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# ******************************************************************************/
"""
Time:
Author:
Description:
"""
import unittest
from unittest import mock

from apollo.conf import configuration
from apollo.database.proxy.task import TaskMysqlProxy, TaskProxy
from apollo.handler.task_handler.callback.cve_scan import CveScanCallback
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, DATABASE_INSERT_ERROR, SUCCEED


class TestCveScanCallback(unittest.TestCase):
    def setUp(self):
        self.task_info = {
            "status": "init",
            "host_id": 1,
            "installed_packages": ["string"],
            "os_version": "openEuler 22.03 LTS",
            "cves": ["CVE-2021-11111", "CVE-2022-13111"]
        }

        self.call = CveScanCallback(TaskProxy(configuration))

    @mock.patch.object(TaskMysqlProxy, 'save_cve_scan_result')
    @mock.patch.object(TaskMysqlProxy, 'update_host_scan')
    def test_cve_scan_callback_should_success_when_save_cve_scan_result_succeed_and_update_host_scan_succeed(self,
                                                                                                             mock_update_host_scan,
                                                                                                             mock_save_cve_scan_result):
        self.call.callback("task_id", self.task_info, "admin")
        mock_update_host_scan.assert_called_with("finish", [self.task_info["host_id"]])
        mock_save_cve_scan_result.assert_called_with(self.task_info, "admin")

    @mock.patch.object(TaskMysqlProxy, 'save_cve_scan_result')
    @mock.patch.object(TaskMysqlProxy, 'update_host_scan')
    def test_cve_scan_callback_should_failed_when_save_cve_scan_result_failed(self,
                                                                              mock_update_host_scan,
                                                                              mock_save_cve_scan_result):
        mock_update_host_scan.return_value = SUCCEED
        mock_save_cve_scan_result.return_value = DATABASE_INSERT_ERROR
        status_code = self.call.callback("task_id", self.task_info, "admin")
        self.assertEqual(DATABASE_UPDATE_ERROR, status_code)

    @mock.patch.object(TaskMysqlProxy, 'update_host_scan')
    def test_cve_scan_callback_should_failed_when_status_no_succeed(self,
                                                                    mock_update_host_scan):
        mock_update_host_scan.return_value = SUCCEED
        self.task_info["status"] = "fail"
        status_code = self.call.callback("task_id", self.task_info, "admin")
        self.assertEqual(DATABASE_UPDATE_ERROR, status_code)

    @mock.patch.object(TaskMysqlProxy, 'update_host_scan')
    def test_cve_scan_callback_should_failed_when_update_host_scan_result_failed(self,
                                                                                 mock_update_host_scan_result):
        mock_update_host_scan_result.return_value = DATABASE_UPDATE_ERROR
        status_code = self.call.callback("task_id", self.task_info, "admin")
        self.assertEqual(DATABASE_UPDATE_ERROR, status_code)
