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
import json
from unittest import mock

from vulcanus.exceptions import DatabaseConnectionFailed
from vulcanus.restful.resp import state
from vulcanus.restful.response import BaseResponse

from apollo.conf.constant import VUL_TASK_CVE_SCAN_CALLBACK
from apollo.database.proxy.task.base import TaskMysqlProxy
from apollo.tests import BaseTestCase

header = {"Content-Type": "application/json; charset=UTF-8"}
header_with_token = {"Content-Type": "application/json; charset=UTF-8", "access_token": "81fe"}
header_with_upload_file_token = {"Content-Type": "multipart/form-data;", "access_token": "81fe"}


class TestCveScanCallback(BaseTestCase):
    client = BaseTestCase.create_app()

    def setUp(self):
        super().setUp()
        self.task_info = {
            "task_id": "mock-host-id",
            "status": "succeed",
            "host_id": 2,
            "os_version": "mock-version",
            "installed_packages": [{"name": "mock-app", "version": "mock-version"}],
            "unfixed_cves": [
                {"cve_id": "CVE-2023-0001", "support_hp": True},
                {"cve_id": "CVE-2023-0002", "support_hp": False},
            ],
            "fixed_cves": [
                {"cve_id": "CVE-2023-0003", "fixed_by_hp": True, "hp_status": "ACCEPTED"},
                {"cve_id": "CVE-2023-0004", "fixed_by_hp": False},
            ],
        }

    @mock.patch.object(TaskMysqlProxy, "__exit__")
    @mock.patch.object(TaskMysqlProxy, "update_host_scan_status")
    @mock.patch.object(TaskMysqlProxy, "save_cve_scan_result")
    @mock.patch.object(TaskMysqlProxy, "_create_session")
    @mock.patch.object(BaseResponse, "verify_request")
    def test_cve_scan_callback_should_return_succeed_when_all_is_right(
        self, mock_verify_request, mock_connect, mock_save, mock_update_host_scan, mock_close
    ):
        self.task_info["username"] = "mock-user"
        mock_verify_request.return_value = self.task_info, state.SUCCEED
        mock_connect.return_value = None
        mock_save.return_value = state.SUCCEED
        mock_update_host_scan.return_value = state.SUCCEED
        mock_close.return_value = None
        response = self.client.post(
            VUL_TASK_CVE_SCAN_CALLBACK, data=json.dumps(self.task_info), headers=header_with_token
        )
        self.assertEqual(state.SUCCEED, response.json.get("label"), response.json)

    @mock.patch.object(TaskMysqlProxy, "__exit__")
    @mock.patch.object(TaskMysqlProxy, "update_host_scan_status")
    @mock.patch.object(TaskMysqlProxy, "save_cve_scan_result")
    @mock.patch.object(TaskMysqlProxy, "_create_session")
    @mock.patch.object(BaseResponse, "verify_request")
    def test_cve_scan_callback_should_return_update_error_when_save_scan_result_failed(
        self, mock_verify_request, mock_connect, mock_save, mock_update_host_scan, mock_close
    ):
        self.task_info["username"] = "mock-user"
        mock_verify_request.return_value = self.task_info, state.SUCCEED
        mock_connect.return_value = None
        mock_save.return_value = state.DATABASE_INSERT_ERROR
        mock_update_host_scan.return_value = state.SUCCEED
        mock_close.return_value = None
        response = self.client.post(
            VUL_TASK_CVE_SCAN_CALLBACK, data=json.dumps(self.task_info), headers=header_with_token
        )
        self.assertEqual(state.DATABASE_UPDATE_ERROR, response.json.get("label"), response.json)

    def test_cve_scan_callback_should_return_400_when_request_without_args(self):
        response = self.client.post(VUL_TASK_CVE_SCAN_CALLBACK, headers=header_with_token)
        self.assertEqual(400, response.status_code)

    def test_cve_scan_callback_should_return_405_when_request_with_incorrect_method(self):
        response = self.client.put(VUL_TASK_CVE_SCAN_CALLBACK, headers=header_with_token)
        self.assertEqual(405, response.status_code)

    def test_cve_scan_callback_should_return_param_error_when_request_with_incorrect_args(self):
        response = self.client.post(VUL_TASK_CVE_SCAN_CALLBACK, data=json.dumps({}), headers=header_with_token)
        self.assertEqual(state.PARAM_ERROR, response.json.get("label"), response.json)

    @mock.patch.object(BaseResponse, "verify_token")
    def test_cve_scan_callback_should_return_token_error_when_request_with_no_token_incorrect_token(self, mock_token):
        mock_token.return_value = state.TOKEN_ERROR
        response = self.client.post(
            VUL_TASK_CVE_SCAN_CALLBACK, data=json.dumps(self.task_info), headers=header_with_token
        )
        self.assertEqual(state.TOKEN_ERROR, response.json.get("label"), response.json)

    @mock.patch.object(TaskMysqlProxy, "_create_session")
    @mock.patch.object(BaseResponse, "verify_token")
    def test_cve_scan_callback_should_return_database_connect_error_when_connect_database_failed(
        self, mock_token, mock_connect
    ):
        mock_connect.side_effect = DatabaseConnectionFailed
        mock_token.return_value = state.SUCCEED
        response = self.client.post(
            VUL_TASK_CVE_SCAN_CALLBACK, data=json.dumps(self.task_info), headers=header_with_token
        )
        self.assertEqual(state.DATABASE_CONNECT_ERROR, response.json.get("label"), response.json)
