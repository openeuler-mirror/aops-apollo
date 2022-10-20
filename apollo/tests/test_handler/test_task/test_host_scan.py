#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
from flask import Flask

from vulcanus.restful.response import MyResponse
from vulcanus.restful.status import DATABASE_CONNECT_ERROR, PARAM_ERROR, StatusCode, SUCCEED
from apollo import BLUE_POINT
from apollo.conf import *
from apollo.conf.constant import VUL_HOST_SCAN
from apollo.database.proxy.task import TaskMysqlProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager
from apollo.handler.task_handler.view import VulScanHost


class TestHostScanView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulScanHost, '_handle')
    @mock.patch.object(MyResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED
        args = {
            "host_list": [],
            "filter": {
                "host_name": "b",
                "host_group": [],
            }
        }
        response = self.client.post(
            VUL_HOST_SCAN, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(SUCCEED)
        self.assertDictEqual(res, expected_res)

        args = {
            "host_list": "a",
            "filter": {
                "host_name": 111,
                "host_group": [],
                "bb": 1
            }
        }
        response = self.client.post(
            VUL_HOST_SCAN, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)

    @mock.patch.object(ScanManager, 'execute_task')
    @mock.patch.object(ScanManager, 'pre_handle')
    @mock.patch.object(ScanManager, 'generate_playbook_and_inventory')
    @mock.patch.object(TaskMysqlProxy, 'get_scan_host_info')
    @mock.patch.object(TaskMysqlProxy, 'connect')
    def test_handle(self, mock_connect, mock_scan_info, mock_gen, mock_pre_handle, mock_execute):
        # test database connect
        interface = VulScanHost()
        mock_connect.return_value = False
        res = interface._handle(1)
        self.assertEqual(res, DATABASE_CONNECT_ERROR)

        # test param verify
        mock_connect.return_value = True
        mock_scan_info.return_value = [
            {
                "host_id": "id1",
                "status": "done"
            },
            {
                "host_id": "id2",
                "status": "done"
            }
        ]
        args = {
            "username": "a",
            "host_list": ["id1", "id3"]
        }
        res = interface._handle(args)
        self.assertEqual(res, PARAM_ERROR)

        # test succeed
        args['host_list'] = ["id1", "id2"]
        mock_pre_handle.return_value = True
        res = interface._handle(args)
        self.assertEqual(res, SUCCEED)

    def test_param_verify(self):
        interface = VulScanHost()
        host_list = []
        actual_host_list = []
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, False)

        actual_host_list = [
            {
                "host_id": "1",
                "status": "aa"
            }
        ]
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, True)

        host_list = ["1", "2"]
        actual_host_list = [
            {
                "host_id": "2",
                "status": "b"
            }
        ]
        res = interface._verify_param(host_list, actual_host_list)
        self.assertEqual(res, False)
