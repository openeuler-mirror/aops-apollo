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

from vulcanus.restful.resp.state import PARAM_ERROR, StatusCode, SUCCEED
from apollo import BLUE_POINT
from apollo.conf import *
from apollo.conf.constant import VUL_TASK_CVE_GENERATE
from apollo.handler.task_handler.view import VulGenerateCveTask


class TestGenerateCveTaskView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulGenerateCveTask, '_handle')
    @mock.patch.object(VulGenerateCveTask, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED, {"task_id": 2}
        args = {
            "task_name": "a",
            "description": "1",
            "info": [
                {
                    "cve_id": "id1",
                    "host_info": [
                        {
                            "host_id": 1,
                            "host_name": "name1",
                            "host_ip": "1.1.1.1"
                        }
                    ],
                    "reboot": False
                }
            ]
        }
        response = self.client.post(
            VUL_TASK_CVE_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(SUCCEED)
        expected_res['task_id'] = 2
        self.assertDictEqual(res, expected_res)

        args = {
            "task_name": "a",
            "description": "1",
            "info": [
                {
                    "cve_id": "id1",
                    "host_info": [
                        {
                            "host_id": 1,
                            "host_name": "name1"
                        }
                    ]
                }
            ]
        }
        response = self.client.post(
            VUL_TASK_CVE_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)
