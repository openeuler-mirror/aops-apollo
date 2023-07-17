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
from vulcanus.restful.resp import make_response
from vulcanus.restful.resp.state import SUCCEED, PARAM_ERROR

from apollo import BLUE_POINT
from apollo.conf.constant import VUL_TASK_DELETE
from apollo.handler.task_handler.view import VulDeleteTask


class TestDeleteTaskView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulDeleteTask, '_handle')
    @mock.patch.object(VulDeleteTask, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED
        args = {"task_list": ["a", "b"]}
        response = self.client.delete(VUL_TASK_DELETE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(SUCCEED)
        self.assertEqual(res, expected_res)

        args = {"task_list": "b"}
        response = self.client.delete(VUL_TASK_DELETE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(PARAM_ERROR)
        self.assertEqual(res, expected_res)
