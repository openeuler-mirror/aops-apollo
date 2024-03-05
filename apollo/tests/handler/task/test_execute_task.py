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
from unittest import mock

from flask import request
from vulcanus.exceptions import DatabaseConnectionFailed
from vulcanus.restful.resp.state import (
    DATABASE_CONNECT_ERROR,
    PARAM_ERROR,
    SUCCEED,
    REPEAT_TASK_EXECUTION,
)
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.resp import make_response

from apollo.conf.constant import VUL_TASK_EXECUTE
from apollo.database.proxy.task.base import TaskProxy
from apollo.handler.task_handler.view import VulExecuteTask
from apollo.tests import BaseTestCase


class TestExecuteTaskView(BaseTestCase):
    client = BaseTestCase.create_app()

    def setUp(self):
        super().setUp()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulExecuteTask, '_handle')
    @mock.patch.object(BaseResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED
        args = {"task_id": "a"}
        response = self.client.post(VUL_TASK_EXECUTE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(SUCCEED)
        self.assertDictEqual(res, expected_res)

        args = {"task": "a"}
        response = self.client.post(VUL_TASK_EXECUTE, json=args, headers=self.headers)
        res = response.json
        expected_res = make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)

    @mock.patch.object(VulExecuteTask, '_handle_repo')
    @mock.patch.object(TaskProxy, 'check_task_status')
    @mock.patch.object(TaskProxy, 'get_task_type')
    @mock.patch.object(TaskProxy, '_create_session')
    @mock.patch.object(BaseResponse, 'verify_request')
    def test_handle(self, mcok_verify_request, mock_connect, mock_get_task_type, mock_check_status, mock_handle_repo):
        # test database connect
        interface = VulExecuteTask()
        mcok_verify_request.return_value = {"task_id": 1, "username": "mock_user"}, SUCCEED
        mock_connect.side_effect = DatabaseConnectionFailed
        response = self.client.post(VUL_TASK_EXECUTE, json={"task_id": "1"}, headers=self.headers).json
        self.assertEqual(response.get("label"), DATABASE_CONNECT_ERROR)

        # test check task type fail
        mcok_verify_request.return_value = {"task_id": 1, "username": "mock_user"}, SUCCEED
        mock_connect.side_effect = None
        mock_get_task_type.return_value = 'a'
        response = self.client.post(VUL_TASK_EXECUTE, json={"task_id": "1"}, headers=self.headers).json
        self.assertEqual(response.get("label"), PARAM_ERROR)

        # test task running repeatedly
        mock_connect.return_value = None
        mock_get_task_type.return_value = 'repo set'
        mock_check_status.return_value = False
        args = {"task_id": "1"}
        response = self.client.post(VUL_TASK_EXECUTE, json=args, headers=self.headers).json
        self.assertEqual(response.get("label"), REPEAT_TASK_EXECUTION, response)

        # # test succeed
        mock_check_status.return_value = True
        mock_handle_repo.return_value = SUCCEED
        response = self.client.post(VUL_TASK_EXECUTE, json=args, headers=self.headers).json
        self.assertEqual(response.get("label"), SUCCEED, response)
