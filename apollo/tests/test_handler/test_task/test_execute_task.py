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
from vulcanus.restful.status import DATABASE_CONNECT_ERROR, NO_DATA, PARAM_ERROR, StatusCode, SUCCEED, REPEAT_TASK_EXECUTION
from apollo import BLUE_POINT
from apollo.conf import *
from apollo.conf.constant import VUL_TASk_EXECUTE
from apollo.database.proxy.task import TaskProxy, TaskMysqlProxy
from apollo.handler.task_handler.cache import TaskCache
from apollo.handler.task_handler.manager.cve_fix_manager import CveFixManager
from apollo.handler.task_handler.manager.playbook_manager import RepoPlaybook, Playbook
from apollo.handler.task_handler.manager.repo_manager import RepoManager
from apollo.handler.task_handler.view import VulExecuteTask


class TestExecuteTaskView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulExecuteTask, '_handle')
    @mock.patch.object(MyResponse, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED
        args = {
            "task_id": "a"
        }
        response = self.client.post(
            VUL_TASk_EXECUTE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(SUCCEED)
        self.assertDictEqual(res, expected_res)

        args = {
            "task": "a"
        }
        response = self.client.post(
            VUL_TASk_EXECUTE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)

    @mock.patch.object(VulExecuteTask, '_handle_repo')
    @mock.patch.object(TaskProxy, 'check_task_status')
    @mock.patch.object(TaskProxy, 'get_task_type')
    @mock.patch.object(TaskProxy, 'connect')
    def test_handle(self, mock_connect, mock_get_task_type, mock_check_status, mock_handle_repo):
        # test database connect
        interface = VulExecuteTask()
        mock_connect.return_value = False
        res = interface._handle(1)
        self.assertEqual(res, DATABASE_CONNECT_ERROR)

        # test check task type fail
        args = {
            "task_id": "1",
            "username": "a"
        }
        mock_connect.return_value = True
        mock_get_task_type.return_value = 'a'
        res = interface._handle(args)
        self.assertEqual(res, PARAM_ERROR)

        # test task running repeatedly
        mock_get_task_type.return_value = 'repo'
        mock_check_status.return_value = False
        res = interface._handle(args)
        self.assertEqual(res, REPEAT_TASK_EXECUTION)

        # test succeed
        mock_check_status.return_value = True
        mock_handle_repo.return_value = 4
        res = interface._handle(args)
        self.assertEqual(res, 4)

    @mock.patch.object(RepoManager, 'execute_task')
    @mock.patch.object(RepoManager, 'pre_handle')
    @mock.patch.object(TaskCache, 'query_repo_info')
    @mock.patch.object(RepoPlaybook, 'check_pb_and_inventory')
    @mock.patch.object(RepoPlaybook, 'check_repo')
    @mock.patch.object(TaskProxy, 'get_repo_task_info')
    def test_handle_repo(self, mock_get_repo, mock_check_repo, mock_check_pb, mock_query_repo, mock_pre_handle, mock_execute_task):
        args = {
            "task_id": "a",
            "username": "b"
        }
        proxy = TaskProxy(configuration)
        mock_get_repo.return_value = 1, {"total_count": 0}
        res = VulExecuteTask._handle_repo(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_get_repo.return_value = SUCCEED, {"result": [{"repo_name": "a"}], "total_count": 1}
        mock_check_repo.return_value = False
        res = VulExecuteTask._handle_repo(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_check_repo.return_value = True
        mock_check_pb.return_value = False
        res = VulExecuteTask._handle_repo(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_check_pb.return_value = True
        mock_query_repo.return_value = None
        res = VulExecuteTask._handle_repo(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_query_repo.return_value = [1]
        mock_pre_handle.return_value = True
        res = VulExecuteTask._handle_repo(args, proxy)
        self.assertEqual(res, SUCCEED)

    @mock.patch.object(CveFixManager, 'execute_task')
    @mock.patch.object(CveFixManager, 'pre_handle')
    @mock.patch.object(TaskMysqlProxy, 'get_cve_basic_info')
    @mock.patch.object(TaskCache, 'make_cve_info')
    @mock.patch.object(Playbook, 'check_pb_and_inventory')
    def test_handle_cve(self, mock_check_pb, mock_make_cve_info, mock_get_cve_info, mock_pre_handle, mock_execute_task):
        args = {
            "task_id": "a",
            "username": "b"
        }
        proxy = TaskProxy(configuration)
        mock_get_cve_info.return_value = (NO_DATA, '')
        res = VulExecuteTask._handle_cve(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_get_cve_info.return_value = (SUCCEED, '')
        mock_make_cve_info.return_value = '1'
        mock_check_pb.return_value = False
        res = VulExecuteTask._handle_cve(args, proxy)
        self.assertEqual(res, NO_DATA)

        mock_check_pb.return_value = True
        mock_pre_handle.return_value = True
        res = VulExecuteTask._handle_cve(args, proxy)
        self.assertEqual(res, SUCCEED)
