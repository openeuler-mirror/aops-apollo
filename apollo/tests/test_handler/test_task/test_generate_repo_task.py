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

from vulcanus.restful.status import DATABASE_CONNECT_ERROR, PARAM_ERROR, StatusCode, SUCCEED
from apollo import BLUE_POINT
from apollo.conf import *
from apollo.conf.constant import VUL_TASK_REPO_GENERATE
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.manager.playbook_manager import RepoPlaybook
from apollo.handler.task_handler.view import VulGenerateRepoTask


class TestGenerateRepoTaskView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulGenerateRepoTask, '_handle')
    @mock.patch.object(VulGenerateRepoTask, 'verify_token')
    def test_schema(self, mock_verify_token, mock_handle):
        mock_verify_token.return_value = SUCCEED
        mock_handle.return_value = SUCCEED, {"task_id": "4"}
        args = {
            "task_name": "a",
            "description": "1",
            "repo_name": "r",
            "info": [
                {
                    "host_id": "id1",
                    "host_name": "name1",
                    "host_ip": "1.1.1.1"
                }
            ]
        }
        response = self.client.post(
            VUL_TASK_REPO_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(SUCCEED)
        expected_res['task_id'] = "4"
        self.assertDictEqual(res, expected_res)

        args = {
            "task_name": "a",
            "description": "1",
            "repo_name": "r",
            "info": [
                {
                    "host_id": 1,
                    "host_name": "name1",
                    "host_ip": "1.1.1.1"
                }
            ]
        }
        response = self.client.post(
            VUL_TASK_REPO_GENERATE, json=args, headers=self.headers)
        res = response.json
        expected_res = StatusCode.make_response(PARAM_ERROR)
        self.assertDictEqual(res, expected_res)

    @mock.patch.object(RepoPlaybook, 'create_playbook')
    @mock.patch.object(RepoPlaybook, 'create_inventory')
    @mock.patch.object(RepoPlaybook, 'check_repo')
    @mock.patch.object(TaskProxy, 'save_task_info')
    @mock.patch.object(TaskProxy, 'generate_repo_task')
    @mock.patch.object(TaskProxy, 'connect')
    def test_handle(self, mock_connect, mock_gen_repo_task, mock_save_task, mock_check_repo, mock_create_inv, mock_create_pb):
        # test database connect
        interface = VulGenerateRepoTask()
        mock_connect.return_value = False
        res = interface._handle(1)
        self.assertEqual(res[0], DATABASE_CONNECT_ERROR)

        # test check repo fail
        args = {
            "repo_name": "r",
            "username": "admin",
            "info": []
        }
        mock_connect.return_value = True
        mock_check_repo.return_value = 2
        res = interface._handle(args)
        self.assertEqual(res[0], 2)

        # test generate repo task fail
        mock_check_repo.return_value = SUCCEED
        mock_gen_repo_task.return_value = 2
        res = interface._handle(args)
        self.assertEqual(res[0], 2)

        # test succeed
        mock_gen_repo_task.return_value = SUCCEED
        mock_create_inv.return_value = {"a": 1}
        mock_create_pb.return_value = {"a": 1}
        res = interface._handle(args)
        self.assertEqual(res[0], SUCCEED)
