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
import os
import unittest
from unittest import mock
from flask import Flask

from vulcanus.restful.status import DATABASE_CONNECT_ERROR, PARAM_ERROR, SUCCEED
from apollo import BLUE_POINT
from apollo.conf import *
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.config import PLAYBOOK_DIR
from apollo.handler.task_handler.manager.playbook_manager import CveFixPlaybook, RepoPlaybook
from apollo.handler.task_handler.view import VulGetTaskPlaybook


class TestGetTaskPlaybookView(unittest.TestCase):
    def setUp(self):
        app = Flask("aops-apollo")

        for blue, api in BLUE_POINT:
            api.init_app(app)
            app.register_blueprint(blue)

        app.testing = True
        self.client = app.test_client()
        self.headers = {"access_token": "123456"}

    @mock.patch.object(VulGetTaskPlaybook, '_handle_cve')
    @mock.patch.object(VulGetTaskPlaybook, '_handle_repo')
    @mock.patch.object(TaskProxy, 'get_task_ansible_info')
    @mock.patch.object(TaskProxy, 'get_task_type')
    @mock.patch.object(TaskProxy, 'connect')
    def test_handle(self, mock_connect, mock_get_task_type, mock_get_pb, mock_handle_repo, mock_handle_cve):
        args = {
            "task_id": "1",
            "task_type": "repo",
            "username": "a"
        }
        # test database connect
        interface = VulGetTaskPlaybook()
        mock_connect.return_value = False
        res = interface._handle(args)
        self.assertEqual(res, DATABASE_CONNECT_ERROR)

        # test check task type fail
        mock_connect.return_value = True
        mock_get_task_type.return_value = 'a'
        res = interface._handle(args)
        self.assertEqual(res, PARAM_ERROR)

        # test succeed
        mock_get_task_type.return_value = 'repo'
        if not os.path.exists(PLAYBOOK_DIR):
            os.makedirs(PLAYBOOK_DIR)
        
        file_path = os.path.join(PLAYBOOK_DIR, '1.yml')
        with open(file_path, 'w') as file_io:
            file_io.write("ccc")
        
        res = interface._handle(args)
        self.assertEqual(res, SUCCEED)
        os.remove(file_path)

        mock_get_pb.return_value = SUCCEED, ""
        mock_handle_repo.return_value = 1, 2
        res = interface._handle(args)
        self.assertEqual(res, 1)
    
    @mock.patch.object(RepoPlaybook, 'create_playbook')
    def test_handle_repo(self, mock_create_pb):
        res = VulGetTaskPlaybook._handle_repo('1')
        self.assertEqual(res, SUCCEED)

    
    @mock.patch.object(CveFixPlaybook, 'create_fix_playbook')
    @mock.patch.object(TaskProxy, 'save_task_info')
    @mock.patch.object(TaskProxy, 'get_package_info')
    @mock.patch.object(TaskProxy, 'get_cve_basic_info')
    def test_handle_cve(self, mock_get_basic_info, mock_get_package_info, mock_save_info, mock_create_pb):
        interface = VulGetTaskPlaybook()
        interface.proxy = TaskProxy(configuration)
        mock_get_basic_info.return_value = 1, 2
        res = interface._handle_cve(1)
        self.assertEqual(res, 1)
        
        mock_get_basic_info.return_value = SUCCEED, 2
        mock_get_package_info.return_value = 1, 2
        res = interface._handle_cve(1)
        self.assertEqual(res, 1)
        
        mock_get_package_info.return_value = SUCCEED, 2
        mock_create_pb.return_value = ["a"]
        res = interface._handle_cve(1)
        self.assertEqual(res, SUCCEED)