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
import json
import unittest
from unittest import mock

from vulcanus.restful.resp.state import SERVER_ERROR, SUCCEED
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.manager.repo_manager import RepoManager


class TestRepoManager(unittest.TestCase):
    def setUp(self):
        proxy = TaskProxy(configuration)
        self.manager = RepoManager(proxy, 'task+_id')

    def test_pre_handle_should_success_when_update_repo_status_is_running(self):
        with mock.patch.object(TaskProxy, 'set_repo_status') as mock_init_status:
            mock_init_status.return_value = 1
            res = self.manager.pre_handle()
            self.assertEqual(res, False)

        with mock.patch.object(TaskProxy, 'set_repo_status') as mock_init_status:
            mock_init_status.return_value = SUCCEED
            with mock.patch.object(TaskProxy, 'update_task_execute_time') as mock_update:
                mock_update.return_value = SUCCEED
                res = self.manager.pre_handle()
                self.assertEqual(res, True)

    def test_handle_call_agent_api_should_success_when_call_agent_is_right(self):
        with mock.patch.object(BaseResponse, 'get_response') as mock_agent:
            mock_agent.return_value = dict(result=list())
            self.manager.handle()
            header = {"access_token": None, "Content-Type": "application/json; charset=UTF-8"}
            manager_url = "http://127.0.0.1:11111/manage/vulnerability/repo/set"
            mock_agent.assert_called_with("POST", manager_url, None, header)

    def test_handle_call_agent_api_should_failed_when_call_agent_return_code_is_fail(self):
        with mock.patch.object(BaseResponse, 'get_response') as mock_agent:
            mock_agent.return_value = dict(result=list(), code=SERVER_ERROR)
            self.manager.handle()
            result = getattr(self.manager, "result", None)
            self.assertEqual(result, None)

    def test_handle_call_agent_api_should_success_when_call_agent_return_code_is_success(self):
        with mock.patch.object(BaseResponse, 'get_response') as mock_agent:
            mock_agent.return_value = dict(result=["host id1", "host id2"], code=SUCCEED)
            self.manager.handle()
            self.assertNotEqual(getattr(self.manager, "result", None), None)

    @mock.patch.object(TaskProxy, 'fix_task_status')
    @mock.patch.object(TaskProxy, 'save_task_info')
    def test_post_handle_should_success_when_callbacked_save_task_info(self, mock_save_result, mock_fix_status):
        self.manager.task = dict(task_type="repo set")
        self.manager.result = {
            "task_id": "a",
            "task_name": "repo",
            "task_result": [
                {"host_id": 1, "host_name": "name1", "host_ip": "ip1", "repo": "a", "status": "succeed", "log": "1"},
            ],
        }
        result = {
            "task_id": self.manager.task_id,
            "task_type": "repo set",
            "latest_execute_time": self.manager.cur_time,
            "task_result": self.manager.result,
        }
        self.manager.post_handle()
        mock_save_result.assert_called_with('task+_id', log=json.dumps(result))
