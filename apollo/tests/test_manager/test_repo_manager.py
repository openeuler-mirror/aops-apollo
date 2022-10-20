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
import json
import unittest
from unittest import mock
from collections import namedtuple

from apollo.handler.task_handler.manager.repo_manager import RepoManager
from apollo.handler.task_handler.manager.task_manager import CveAnsible
from apollo.handler.task_handler.config import PLAYBOOK_DIR
from apollo.conf import configuration
from apollo.database.proxy.task import TaskProxy
from apollo.conf.constant import REPO_STATUS, ANSIBLE_TASK_STATUS

from vulcanus.restful.status import SUCCEED


class TestRepoManager(unittest.TestCase):
    def setUp(self):
        proxy = TaskProxy(configuration)
        self.manager = RepoManager(proxy, 'a', 'a')
        self.manager.cur_time = 5

    def tearDown(self):
        pass

    def test_pre_handle(self):
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

    def test_handle(self):
        path = os.path.join(PLAYBOOK_DIR, 'a' + '.yml')
        with mock.patch.object(CveAnsible, 'playbook') as mock_pb:
            mock_pb.return_value = True
            self.manager.handle()
            mock_pb.assert_called_with([path])

    @mock.patch.object(TaskProxy, 'fix_task_status')
    @mock.patch.object(TaskProxy, 'save_task_info')
    def test_post_handle(self, mock_save_result, mock_fix_status):
        task = namedtuple('task', ['result', 'check', 'info'])
        task.result = {
            "name1": {
                "set repo": {
                    "status": REPO_STATUS.SUCCEED,
                    "info": "1"
                }
            },
            "name2": {
                "set repo": {
                    "status": REPO_STATUS.FAIL,
                    "info": "2"
                }
            },
            "name3": {}
        }
        task.check = {
            "name1": {
                "check1": {
                    "status": ANSIBLE_TASK_STATUS.SUCCEED
                }
            },
            "name2": {
                "check1": {
                    "status": ANSIBLE_TASK_STATUS.SUCCEED
                }
            },
            "name3": {}
        }
        task.info = {
            "name1": {
                "host_id": "id1",
                "host_name": "name1",
                "host_ip": "ip1",
                "repo_name": "a"
            },
            "name2": {
                "host_id": "id2",
                "host_name": "name2",
                "host_ip": "ip2",
                "repo_name": "a"
            },
            "name3": {
                "host_id": "id3",
                "host_name": "name3",
                "host_ip": "ip3",
                "repo_name": "a"
            }
        }
        expected_res = {
            "task_id": "a",
            "task_type": "repo",
            "latest_execute_time": 5,
            "task_result": [
                {
                    "host_id": "id1",
                    "host_name": "name1",
                    "host_ip": "ip1",
                    "repo": "a",
                    "status": "succeed",
                    "check_items": [
                        {
                            "item": "check1",
                            "result": True
                        }
                    ],
                    "log": "1"
                },
                {
                    "host_id": "id2",
                    "host_name": "name2",
                    "host_ip": "ip2",
                    "repo": "a",
                    "status": "fail",
                    "check_items": [
                        {
                            "item": "check1",
                            "result": True
                        }
                    ],
                    "log": "2"
                },
                {
                    "host_id": "id3",
                    "host_name": "name3",
                    "host_ip": "ip3",
                    "repo": "a",
                    "status": "unknown",
                    "check_items": [
                    ],
                    "log": ""
                }
            ]
        }
        self.manager.task = task
        self.manager.post_handle()
        mock_save_result.assert_called_with('a', log=json.dumps(expected_res))
