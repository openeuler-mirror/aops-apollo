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
import copy
import unittest
from unittest import mock

from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR
from apollo.conf import configuration
from apollo.handler.task_handler.callback.repo_set import RepoSetCallback
from apollo.database.proxy.task import TaskProxy


class TestCveRollbackCallback(unittest.TestCase):
    def setUp(self):
        self.task_info = {
            "status": "set",
            "repo_name": "repo name",
            "host_id": 1
        }
        self.call = RepoSetCallback(TaskProxy(configuration))

    @mock.patch.object(TaskProxy, 'update_repo_host_status_and_host_reponame')
    def test_repo_set_callback_should_success_when_update_repo_host(self, mock_update_repo_host):
        self.call.callback("a", self.task_info)
        host_ids = ["host id"]
        data = dict(
            task_id="a", status=self.task_info["status"], repo_name=self.task_info["repo_name"])
        mock_update_repo_host.assert_called_with(data, host_ids)

    @mock.patch.object(TaskProxy, 'update_repo_host_status_and_host_reponame')
    def test_repo_set_callback_should_failed_when_update_repo_host_status(self, mock_update_repo_host):
        mock_update_repo_host.return_value = DATABASE_UPDATE_ERROR
        update_status = self.call.callback("a", self.task_info)
        self.assertEqual(DATABASE_UPDATE_ERROR, update_status)

    @mock.patch.object(TaskProxy, '_update_host_repo')
    def test_repo_set_callback_should_not_upate_host_repo_when_status_is_unset(self, mock_update_host_repo):
        self.call.proxy.connect()
        task_info = copy.deepcopy(self.task_info)
        task_info["status"] = "unset"
        self.call.callback("a", task_info)
        mock_update_host_repo.assert_not_called()
