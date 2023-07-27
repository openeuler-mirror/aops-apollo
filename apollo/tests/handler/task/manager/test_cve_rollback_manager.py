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

import unittest
from unittest import mock
import json

from vulcanus.restful.response import BaseResponse
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, SUCCEED, TASK_EXECUTION_FAIL
from apollo.database.proxy.task import TaskProxy
from apollo.handler.task_handler.manager.cve_rollback_manager import CveRollbackManager
from apollo.tests import BaseTestCase


class CveRollbackManagerTestCase(BaseTestCase):
    def setUp(self):
        super(CveRollbackManagerTestCase, self).setUp()
        proxy = TaskProxy()
        self.manager = CveRollbackManager(proxy, 'task+_id')

    def test_pre_handle_should_failed_when_update_task_cve_host_status_is_running(self):
        """
        test pre handle shoule failed when update task cve host status is running
        """
        with mock.patch.object(TaskProxy, 'init_cve_task') as mock_init_status:
            mock_init_status.return_value = DATABASE_UPDATE_ERROR
            self.assertEqual(self.manager.pre_handle(), False)

    @mock.patch.object(TaskProxy, "update_task_execute_time")
    @mock.patch.object(TaskProxy, "init_cve_task")
    def test_pre_handle_should_success_when_update_task_status_and_execute_time(
        self, mock_init_cve_task, mock_update_task_execute_time
    ):
        """
        test pre handle should success when update task status and execute time
        """
        mock_init_cve_task.return_value = SUCCEED
        mock_update_task_execute_time.return_value = SUCCEED
        self.assertEqual(self.manager.pre_handle(), True)

    @mock.patch.object(BaseResponse, "get_response")
    def test_handle_should_success_when_request_task_execute_exists_response_data(self, mock_get_response):
        """
        test handle should success when request task execute exists response data
        """
        mock_get_response.return_value = {"label": SUCCEED, "data": {"execute_result": None}}
        self.manager.handle()
        self.assertEqual(self.manager.result, [])

    @mock.patch.object(BaseResponse, "get_response")
    def test_handle_should_fail_when_request_task_execute_is_failed(self, mock_get_response):
        """
        test handle should success when request task execute is failed
        """
        mock_get_response.return_value = {"label": TASK_EXECUTION_FAIL, "data": {"execute_result": None}}
        self.assertEqual(self.manager.handle(), None)

    @mock.patch.object(CveRollbackManager, "fault_handle")
    def test_post_handle_should_none_when_result_is_none(self, mock_fault_handle):
        """
        test post handle should reutrn none when result is none
        """
        mock_fault_handle.return_value = None
        self.manager.result = None
        self.assertEqual(self.manager.post_handle(), None)

    @mock.patch.object(CveRollbackManager, "fault_handle")
    @mock.patch.object(TaskProxy, 'save_task_info')
    def test_post_handle_should_success_when_callbacked_save_task_info(self, mock_save_result, mock_fault_handle):
        """
        test post handle should success when callbacked save task info
        """
        mock_fault_handle.return_value = None
        self.manager.task = dict(task_type="cve rollback")
        self.manager.result = [
            {"host_id": "host_id1", "status": "succeed", "cves": [{"cve_id": "cve1", "log": "", "result": ""}]}
        ]

        result = {
            "task_id": self.manager.task_id,
            "task_type": "cve rollback",
            "latest_execute_time": self.manager.cur_time,
            "task_result": self.manager.result,
        }
        self.manager.post_handle()
        mock_save_result.assert_called_with('task+_id', log=json.dumps(result))
