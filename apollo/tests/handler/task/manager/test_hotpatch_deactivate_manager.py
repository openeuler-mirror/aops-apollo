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

from unittest import mock

from vulcanus.restful.response import BaseResponse
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, SUCCEED, TASK_EXECUTION_FAIL
from apollo.database.proxy.task.base import TaskProxy
from apollo.handler.task_handler.manager.hotpatch_remove_manager import HotpatchRemoveManager
from apollo.tests import BaseTestCase


class CveRollbackManagerTestCase(BaseTestCase):
    def setUp(self):
        super().setUp()
        proxy = TaskProxy()
        proxy.connect()
        self.manager = HotpatchRemoveManager(proxy, 'task+_id')

    def test_pre_handle_should_failed_when_update_task_cve_host_status_is_running(self):
        """
        test pre handle shoule failed when update task cve host status is running
        """
        with mock.patch.object(TaskProxy, 'init_cve_rollback_task') as mock_init_status:
            mock_init_status.return_value = DATABASE_UPDATE_ERROR
            self.assertFalse(self.manager.pre_handle())

    @mock.patch.object(TaskProxy, "update_task_execute_time")
    @mock.patch.object(TaskProxy, "init_cve_rollback_task")
    def test_pre_handle_should_success_when_update_task_status_and_execute_time(
        self, mock_init_cve_task, mock_update_task_execute_time
    ):
        """
        test pre handle should success when update task status and execute time
        """
        mock_init_cve_task.return_value = SUCCEED
        mock_update_task_execute_time.return_value = SUCCEED
        self.assertTrue(self.manager.pre_handle())

    @mock.patch.object(BaseResponse, "get_response")
    def test_handle_should_success_when_request_task_execute_exists_response_data(self, mock_get_response):
        """
        test handle should success when request task execute exists response data
        """
        mock_get_response.return_value = {"label": SUCCEED, "data": {"execute_result": None}}
        self.assertEqual(self.manager.handle(), SUCCEED)

    @mock.patch.object(BaseResponse, "get_response")
    def test_handle_should_fail_when_request_task_execute_is_failed(self, mock_get_response):
        """
        test handle should success when request task execute is failed
        """
        mock_get_response.return_value = {"label": TASK_EXECUTION_FAIL, "data": {"execute_result": None}}
        self.assertEqual(self.manager.handle(), TASK_EXECUTION_FAIL)
