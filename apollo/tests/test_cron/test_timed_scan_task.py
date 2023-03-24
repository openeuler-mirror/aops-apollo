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

from apollo.cron.timed_scan_task import TimedScanTask
from apollo.database.proxy.task import TaskMysqlProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager
from vulcanus.restful.resp.state import DATABASE_QUERY_ERROR, SUCCEED, DATABASE_UPDATE_ERROR


class TestTimedScanTask(unittest.TestCase):

    def test_check_host_info_should_return_False_when_host_info_is_null(self):
        username = "admin"
        host_info = []
        self.assertEqual(TimedScanTask()._check_host_info(username, host_info), False)

    def test_check_host_info_should_return_False_when_host_status_is_scanning(self):
        username = "admin"
        host = dict()
        host["status"] = "scanning"
        host_info = [host]
        self.assertEqual(TimedScanTask()._check_host_info(username, host_info), False)

    def test_check_host_info_should_return_True_when_host_no_scanning(self):
        username = "admin"
        host = dict()
        host["status"] = "done"
        host_info = [host]
        self.assertEqual(TimedScanTask()._check_host_info(username, host_info), True)

    @mock.patch.object(TaskMysqlProxy, "connect")
    def test_task_enter_should_return_None_when_connect_error(self,
                                                              mock_connect):
        mock_connect.return_value = False
        self.assertEqual(TimedScanTask().task_enter(), None)

    @mock.patch.object(TaskMysqlProxy, "connect")
    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    def test_task_enter_should_return_None_when_get_total_host_info_fail(self,
                                                                         mock_get_total_host_info,
                                                                         mock_connect):
        mock_connect.return_value = True
        mock_get_total_host_info.return_value = DATABASE_QUERY_ERROR, {"host_infos": {}}
        self.assertEqual(TimedScanTask().task_enter(), None)

    @mock.patch.object(TaskMysqlProxy, "connect")
    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    @mock.patch.object(TimedScanTask, "_check_host_info")
    @mock.patch.object(ScanManager, "create_task")
    @mock.patch.object(ScanManager, "pre_handle")
    def test_task_enter_should_return_DATABASE_UPDATE_ERROR_when_pre_handle_fail(self,
                                                                                 mock_pre_handle,
                                                                                 mock_create_task,
                                                                                 mock__check_host_info,
                                                                                 mock_get_total_host_info,
                                                                                 mock_connect):
        mock_connect.return_value = True
        mock_get_total_host_info.return_value = SUCCEED, {"host_infos":
            {"admin": [{
                "host_id": 1,
                "host_name": "host name",
                "host_ip": "127.0.0.0",
                "status": "done"
            }]}}
        mock__check_host_info.return_value = True
        mock_create_task.return_value = True
        mock_pre_handle.return_value = False
        self.assertEqual(TimedScanTask().task_enter(), DATABASE_UPDATE_ERROR)

    @mock.patch.object(TaskMysqlProxy, "connect")
    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    @mock.patch.object(TimedScanTask, "_check_host_info")
    @mock.patch.object(ScanManager, "create_task")
    @mock.patch.object(ScanManager, "pre_handle")
    def test_task_enter_should_return_None_when_task_enter_succeed(self,
                                                                   mock_pre_handle,
                                                                   mock_create_task,
                                                                   mock__check_host_info,
                                                                   mock_get_total_host_info,
                                                                   mock_connect):
        mock_connect.return_value = True
        mock_get_total_host_info.return_value = SUCCEED, {"host_infos":
            {"admin": [{
                "host_id": 1,
                "host_name": "host name",
                "host_ip": "127.0.0.0",
                "status": "done"
            }]}}
        mock__check_host_info.return_value = True
        mock_create_task.return_value = True
        mock_pre_handle.return_value = True
        self.assertEqual(TimedScanTask().task_enter(), None)
