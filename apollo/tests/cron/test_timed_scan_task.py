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

import sqlalchemy
from vulcanus.restful.resp.state import DATABASE_QUERY_ERROR, SUCCEED

from apollo.conf.constant import HostStatus
from apollo.cron.timed_scan_task import TimedScanTask
from apollo.database.proxy.task.base import TaskMysqlProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager


class TestTimedScanTask(unittest.TestCase):
    def setUp(self) -> None:
        self.timed_config = {
            "timed_name": "cves scan",
            "task": "cve_scan",
            "enable": True,
            "timed": {"day_of_week": "0-6", "hour": 3, "trigger": "cron"},
        }

        self.cve_scan = TimedScanTask(timed_config=self.timed_config)

    def test_check_host_info_should_return_False_when_host_info_is_null(self):
        username = "admin"
        host_info = []
        self.assertEqual(self.cve_scan._check_host_info(username, host_info), False)

    def test_check_host_info_should_return_False_when_host_status_is_scanning(self):
        username = "admin"
        host = dict()
        host["status"] = HostStatus.SCANNING
        host_info = [host]
        self.assertEqual(self.cve_scan._check_host_info(username, host_info), False)

    def test_check_host_info_should_return_True_when_host_no_scanning(self):
        username = "admin"
        host = dict()
        host["status"] = HostStatus.DONE
        host_info = [host]
        self.assertEqual(self.cve_scan._check_host_info(username, host_info), True)

    @mock.patch.object(TaskMysqlProxy, "_create_session")
    def test_task_enter_should_return_None_when_connect_error(self, mock_connect):
        mock_connect.side_effect = sqlalchemy.exc.SQLAlchemyError("Connection error")
        self.assertEqual(self.cve_scan.execute(), None)

    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    def test_task_enter_should_return_None_when_get_total_host_info_fail(self, mock_get_total_host_info):
        mock_get_total_host_info.return_value = DATABASE_QUERY_ERROR, {"host_infos": {}}
        self.assertEqual(self.cve_scan.execute(), None)

    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    @mock.patch.object(TimedScanTask, "_check_host_info")
    @mock.patch.object(ScanManager, "create_task")
    @mock.patch.object(ScanManager, "pre_handle")
    def test_task_enter_should_return_None_when_pre_handle_fail(
        self, mock_pre_handle, mock_create_task, mock__check_host_info, mock_get_total_host_info
    ):
        mock_get_total_host_info.return_value = SUCCEED, {
            "host_infos": {
                "admin": [{"host_id": 1, "host_name": "host name", "host_ip": "127.0.0.0", "status": "done"}]
            }
        }
        mock__check_host_info.return_value = True
        mock_create_task.return_value = True
        mock_pre_handle.return_value = False
        self.assertEqual(self.cve_scan.execute(), None)

    @mock.patch.object(ScanManager, "fault_handle")
    @mock.patch.object(TaskMysqlProxy, "get_total_host_info")
    @mock.patch.object(TimedScanTask, "_check_host_info")
    @mock.patch.object(ScanManager, "create_task")
    @mock.patch.object(ScanManager, "pre_handle")
    def test_task_enter_should_return_None_when_task_enter_succeed(
        self, mock_pre_handle, mock_create_task, mock__check_host_info, mock_get_total_host_info, mock_fault_handle
    ):
        mock_get_total_host_info.return_value = SUCCEED, {
            "host_infos": {
                "admin": [{"host_id": 1, "host_name": "host name", "host_ip": "127.0.0.0", "status": "done"}]
            }
        }
        mock__check_host_info.return_value = True
        mock_create_task.return_value = True
        mock_pre_handle.return_value = True
        mock_fault_handle.return_value = None
        self.assertEqual(self.cve_scan.execute(), None)
