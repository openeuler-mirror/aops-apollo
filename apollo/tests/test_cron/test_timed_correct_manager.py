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

from apollo.database.proxy.task import TaskProxy
from apollo.cron.timed_correct_manager import TimedCorrectTask
from vulcanus.restful.status import DATABASE_CONNECT_ERROR, SUCCEED


class TestTimedCorrectTask(unittest.TestCase):

    @mock.patch.object(TaskProxy, "connect")
    def test_get_abnormal_task_should_return_connect_error_when_database_connect_fail(self,
                                                                                      mock_connect):
        mock_connect.return_value = False
        self.assertEqual(TimedCorrectTask.get_abnormal_task(), DATABASE_CONNECT_ERROR)

    @mock.patch.object(TaskProxy, "connect")
    @mock.patch.object(TaskProxy, "get_task_create_time")
    def test_get_abnormal_task_should_return_none_list_when_time_less_threshold(self,
                                                                                mock_get_task_create_time,
                                                                                mock_connect):
        mock_connect.return_value = True
        mock_get_task_create_time.return_value = [("qwertyuiop", "cve fix", "1707777777")]
        self.assertEqual(TimedCorrectTask.get_abnormal_task(), [])

    @mock.patch.object(TaskProxy, "connect")
    @mock.patch.object(TaskProxy, "get_task_create_time")
    def test_get_abnormal_task_should_return_list_when_time_exceeds_threshold(self,
                                                                              mock_get_task_create_time,
                                                                              mock_connect):
        mock_connect.return_value = True
        mock_get_task_create_time.return_value = [("qwertyuiop", "cve fix", "1672777777")]
        self.assertEqual(TimedCorrectTask.get_abnormal_task(), ["qwertyuiop"])

    @mock.patch.object(TaskProxy, "connect")
    @mock.patch.object(TimedCorrectTask, "get_abnormal_task")
    def test_create_timed_scan_task_should_return_connect_error_when_database_connect_fail(self,
                                                                                           mock_get_abnormal_task,
                                                                                           mock_connect):
        mock_get_abnormal_task.return_value = ["qwertyuiop"]
        mock_connect.return_value = False
        self.assertEqual(TimedCorrectTask.task_enter(), DATABASE_CONNECT_ERROR)

    @mock.patch.object(TaskProxy, "connect")
    @mock.patch.object(TimedCorrectTask, "get_abnormal_task")
    def test_create_timed_scan_task_should_return_log_info_when_abnormal_task_list_is_null(self,
                                                                                           mock_get_abnormal_task,
                                                                                           mock_connect):
        mock_get_abnormal_task.return_value = []
        mock_connect.return_value = True
        self.assertEqual(TimedCorrectTask.task_enter(), None)

    @mock.patch.object(TaskProxy, "connect")
    @mock.patch.object(TimedCorrectTask, "get_abnormal_task")
    @mock.patch.object(TaskProxy, "update_task_status")
    def test_create_timed_scan_task_should_return_none_when_update_task_status_succeed(self,
                                                                                       mock_update_task_status,
                                                                                       mock_get_abnormal_task,
                                                                                       mock_connect):
        mock_get_abnormal_task.return_value = ["QWERTYUIOP"]
        mock_connect.return_value = True
        mock_update_task_status.return_value = SUCCEED
        self.assertEqual(TimedCorrectTask.task_enter(), None)
