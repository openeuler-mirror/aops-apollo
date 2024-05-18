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
from unittest import mock
import sqlalchemy

from apollo.database.proxy.task.base import TaskProxy
from apollo.cron.timed_correct_manager import TimedCorrectTask
from apollo.tests import BaseTestCase


class TestTimedCorrectTask(BaseTestCase):
    def setUp(self) -> None:
        super().setUp()
        self._timed_config = {
            "timed_name": "Data correction cleaning",
            "task": "data_correction",
            "enable": True,
            "timed": {"day_of_week": "0-6", "hour": 3, "trigger": "cron"},
        }
        self.timed_correct = TimedCorrectTask(timed_config=self._timed_config)
        self.proxy = TaskProxy()

    @mock.patch.object(TaskProxy, "_create_session")
    def test_get_abnormal_task_should_return_connect_error_when_database_connect_fail(self, mock_connect):
        mock_connect.side_effect = sqlalchemy.exc.SQLAlchemyError("Connection error")
        self.assertEqual(self.timed_correct.execute(), None)

    @mock.patch.object(TaskProxy, "get_task_create_time")
    def test_get_abnormal_task_should_return_none_list_when_time_less_threshold(self, mock_get_task_create_time):
        mock_get_task_create_time.return_value = [[("qwertyuiop", "1707777777")], None]
        self.assertEqual(self.timed_correct.get_abnormal_task(self.proxy), ([], []))

    @mock.patch.object(TaskProxy, "get_task_create_time")
    def test_get_abnormal_task_should_return_list_when_time_exceeds_threshold(self, mock_get_task_create_time):
        mock_get_task_create_time.return_value = [[("qwertyuiop", "1672777777")], None]
        self.assertEqual(self.timed_correct.get_abnormal_task(self.proxy), (["qwertyuiop"], []))

    @mock.patch.object(TaskProxy, "_create_session")
    @mock.patch.object(TimedCorrectTask, "get_abnormal_task")
    def test_create_timed_scan_task_should_return_connect_error_when_database_connect_fail(
        self, mock_get_abnormal_task, mock_connect
    ):
        mock_get_abnormal_task.return_value = ["qwertyuiop"]
        mock_connect.side_effect = sqlalchemy.exc.SQLAlchemyError("Connection error")
        self.assertEqual(self.timed_correct.execute(), None)

    @mock.patch.object(TimedCorrectTask, "get_abnormal_task")
    def test_create_timed_scan_task_should_return_log_info_when_abnormal_task_list_is_null(
        self, mock_get_abnormal_task
    ):
        mock_get_abnormal_task.return_value = ([], [])
        self.assertEqual(self.timed_correct.execute(), None)
