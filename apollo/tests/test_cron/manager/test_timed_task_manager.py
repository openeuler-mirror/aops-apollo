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

from flask import Flask

from apollo.cron.manager import TimedTaskManager


class TestTimedTaskManager(unittest.TestCase):
    def test_init_app_should_return_None_when_init_app_succeed(self):
        app = Flask('apollo')
        self.assertEqual(TimedTaskManager().init_app(app), None)

    def test_start_task_should_return_None_when_start_task_succeed(self):
        self.assertEqual(TimedTaskManager().start_task(), None)

    def test_add_task_should_return_None_when_auto_start_is_False(self):
        timed_task_parameters = {
            "auto_start": False,
        }
        self.assertEqual(TimedTaskManager().add_task("task id", **timed_task_parameters), None)

    @mock.patch.object(TimedTaskManager, "get_task")
    def test_add_task_should_return_None_when_no_this_id_and_add_succeed(self, mock_get_task):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        mock_get_task.return_value = []
        self.assertEqual(TimedTaskManager().add_task("task id", **timed_task_parameters), None)

    @mock.patch.object(TimedTaskManager, "get_task")
    @mock.patch.object(TimedTaskManager, "delete_task")
    def test_add_task_should_return_None_when_this_id_exist_and_add_succeed(self, mock_delete_task, mock_get_task):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        mock_get_task.return_value = ["task id"]
        mock_delete_task.return_value = None
        self.assertEqual(TimedTaskManager().add_task("task id", **timed_task_parameters), None)

    def test_pause_task_should_return_None_when_pause_succeed(self):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        TimedTaskManager().add_task("task id", **timed_task_parameters)
        self.assertEqual(TimedTaskManager().pause_task("task id"), None)

    def test_resume_task_should_return_None_when_resume_succeed(self):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        TimedTaskManager().add_task("task id", **timed_task_parameters)
        TimedTaskManager().pause_task("task id")
        self.assertEqual(TimedTaskManager().resume_task("task id"), None)

    def test_get_all_task_should_return_list_when_get_succeed(self):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        TimedTaskManager().add_task("task id", **timed_task_parameters)
        self.assertEqual(TimedTaskManager().get_all_tasks()[0].id, "task id")

    def test_get_task_should_return_task_id_when_get_succeed(self):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        TimedTaskManager().add_task("task id", **timed_task_parameters)
        self.assertEqual(TimedTaskManager().get_task("task id").id, "task id")

    def test_delete_task_should_return_None_when_delete_succeed(self):
        timed_task_parameters = {"auto_start": True, "func": mock.Mock()}
        TimedTaskManager().add_task("task id", **timed_task_parameters)
        self.assertEqual(TimedTaskManager().delete_task("task id"), None)
