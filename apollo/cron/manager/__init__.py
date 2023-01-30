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
from flask_apscheduler import APScheduler

from vulcanus.log.log import LOGGER


class TimedTaskManager():
    """
    Classes for Timed Task Management
    """
    _instance = None
    _APscheduler = None

    def __new__(cls, *args, **kw):
        if cls._instance is None:
            cls._APscheduler = APScheduler()
            cls._instance = object.__new__(cls)
        return cls._instance

    @staticmethod
    def init_app(app):
        TimedTaskManager._APscheduler.init_app(app)

    @staticmethod
    def start_task():
        TimedTaskManager._APscheduler.start()

    @staticmethod
    def add_timed_task(**kwargs):
        """
        Create a timed task.

        Args:
            kwargs: Parameters needed to create a timed task
        """
        timed_task_parameters = dict(kwargs)

        task_id = timed_task_parameters['id']
        auto_start = timed_task_parameters['auto_start']
        timed_task_parameters.pop("auto_start")
        if auto_start == "False":
            LOGGER.info(f"{task_id}, This task is configured to not start.")
            return
        if TimedTaskManager.get_timed_task(task_id):
            TimedTaskManager.delete_timed_task(task_id)
        TimedTaskManager._APscheduler.add_job(**timed_task_parameters)

    @staticmethod
    def pause_timed_task(task_id):
        """
        Pause a timed task for an id

        Args:
            task_id (int): Create timed task id;
        """
        TimedTaskManager._APscheduler.pause_job(task_id)

    @staticmethod
    def resume_timed_task(task_id):
        """
        Resume a timed task for an id

        Args:
            task_id (int): Create timed task id;
        """
        TimedTaskManager._APscheduler.resume_job(task_id)

    @staticmethod
    def get_all_timed_tasks():
        """
        Get all timed task

        Return:
            list: List of all timed task
        """
        timed_task_list = TimedTaskManager._APscheduler.get_jobs()
        return timed_task_list

    @staticmethod
    def get_timed_task(task_id):
        """
        Get the scheduled task of the corresponding id

        Args:
            task_id (str): Create timed task id;

        Return:
            list: List of all timed task
        """
        timed_task = TimedTaskManager._APscheduler.get_job(task_id)
        return timed_task

    @staticmethod
    def delete_timed_task(task_id):
        """
        Delete the scheduled task of the corresponding id

        Args:
            task_id (str): Create timed task id;
        """
        TimedTaskManager._APscheduler.delete_job(task_id)
