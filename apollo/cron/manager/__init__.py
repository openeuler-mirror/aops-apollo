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

from apollo.cron.manager.parse_config_info import get_timed_task_config_info
from vulcanus.log.log import LOGGER


class TimedTaskManager():
    """
    Classes for Timed Task Management, it can add, delete, pause and view scheduled tasks.
    """
    _instance = None
    _APscheduler = None

    def __new__(cls):
        if cls._instance is None:
            cls._APscheduler = APScheduler()
            cls._instance = object.__new__(cls)
        return cls._instance

    @staticmethod
    def init_app(app):
        """
        Initialize APScheduler

        Args:
            app:flask.Application
        """
        TimedTaskManager._APscheduler.init_app(app)

    @staticmethod
    def start_task():
        """
        Start running scheduled tasks
        """
        TimedTaskManager._APscheduler.start()

    @staticmethod
    def add_task(func, task_id=None, trigger="cron", **kwargs):
        """
        Create a timed task.

        Args:
            func(str): Functions for scheduled task execution
            task_id(str): The name of the task
            trigger(str): Timed task start method, value "date" or "cron" or "interval"
            kwargs: Parameters needed to create a timed task
                If the trigger method is "date", the parameter format is:
                {
                    "date","2022-2-3 00:00:01"
                }

                If the trigger method is "interval", the parameter format is:
                    {
                        "weeks" or "days" or "hours" or "minutes" or "seconds": time interval
                    }

                If the trigger method is "cron", the parameter format is:
                    {
                        "weeks" or "days" or "hours" or "minutes" or "seconds": time
                    }

        """
        if trigger not in ["date", "cron", "interval"]:
            LOGGER.error("Wrong trigger parameter for timed tasks.")
            return
        timed_task_parameters = dict(kwargs)
        if task_id is None:
            if "id" not in timed_task_parameters:
                LOGGER.error("Create scheduled task is missing id fields.")
                return
        else:
            if TimedTaskManager.get_task(task_id):
                LOGGER.info("This task id already exists for a scheduled task.")
                return
            timed_task_parameters['id'] = task_id

        if "day_of_week" not in timed_task_parameters or "hour" not in timed_task_parameters:
            LOGGER.error("Create scheduled task is missing required  fields.")
            return

        if "cvrf_url" in timed_task_parameters:
            timed_task_parameters.pop("cvrf_url")
        if "service_timeout_threshold_min" in timed_task_parameters:
            timed_task_parameters.pop("service_timeout_threshold_min")

        timed_task_parameters['trigger'] = trigger
        timed_task_parameters['func'] = func
        if "auto_start" in timed_task_parameters:
            auto_start = timed_task_parameters['auto_start']
            timed_task_parameters.pop("auto_start")
            if auto_start == "false":
                LOGGER.info(f"{task_id}, This task is configured to not start.")
                return
        TimedTaskManager._APscheduler.add_job(**timed_task_parameters)

    @staticmethod
    def pause_task(task_id: str):
        """
        Pause a timed task for an id

        Args:
            task_id (str): Create timed task id;
        """
        TimedTaskManager._APscheduler.pause_job(task_id)

    @staticmethod
    def resume_task(task_id: str):
        """
        Resume a timed task for an id

        Args:
            task_id (str): Create timed task id;
        """
        TimedTaskManager._APscheduler.resume_job(task_id)

    @staticmethod
    def get_all_tasks():
        """
        Get all timed task

        Return:
            list: List of all timed task
        """
        timed_task_list = TimedTaskManager._APscheduler.get_jobs()
        return timed_task_list

    @staticmethod
    def get_task(task_id: str):
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
    def delete_task(task_id: str):
        """
        Delete the scheduled task of the corresponding id

        Args:
            task_id (str): Create timed task id;
        """
        TimedTaskManager._APscheduler.delete_job(task_id)
