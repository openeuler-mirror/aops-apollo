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
"""
Time:
Author:
Description:
"""
import time
from abc import ABC, abstractmethod

from apollo.database.proxy.task import TaskProxy


class Manager(ABC):
    """
    Base manager, define execute steps and handle function of each step.
    """

    def __init__(self, proxy: TaskProxy, task_id: str):
        """
        Args:
            proxy (object): database proxy instance
            task_id (str): id of current task
            task_info (dict): task info, it's generally host info.
        """
        self.__proxy = proxy
        self.__task_id = task_id
        self.__task = None
        self.__cur_time = int(time.time())
        self.__token = None
        self.result = None

    @property
    def proxy(self):
        return self.__proxy

    @proxy.setter
    def proxy(self, proxy):
        self.__proxy = proxy

    @property
    def task_id(self):
        return self.__task_id

    @property
    def task(self):
        return self.__task

    @task.setter
    def task(self, task):
        self.__task = task

    @property
    def cur_time(self):
        return self.__cur_time

    @property
    def token(self):
        return self.__token

    @token.setter
    def token(self, token):
        self.__token = token

    @abstractmethod
    def create_task(self):
        """
        Create task before executing the task, it's the params for restful request of manager.
        """

    @abstractmethod
    def pre_handle(self):
        """
        Pre handle before executing the task, it's often about initing some status.
        """

    @abstractmethod
    def handle(self):
        """
        Task executing
        """

    def execute_task(self):
        """
        Run task according to the two handle function steps.
        """
        return self.handle()
