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
Description: callback function of the cve task.
"""

from apollo.database.proxy.task.base import TaskProxy
from abc import abstractmethod


class TaskCallback:
    """
    Callback function for cve task.
    """

    def __init__(self, proxy: TaskProxy):
        """
        Args:
            proxy (object): database proxy
        """
        self.proxy = proxy

    @abstractmethod
    def callback(self, task_result: dict) -> str:
        """task execution result is saved"""
