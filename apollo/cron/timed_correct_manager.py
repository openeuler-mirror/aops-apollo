#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
import datetime
import time

import sqlalchemy
from vulcanus.conf.constant import TIMEOUT
from vulcanus.log.log import LOGGER
from vulcanus.timed import TimedTask

from apollo.database.proxy.task import TaskProxy


class TimedCorrectTask(TimedTask):
    """
    Timed correct data tasks
    """

    def execute(self):
        """
        Start the correct after the specified time of day.
        """
        LOGGER.info("Begin to correct the whole host in %s.", str(datetime.datetime.now()))
        try:
            with TaskProxy() as proxy:
                abnormal_task_list, abnormal_host_list = self.get_abnormal_task(proxy)
                proxy.update_repo_task_status(abnormal_task_list)
                proxy.update_cve_host_task_status(abnormal_task_list)
                proxy.update_host_status(abnormal_host_list)
        except sqlalchemy.exc.SQLAlchemyError:
            LOGGER.error("Connect to database fail.")

    @staticmethod
    def _abnormal_task(tasks):
        abnormal_tasks = []
        if not tasks:
            return abnormal_tasks

        current_time = int(time.time())
        for task_id, create_time in tasks:
            if current_time - int(create_time) >= TIMEOUT:
                abnormal_tasks.append(task_id)

        return abnormal_tasks

    def get_abnormal_task(self, proxy: TaskProxy):
        """
        Get abnormal tasks based on set thresholds and task creation time

        Args:
            proxy: Connected database proxy.

        Returns:
            list: The element of each list is the task ID
            list: The element of each list is the host ID
        """
        running_tasks, hosts = proxy.get_task_create_time()

        abnormal_tasks = self._abnormal_task(running_tasks)
        abnormal_hosts = self._abnormal_task(hosts)

        return abnormal_tasks, abnormal_hosts
