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

from vulcanus.database.proxy import connect_database
from vulcanus.conf.constant import TIMEOUT, URL_FORMAT
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED
from vulcanus.restful.response import BaseResponse
from vulcanus.timed import TimedTask

from apollo.conf import configuration
from apollo.conf.constant import HOST_STATUS_GET
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.proxy.task.timed_proxy import TimedProxy


class TimedCorrectTask(TimedTask):
    """
    Timed correct data tasks
    """

    @connect_database()
    def execute(self):
        """
        Start the correct after the specified time of day.
        """
        LOGGER.info(
            "Begin to correct the status of timeout tasks and scan timeout host in %s.",
            str(datetime.datetime.now()))
        abnormal_task_ids, abnormal_host_ids = self.get_abnormal_task()
        if len(abnormal_host_ids) != 0:
            self._update_host_status(abnormal_host_ids)
        if len(abnormal_task_ids) != 0:
            with TimedProxy() as proxy:
                proxy.timed_correct_error_task_status(abnormal_task_ids)

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

    @connect_database()
    def get_abnormal_task(self):
        """
        Get abnormal tasks based on set thresholds and task creation time

        Args:
            proxy: Connected database proxy.

        Returns:
            list: The element of each list is the task ID
            list: The element of each list is the host ID
        """
        with TaskProxy() as proxy:
            running_tasks, hosts = proxy.get_task_create_time()

        abnormal_tasks = self._abnormal_task(running_tasks)
        abnormal_hosts = self._abnormal_task(hosts)

        return abnormal_tasks, abnormal_hosts

    @staticmethod
    def _update_host_status(host_ids):
        """
        update host status

        Args:
            host_ids(list): host id list

        Returns:
        """
        update_url = URL_FORMAT % (configuration.zeus.get('IP'), configuration.zeus.get('PORT'), HOST_STATUS_GET)
        header = {"exempt_authentication": configuration.individuation.get("EXEMPT_AUTHENTICATION"),
                  "Content-Type": "application/json; charset=UTF-8"}

        parameter = {"host_list": host_ids}
        response = BaseResponse.get_response('POST', update_url, parameter, header)
        if response.get('label') != SUCCEED:
            LOGGER.error("Failed to update host status")
