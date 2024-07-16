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
import time
from typing import Dict, Optional

from vulcanus.cache import RedisError, RedisProxy
from vulcanus.conf.constant import TIMEOUT
from vulcanus.database.proxy import connect_database
from vulcanus.log.log import LOGGER

from apollo.conf import cache
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.proxy.task.timed_proxy import TimedProxy


class CorrectTask:
    """
    correct data tasks
    """

    @connect_database()
    def execute(self):
        """
        Start the correct after the specified time of day.
        """

        abnormal_task_ids, abnormal_host_ids = self.get_abnormal_task()
        if len(abnormal_host_ids) != 0:
            self._remove_cached_host_info(abnormal_host_ids)
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
            running_tasks = proxy.get_task_create_time()

        hosts = self._get_scanning_host_info()
        abnormal_tasks = self._abnormal_task(running_tasks)

        return abnormal_tasks, hosts

    @staticmethod
    def _get_scanning_host_info() -> Optional[Dict[str, int]]:
        """
        Query all host IDs and last scan time in scanning state

        Returns:
            Optional[Dict[str, int]]: scanning host id and its scan time timestamp
        """
        # example {"host_id1":"scanning timestamp info", "host_id2":"scanning timestamp info}
        scanning_host_dic: Dict[str, str] = cache.hash(cache.SCANNING_HOST_KEY)
        return scanning_host_dic or {}

    @staticmethod
    def _remove_cached_host_info(host_info: Dict[str, int]) -> None:
        """
        Remove the host information recorded in the redis cache

        Args:
            host_info(Dict[str,int]): scanning host information

        Returns:
            None
        """
        if not host_info:
            return

        current_time = int(time.time())
        wait_correct_host_id = []
        for host_id, scan_time in host_info.items():
            if current_time - int(scan_time) >= TIMEOUT:
                wait_correct_host_id.append(host_id)

        if not wait_correct_host_id:
            return

        try:
            RedisProxy.redis_connect.hdel(cache.SCANNING_HOST_KEY, *wait_correct_host_id)
        except RedisError as error:
            LOGGER.error("Failed to update host status: %s", error)
