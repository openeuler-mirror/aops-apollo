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
Description: Task manager for cve scanning.
"""
import re
import time

from celery import group
from celery.exceptions import CeleryError
from redis.exceptions import RedisError
from vulcanus.database.proxy import RedisProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, TASK_EXECUTION_FAIL

from apollo.conf import cache, celery_client
from apollo.conf.constant import TaskChannel
from apollo.handler.task_handler.manager import Manager


class ScanManager(Manager):
    """
    Manager for scanning task
    """

    def __init__(self, task_id, proxy, host_info_list, cluster_id=None, timed=False):
        """
        Args:
            task_id (str)
            proxy (object): proxy object of the database
            host_info_list (list)
        """
        self.host_info_list = host_info_list
        self.pattern = re.compile(r'CVE-\d+-\d+')
        self._timed = timed
        self.cluster_id = cluster_id
        super().__init__(proxy, task_id)

    def create_task(self):
        """
        Returns:
            int: status code
        """
        self.task = [
            (host_info, {"check_items": [], "task_id": self.task_id, "cluster_id": self.cluster_id})
            for host_info in self.host_info_list
        ]

    def pre_handle(self):
        """
        Generate request headers

        Returns:
            bool
        """
        try:
            current_time = int(time.time())
            RedisProxy.redis_connect.hmset(
                cache.SCANNING_HOST_KEY, {host.get("host_id"): current_time for host in self.host_info_list}
            )
            return True
        except RedisError as error:
            LOGGER.error(error)
            LOGGER.error("Failed to connect redis!")
            return False

    def handle(self):
        """
        Execute cve scan task.
        """
        try:
            LOGGER.info("Scanning task %s start to execute.", self.task_id)
            group(celery_client.signature(TaskChannel.CVE_SCAN_TASK, args=args) for args in self.task).apply_async()
            return SUCCEED
        except CeleryError as error:
            LOGGER.error(error)
            LOGGER.error("Cve scan task %s execute failed.", self.task_id)
            return TASK_EXECUTION_FAIL
