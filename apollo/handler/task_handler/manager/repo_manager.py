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
Description: Task manager for repo setting
"""
from celery import group
from celery.exceptions import CeleryError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import PARAM_ERROR, SUCCEED, TASK_EXECUTION_FAIL

from apollo.conf import cache, celery_client
from apollo.conf.constant import RepoStatus, TaskChannel
from apollo.function.utils import query_user_hosts
from apollo.handler.task_handler.cache import TASK_CACHE
from apollo.handler.task_handler.manager import Manager


class RepoManager(Manager):
    """
    Manager for repo setting
    """

    def create_task(self) -> int:
        """
        Create a task template for setting repo

        Args:
            username: system user
        Returns:
            int: status code
        """
        self.task = TASK_CACHE.get(self.task_id)
        if self.task is not None:
            return SUCCEED

        # query from database
        if not self.proxy:
            LOGGER.error("The database proxy need to be inited first.")
            return PARAM_ERROR

        cluster_info = cache.get_user_clusters()
        if not cluster_info:
            LOGGER.error("There is no data about cluster info, stop repo set.")
            return TASK_EXECUTION_FAIL

        status_code, self.task = self.proxy.get_repo_set_task_template(self.task_id, cluster_info)
        if status_code != SUCCEED:
            LOGGER.error("There is no data about host info, stop repo set.")
            return status_code

        # save to cache
        TASK_CACHE.put(self.task_id, self.task)

        return SUCCEED

    def pre_handle(self):
        """
        Init host status and update latest task execute time.

        Returns:
            bool
        """
        if self.proxy.delete_task_log(self.task_id) != SUCCEED:
            LOGGER.error("Delete the task log for repo set task %s failed.", self.task_id)
            return False

        if self.proxy.set_repo_status(self.task_id, [], RepoStatus.RUNNING) != SUCCEED:
            LOGGER.error("Init the host status in database failed, stop repo setting task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.error("Update latest execute time for repo set task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Execute repo setting task.
        """
        # Query host info
        host_list = self.task.get("total_hosts")
        LOGGER.info("Repo setting task %s start to execute.", self.task_id)
        query_fields = ["host_id", "host_ip", "host_name", "ssh_user", "ssh_port", "pkey"]
        host_info_list = query_user_hosts(host_list=host_list, fields=query_fields)

        if len(host_info_list) != len(host_list):
            LOGGER.error("Failed to get host info!")
            LOGGER.error("Set repo task %s execute failed.", self.task_id)
            self.proxy.set_repo_status(self.task_id, [], RepoStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL

        # Execute tasks by celery
        celery_tasks = [(host, self.task) for host in host_info_list]
        try:
            group(celery_client.signature(TaskChannel.REPO_SET_TASK, args=args) for args in celery_tasks).apply_async()
            return SUCCEED
        except CeleryError as error:
            LOGGER.error(error)
            LOGGER.error("Set repo task %s execute failed.", self.task_id)
            self.proxy.set_repo_status(self.task_id, [], RepoStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL
