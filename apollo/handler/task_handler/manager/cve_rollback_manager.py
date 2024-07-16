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
Description: Task manager for cve fixing
"""
from celery import group
from celery.exceptions import CeleryError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import PARAM_ERROR, SUCCEED, TASK_EXECUTION_FAIL

from apollo.conf import celery_client
from apollo.conf.constant import TaskChannel, TaskStatus
from apollo.function.utils import query_user_hosts
from apollo.handler.task_handler.cache import TASK_CACHE
from apollo.handler.task_handler.manager import Manager


class CveRollbackManager(Manager):
    """
    Manager for cve rollback
    """

    def create_task(self) -> int:
        """
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

        status_code, self.task = self.proxy.get_cve_rollback_task_info_for_execution(self.task_id)
        if status_code != SUCCEED:
            LOGGER.error("Get rollback task info for execution failed, stop cve rollback.")
            return status_code

        # save to cache
        TASK_CACHE.put(self.task_id, self.task)

        return SUCCEED

    def pre_handle(self) -> bool:
        """
        Init host status to 'running', and update latest task execute time.

        Returns:
            bool: succeed or fail
        """
        if self.proxy.delete_task_log(self.task_id) != SUCCEED:
            LOGGER.error("Delete task log for cve rollback task %s failed.", self.task_id)
            return False

        if self.proxy.update_cve_rollback_task_status(self.task_id, TaskStatus.RUNNING) != SUCCEED:
            LOGGER.error("Init the host status in database failed, stop cve rollback task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.warning("Update latest execute time for cve rollback task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Executing cve rollback task.
        """
        # Query host info
        host_list = self.task.get("total_hosts")
        LOGGER.info("Cve rollback task %s start to execute.", self.task_id)
        query_fields = ["host_id", "host_ip", "host_name", "ssh_user", "ssh_port", "pkey"]
        host_info_list = query_user_hosts(host_list, query_fields)
        if len(host_info_list) != len(host_list):
            LOGGER.error("Cve rollback task %s execute failed.", self.task_id)
            self.proxy.update_cve_rollback_task_status(self.task_id, TaskStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL
        # Execute tasks by celery
        celery_tasks = self._generate_celery_tasks(host_info_list)
        try:
            group(
                celery_client.signature(TaskChannel.CVE_ROLLBACK_TASK, args=args) for args in celery_tasks
            ).apply_async()
            return SUCCEED
        except CeleryError as error:
            LOGGER.error(error)
            LOGGER.error("Cve rollback task %s execute failed.", self.task_id)
            self.proxy.update_cve_rollback_task_status(self.task_id, TaskStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL

    def _generate_celery_tasks(self, host_info_list):
        host_info_dict = {}
        for host_info in host_info_list:
            host_info_dict[host_info.get("host_id")] = host_info

        celery_tasks = []
        for task_info in self.task.get("tasks"):
            celery_tasks.append(
                (
                    host_info_dict.get(task_info["host_id"]),
                    {
                        "task_id": self.task_id,
                        "task_name": task_info.get("task_name"),
                        "task_type": task_info.get("task_type"),
                        "check_items": task_info.get("check_items", []),
                        "rollback_type": self.task.get("rollback_type"),
                        "installed_rpm": task_info.get("installed_rpm"),
                        "target_rpm": task_info.get("target_rpm"),
                        "dnf_event_start": task_info.get("dnf_event_start"),
                        "dnf_event_end": task_info.get("dnf_event_end"),
                    },
                )
            )
        return celery_tasks
