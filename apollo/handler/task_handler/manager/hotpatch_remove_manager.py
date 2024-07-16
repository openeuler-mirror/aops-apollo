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
from celery import group
from celery.exceptions import CeleryError
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, TASK_EXECUTION_FAIL

from apollo.conf import celery_client
from apollo.conf.constant import TaskChannel, TaskStatus
from apollo.function.utils import query_user_hosts
from apollo.handler.task_handler.manager import Manager


class HotpatchRemoveManager(Manager):
    """
    Manager for hotpatch remove
    """

    def create_task(self) -> int:
        """
        Create hotpatch remove task

        Returns:
            int: status code
        """
        status_code, self.task = self.proxy.get_hotpatch_remove_basic_info(self.task_id)
        if status_code != SUCCEED:
            LOGGER.error("There is no data about host info, stop creating a hotpatch remove task.")
            return status_code

        return SUCCEED

    def pre_handle(self) -> bool:
        """
        Init host status to 'running', and update latest task execute time.

        Returns:
            bool: succeed or fail
        """
        if self.proxy.delete_task_log(self.task_id) != SUCCEED:
            LOGGER.error("Delete task log for hotpatch remove task %s failed.", self.task_id)
            return False

        if self.proxy.init_hotpatch_remove_task(self.task_id, []) != SUCCEED:
            LOGGER.error("Init the host status in database failed, stop hotpatch remove task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.warning("Update latest execute time for hotpatch remove task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Executing hotpatch remove task.
        """
        LOGGER.info("hotpatch remove task %s start to execute.", self.task_id)
        host_list = self.task.get("total_hosts")
        query_fields = ["host_id", "host_ip", "host_name", "ssh_user", "ssh_port", "pkey"]
        host_info_list = query_user_hosts(host_list=host_list, fields=query_fields)
        if len(host_info_list) != len(host_list):
            LOGGER.error("Hotpatch remove task %s execute failed.", self.task_id)
            self.proxy.init_hotpatch_remove_task(self.task_id, [], TaskStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL

        # Execute tasks by celery
        celery_tasks = self._generate_celery_tasks(host_info_list)
        try:
            group(
                celery_client.signature(TaskChannel.HOTPATCH_REMOVE_TASK, args=args) for args in celery_tasks
            ).apply_async()
            return SUCCEED
        except CeleryError as error:
            LOGGER.error(error)
            LOGGER.error("Hotpatch remove task %s execute failed.", self.task_id)
            self.proxy.init_hotpatch_remove_task(self.task_id, [], TaskStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL

    def _generate_celery_tasks(self, host_info_list):
        host_info_dict = {}
        for host_info in host_info_list:
            host_info_dict[host_info.get("host_id")] = host_info

        celery_tasks = []
        for task in self.task.get("tasks"):
            celery_tasks.append(
                (
                    host_info_dict.get(task["host_id"]),
                    {
                        "task_id": self.task_id,
                        "task_name": task.get("task_name"),
                        "task_type": task.get("task_type"),
                        "cves": task.get("cves"),
                        "check_items": [],
                    },
                )
            )
        return celery_tasks
