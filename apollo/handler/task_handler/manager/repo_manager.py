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
from vulcanus.log.log import LOGGER
from vulcanus.restful.status import SUCCEED
from apollo.conf.constant import REPO_STATUS
from apollo.handler.task_handler.manager.task_manager import CveAnsible
from apollo.handler.task_handler.manager import Manager
from apollo.handler.task_handler.callback.repo_set import RepoSetCallback


class RepoManager(Manager):
    """
    Manager for repo setting
    """

    def pre_handle(self):
        """
        Init host status and update latest task execute time.

        Returns:
            bool
        """
        if self.proxy.set_repo_status(self.task_id, [], REPO_STATUS.RUNNING) != SUCCEED:
            LOGGER.error(
                "Init the host status in database failed, stop repo setting task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.error(
                "Update latest execute time for repo set task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Execute repo setting task.
        """
        LOGGER.info("Repo setting task %s start to execute.", self.task_id)
        self.task = CveAnsible(inventory=self.inventory_path,
                               callback=RepoSetCallback(self.task_id, self.proxy, self.task_info))
        self.task.playbook([self.playbook_path])
        LOGGER.info(
            "Repo setting task %s end, begin to handle result.", self.task_id)

    def post_handle(self):
        """
        After executing the task, parse the checking and executing result, then
        save to database.
        """
        LOGGER.debug(self.task.result)
        LOGGER.debug(self.task.check)
        LOGGER.debug(self.task.info)

        task_result = []
        for host_name, host_info in self.task.info.items():
            temp = {
                "host_id": host_info['host_id'],
                "host_name": host_name,
                "host_ip": host_info['host_ip'],
                "repo": host_info['repo_name'],
                "status": "succeed",
                "check_items": [],
                "log": ""
            }

            self._record_check_info(self.task.check.get(host_name), temp)

            if self.task.result[host_name].get('set repo') is not None:
                temp['log'] = self.task.result[host_name]['set repo']['info']
                if self.task.result[host_name]['set repo']['status'] != REPO_STATUS.SUCCEED:
                    temp['status'] = 'fail'
            else:
                temp['status'] = REPO_STATUS.UNKNOWN

            task_result.append(temp)

        self._save_result(task_result, "repo")
        self.fault_handle()

    def fault_handle(self):
        """
        When the task is completed or execute fail, set the host status to 'unknown'.
        """
        self.proxy.fix_task_status(self.task_id, 'repo')
