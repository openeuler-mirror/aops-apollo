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
from vulcanus.conf.constant import URL_FORMAT, EXECUTE_REPO_SET
from vulcanus.log.log import LOGGER
from vulcanus.restful.status import SUCCEED, PARAM_ERROR
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.conf.constant import REPO_STATUS, VUL_TASK_REPO_SET_CALLBACK
from apollo.handler.task_handler.manager import Manager
from apollo.handler.task_handler.cache import TASK_CACHE


class RepoManager(Manager):
    """
    Manager for repo setting
    """

    def create_task(self, username) -> int:
        """
        Create a task template for setting repo

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

        status_code, self.task = self.proxy.get_repo_set_task_template(
            self.task_id, username)
        if status_code != SUCCEED:
            LOGGER.error("There is no data about host info, stop repo set.")
            return status_code

        self.task['callback'] = VUL_TASK_REPO_SET_CALLBACK
        # save to cache
        TASK_CACHE.put(self.task_id, self.task)

        return SUCCEED

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
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'),
                                    configuration.zeus.get('PORT'),
                                    EXECUTE_REPO_SET)
        header = {
            "access_token": self.token,
            "Content-Type": "application/json; charset=UTF-8"
        }

        response = BaseResponse.get_response(
            'POST', manager_url, self.task, header)

        if response.get('code') != SUCCEED:
            LOGGER.error("Set repo task %s execute failed.", self.task_id)
            return

        LOGGER.info(
            "Set repo task %s end, begin to handle result.", self.task_id)
        self.result = response["result"]

    def post_handle(self):
        """
        After executing the task, parse the checking and executing result, then
        save to database.
        """
        LOGGER.debug("Set repo task %s result: %s", self.task_id, self.result)
        self._save_result(self.result)
        self.fault_handle()

    def fault_handle(self):
        """
        When the task is completed or execute fail, set the host status to 'unknown'.
        """
        self.proxy.fix_task_status(self.task_id, 'repo set')
