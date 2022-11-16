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

from apollo.conf import configuration
from apollo.conf.constant import CVE_HOST_STATUS, VUL_TASK_CVE_FIX_CALLBACK
from apollo.handler.task_handler.cache import TASK_CACHE
from apollo.handler.task_handler.manager import Manager
from vulcanus.conf.constant import URL_FORMAT, EXECUTE_CVE_FIX
from vulcanus.log.log import LOGGER
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import SUCCEED, PARAM_ERROR


class CveFixManager(Manager):
    """
    Manager for cve fixing
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

        status_code, self.task = self.proxy.get_cve_basic_info(self.task_id)
        if status_code != SUCCEED:
            LOGGER.error("There is no data about host info, stop cve fixing.")
            return status_code

        self.task['callback'] = VUL_TASK_CVE_FIX_CALLBACK
        # save to cache
        TASK_CACHE.put(self.task_id, self.task)

        return SUCCEED

    def pre_handle(self) -> bool:
        """
        Init host status to 'running', and update latest task execute time.

        Returns:
            bool: succeed or fail
        """
        if self.proxy.init_cve_task(self.task_id, []) != SUCCEED:
            LOGGER.error(
                "Init the host status in database failed, stop cve fixing task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.warning(
                "Update latest execute time for cve fix task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Executing cve fix task.
        """
        LOGGER.info("Cve fixing task %s start to execute.", self.task_id)
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'),
                                    configuration.zeus.get('PORT'),
                                    EXECUTE_CVE_FIX)
        header = {
            "access_token": self.token,
            "Content-Type": "application/json; charset=UTF-8"
        }
        pyload = self.task

        response = BaseResponse.get_response('POST', manager_url, pyload, header)
        if response.get('code') != SUCCEED or not response.get("result"):
            LOGGER.error("Cve fixing task %s execute failed.", self.task_id)
        else:
            LOGGER.info(
                "Cve fixing task %s end, begin to handle result.", self.task_id)
        self.result = response.get("result", {}).get("task_result") or []

    def post_handle(self):
        """
        After executing the task, parse the checking and executing result, then
        save to database.
        """
        LOGGER.debug("Cve fixing task %s result: %s", self.task_id, self.result)

        for host in self.result:
            host['status'] = 'succeed'
            for check_item in host['check_items']:
                if not check_item.get('result'):
                    host['status'] = 'fail'
                    break
            if host['status'] == 'fail':
                continue

            for cve in host['cves']:
                if cve.get('result') is None or cve.get('result') != CVE_HOST_STATUS.FIXED:
                    host['status'] = 'fail'
                    break
        self._save_result(self.result)
        self.fault_handle()

    def fault_handle(self):
        """
        When the task is completed or execute fail, fill the progress and set the
        host status to 'unknown'.
        """
        self.proxy.set_cve_progress(self.task_id, [], 'fill')
        self.proxy.fix_task_status(self.task_id, 'cve fix')
