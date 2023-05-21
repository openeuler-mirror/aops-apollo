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
from apollo.conf import configuration
from apollo.conf.constant import CVE_HOST_STATUS, VUL_TASK_CVE_ROLLBACK_CALLBACK
from apollo.handler.task_handler.manager import Manager
from vulcanus.conf.constant import URL_FORMAT, EXECUTE_CVE_ROLLBACK
from vulcanus.log.log import LOGGER
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.resp.state import SUCCEED


class CveRollbackManager(Manager):
    """
    Manager for cve rollback
    """

    def create_task(self) -> int:
        """
        Create cve rollback task

        Returns:
            int: status code
        """
        status_code, self.task = self.proxy.get_cve_rollback_task_info(self.task_id)
        if status_code != SUCCEED:
            LOGGER.error("There is no data about host info, stop cve rollback.")
            return status_code

        self.task['callback'] = VUL_TASK_CVE_ROLLBACK_CALLBACK

        return SUCCEED

    def pre_handle(self) -> bool:
        """
        Init host status to 'running', and update latest task execute time.

        Returns:
            bool: succeed or fail
        """
        if self.proxy.init_cve_task(self.task_id, []) != SUCCEED:
            LOGGER.error("Init the host status in database failed, stop cve rollback task %s.", self.task_id)
            return False

        if self.proxy.update_task_execute_time(self.task_id, self.cur_time) != SUCCEED:
            LOGGER.warning("Update latest execute time for cve rollback task %s failed.", self.task_id)

        return True

    def handle(self):
        """
        Executing cve rollback task.
        """
        LOGGER.info("Cve rollback task %s start to execute.", self.task_id)
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'), configuration.zeus.get('PORT'), EXECUTE_CVE_ROLLBACK)
        header = {
            "access_token": self.token,
            "Content-Type": "application/json; charset=UTF-8"
        }

        response = BaseResponse.get_response('POST', manager_url, self.task, header)
        if response.get('label') != SUCCEED or not response.get("data", dict()):
            LOGGER.error("Cve rollback task %s execute failed.", self.task_id)
            return

        LOGGER.info("Cve rollback task %s end, begin to handle result.", self.task_id)
        self.result = response.get("data", dict()).get("execute_result") or []

    def post_handle(self):
        """
        After executing the task, parse the checking and executing result, then save to database.
        """
        if not self.result:
            return
        LOGGER.debug("Cve rollback task %s result: %s", self.task_id, self.result)

        for host in self.result:
            host['status'] = 'succeed'
            if not host['cves']:
                host['status'] = 'unknown'
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
        self.proxy.fix_task_status(self.task_id, 'cve rollback')
