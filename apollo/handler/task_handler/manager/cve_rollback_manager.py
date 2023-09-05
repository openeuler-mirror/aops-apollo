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
from vulcanus.conf.constant import URL_FORMAT
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, TASK_EXECUTION_FAIL
from vulcanus.restful.response import BaseResponse

from apollo.conf import configuration
from apollo.conf.constant import VUL_TASK_CVE_ROLLBACK_CALLBACK, EXECUTE_CVE_ROLLBACK, TaskStatus
from apollo.handler.task_handler.manager import Manager


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
        if self.proxy.init_cve_rollback_task(self.task_id, []) != SUCCEED:
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
        header = {"access_token": self.token, "Content-Type": "application/json; charset=UTF-8"}

        response = BaseResponse.get_response('POST', manager_url, self.task, header)
        if response.get('label') != SUCCEED:
            LOGGER.error("Cve rollback task %s execute failed.", self.task_id)
            self.proxy.init_cve_rollback_task(self.task_id, [], TaskStatus.UNKNOWN)
            return TASK_EXECUTION_FAIL

        return SUCCEED
