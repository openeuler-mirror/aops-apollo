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

from apollo.conf import configuration
from apollo.handler.task_handler.manager import Manager
from vulcanus.conf.constant import URL_FORMAT, EXECUTE_CVE_SCAN
from vulcanus.log.log import LOGGER
from vulcanus.restful.response import BaseResponse
from vulcanus.restful.status import SUCCEED


class ScanManager(Manager):
    """
    Manager for scanning task
    """

    def __init__(self, task_id, proxy, host_info, username):
        """
        Args:
            task_id (str)
            proxy (object): proxy object of the database
            host_info (list)
            username (str)
        """
        self.host_list = [host['host_id'] for host in host_info]
        self.username = username
        self.pattern = re.compile(r'CVE-\d+-\d+')
        super().__init__(proxy, task_id)

    def create_task(self):
        """
       Returns:
           int: status code
       """
        host_info_list = []
        for host_id in self.host_list:
            host_info_list.append({
                "host_id": host_id,
                "check": False
            })

        self.task = {
            "task_id": self.task_id,
            "task_type": "cve scan",
            "total_hosts": self.host_list,
            "check_items": [],
            "tasks": host_info_list,
            "callback": "/vulnerability/task/callback/cve/scan"
        }

        return SUCCEED

    def pre_handle(self):
        """
        Init host scan status.

        Returns:
            bool
        """
        if self.proxy.update_host_scan("init", self.host_list, self.username) != SUCCEED:
            LOGGER.error(
                "Init the host status in database failed, stop scanning.")
            return False

        return True

    def handle(self):
        """
        Execute cve scan task.
        """
        LOGGER.info("Scanning task %s start to execute.", self.task_id)
        manager_url = URL_FORMAT % (configuration.zeus.get('IP'),
                                    configuration.zeus.get('PORT'),
                                    EXECUTE_CVE_SCAN)
        header = {
            "access_token": self.token,
            "Content-Type": "application/json; charset=UTF-8"
        }
        response = BaseResponse.get_response(
            'POST', manager_url, self.task, header)
        if response.get('code') != SUCCEED:
            LOGGER.error("Cve scan task %s execute failed.", self.task_id)
            return
        self.result = response.get("task_result")
        LOGGER.info(
            "Cve scan task %s end, begin to handle result.", self.task_id)

    def post_handle(self):
        """
        After executing the task, parse and save result to database.
        """

        if self.result:
            for host_info in self.result:
                LOGGER.debug(
                    f"{host_info['host_id']} scan status is {host_info.get('status')}")
        else:
            LOGGER.info(f"cve scan result is null")
        self.fault_handle()

    def fault_handle(self):
        """
            When the task is completed or execute fail, set the host status to 'done'.
        """
        self.proxy.update_host_scan("finish", self.host_list)
