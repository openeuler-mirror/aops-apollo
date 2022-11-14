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
Description: callback function of the cve scanning task.
"""
from vulcanus.log.log import LOGGER
from apollo.handler.task_handler.callback import TaskCallback


class CveScanCallback(TaskCallback):
    """
    Callback function for cve scanning.
    """

    def __init__(self, user, proxy, host_info):
        """
        Args:
            user (str): who the scanned hosts belongs to.
            proxy (object): database proxy
            host_info (list): host info, e.g. hostname, ip, etc.
        """
        self.user = user
        task_info = {}
        for info in host_info:
            host_name = info.get('host_name')
            task_info[host_name] = info

    def save_to_db(self, task_name, host_name, status):
        """
        Set the status of the host to database.

        Args:
            task_name (str): task name in playbook.
            host_name (str)
            status (str)
        """
        host_id = self.task_info[host_name]['host_id']
        self.proxy.update_scan_status([host_id])
        LOGGER.debug("task name: %s, host_id: %s, status: %s",
                     task_name, host_id, status)
