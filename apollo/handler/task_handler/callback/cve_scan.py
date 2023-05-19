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
from apollo.handler.task_handler.callback import TaskCallback
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED, DATABASE_UPDATE_ERROR


class CveScanCallback(TaskCallback):
    """
    Callback function for cve scanning.
    """

    def callback(self, task_info: dict) -> int:
        """
        Set the callback after the cve scan task is completed
        Args:
            task_id: task id,
            task_info: task info, e.g.:
                {
                    "task_id": task id,
                    "host_id": 1
                    "status":succeed,
                    "host_id":1,
                    "installed_packages":[{
                                            "name":"kernel",
                                            "version":"0.2.3"
                                         }],
                    "os_version":"string",
                    "unfixed_cves":[{
                            "cve_id": "CVE-1-1",
                            "support_hp": true
                    }],
                    "fixed_cves":[
                        {
                            "cve_id": "CVE-1-2",
                            "fixed_by_hp": true
                        }
                    ]
                }

        Returns:
            status_code: cve scan setting status
        """
        status_code = self.proxy.save_cve_scan_result(task_info)
        self.proxy.update_host_scan("finish", [task_info["host_id"]])

        if status_code != SUCCEED:
            LOGGER.error(
                f"cve scan to hosts and update cve host state failed, status: {task_info['status']},"
                f" task id: {task_info['task_id']}.")
            return DATABASE_UPDATE_ERROR

        return SUCCEED
