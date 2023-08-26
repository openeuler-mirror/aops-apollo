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
from vulcanus.restful.resp.state import SUCCEED, DATABASE_UPDATE_ERROR

from apollo.handler.task_handler.callback import TaskCallback


class CveScanCallback(TaskCallback):
    """
    Callback function for cve scanning.
    """

    def callback(self, task_result: dict) -> str:
        """
        Set the callback after the cve scan task is completed

        Args:
            task_result: single host cve scan result, e.g.
                {
                    "task_id": "string",
                    "host_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "os_version": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "installed_packages": [
                        {
                            "name": "string",
                            "version": true
                        }
                    ],
                    "unfixed_cves":[
                        {
                            "cve_id": "CVE-2023-1513",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "available_rpm":"kernel-4.19.90-2304.1.0.0196.oe1.x86_64",
                            "support_way":"hotpatch/coldpatch/none"
                        }
                    ],
                    "fixed_cves": [
                        {
                            "cve_id": "CVE-2022-4904",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "fix_way": "hotpatch/coldpatch",
                            "hp_status": "ACCEPTED/ACTIVED"
                        }
                    ],
                }

        Returns:
            status_code: cve scan setting status
        """
        status_code = self.proxy.save_cve_scan_result(task_result)

        if status_code != SUCCEED:
            LOGGER.error(
                f"cve scan to hosts and update cve host state failed, status: {task_result['status']},"
                f" task id: {task_result['task_id']}."
            )
            return DATABASE_UPDATE_ERROR

        return SUCCEED
