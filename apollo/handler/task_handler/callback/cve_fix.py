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
Description: callback function of the cve fixing task.
"""
from typing import Dict

from apollo.handler.task_handler.callback import TaskCallback


class CveFixCallback(TaskCallback):
    """
    Callback function for cve fixing.
    """

    def callback(self, task_id: str, host_id: int, cves: Dict[str, str]) -> int:
        """
        Update cve status for the host and add the progress for the cves.

        Args:
            task_id
            host_id
            cves: e.g.
                {
                    "cve-1-1": "fixed"
                }

        Returns:
            int: status code
        """
        status_code = self.proxy.update_cve_status_and_set_cve_progress(task_id, host_id, cves)
        return status_code
