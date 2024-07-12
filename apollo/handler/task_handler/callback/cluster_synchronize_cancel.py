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

from apollo.handler.task_handler.callback import TaskCallback


class SynchronizeCancelCallback(TaskCallback):
    """
    Callback function for synchronize cancel.
    """

    def callback(self, task_result: dict) -> str:
        """
        cluster synchronize cancel and delete cluster info.

        Args:
            task_result: e.g
                {
                    "cluster_id": "string",
                    "status": "succeed"
                }

        Returns:
            status_code: status_code
        """
        cluster_id = task_result.pop("cluster_id")
        status_code = self.proxy.delete_cluster_info(cluster_id)
        return status_code
