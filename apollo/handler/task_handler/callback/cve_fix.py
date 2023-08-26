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
import json
from apollo.handler.task_handler.callback import TaskCallback
from apollo.conf.constant import TaskType


class CveFixCallback(TaskCallback):
    """
    Callback function for cve fixing.
    """

    def _save_result_to_es(self, task_id, host_id, task_type, task_result):
        """
        Save the result to es.

        Args:
            task_result: e.g
                {
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],

                    "cves": [
                        {
                            "cve_id": "string",
                            "result": "succeed",
                            "rpms":[
                                {
                                "rpm": "string",
                                "result": "string",
                                "log": "string",
                                }
                            ]
                        }
                    ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "username": "admin",
                    "execution_time":""
            }
        """
        result = {
            "task_id": task_id,
            "host_id": host_id,
            "task_type": task_type,
            "latest_execute_time": task_result.pop("execution_time"),
            "task_result": task_result,
        }
        username = task_result.pop("username")
        self.proxy.save_task_info(task_id, host_id, log=json.dumps(result), username=username)

    def callback(self, task_result: dict) -> str:
        """
        Update cve status for the host and add the progress for the cves.

        Args:
            task_result: e.g
                {
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],

                    "cves": [
                        {
                            "cve_id": "string",
                            "result": "succeed",
                            "rpms":[
                                {
                                    "rpm": "string",
                                    "result": "string",
                                    "log": "string",
                                }
                            ]
                        }
                    ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "username": "admin"
                }

        Returns:
            str: status code
        """
        task_id = task_result.pop("task_id")
        host_id = task_result.pop("host_id")
        self._save_result_to_es(
            task_id=task_id,
            host_id=host_id,
            task_type=TaskType.CVE_FIX,
            task_result=task_result,
        )
        status_code = self.proxy.update_cve_status_and_set_package_status(task_id, host_id, task_result["cves"])
        return status_code
