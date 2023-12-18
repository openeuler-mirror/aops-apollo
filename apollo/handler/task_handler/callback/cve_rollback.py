#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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
from apollo.database.proxy.task.cve_rollback import CveRollbackTaskProxy
from apollo.conf.constant import TaskType


class CveRollbackCallback(TaskCallback):
    """
    Callback function for cve rollback task.
    """
    def __init__(self, proxy: CveRollbackTaskProxy):
        """
        Args:
            proxy (object): database proxy
        """
        super().__init__(proxy)
        self.proxy = proxy

    def _save_result_to_es(self, task_id: str, host_id: str, task_result: dict):
        """
        Save the result to es.

        Args:
            task_id(str): task id
            host_id(str): host id
            task_result(dict): rollback task result from zeus
        """
        username = task_result["username"]
        result = self._gen_es_log(task_id, host_id, task_result)
        self.proxy.save_task_info(task_id, host_id, log=json.dumps(result), username=username)

    def _gen_es_log(self, task_id: str, host_id: str, task_result: dict) -> dict:
        """
        generate rollback task's es doc
        Args:
            task_id(str): task id
            host_id(str): host id
            task_result(dict): rollback task result from zeus.  e.g.
                {
                    "username": "admin",
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "log": "",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "execution_time":""
                }

        Returns:
            dict: processed host result.  e.g.
                {
                    "host_id": 2,
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "latest_execute_time": "1691465474",
                    "task_type": "cve rollback",
                    "task_result": {
                        "check_items":[
                            {
                                "item":"network",
                                "result":true,
                                "log":"xxxx"
                            }
                        ],
                        "rpms": [
                            {
                                "installed_rpm": "",
                                "target_rpm": "",
                                "cves": "CVE-2023-12,CVE-2022-4567"
                            }
                        ],
                        "result": "succeed/fail",
                        "log": "string"
                       }
                ]
        """
        _, rpm_info_list = self.proxy.get_cve_rollback_host_rpm_info({"task_id": task_id, "host_id": host_id})
        for rpm_info in rpm_info_list:
            rpm_info.pop("status")

        processed_task_result = {
            "check_items": task_result["check_items"],
            "rpms": rpm_info_list,
            "result": task_result["status"],
            "log": task_result["log"]
        }
        result = {
            "host_id": task_result["host_id"],
            "host_ip": task_result["host_ip"],
            "host_name": task_result["host_name"],
            "latest_execute_time": task_result["execution_time"],
            "task_type": TaskType.CVE_ROLLBACK,
            "task_result": processed_task_result,
        }
        return result

    def callback(self, task_result: dict) -> str:
        """
        Update host's rollback result in es and mysql
        Args:
            task_result: rollback task result from zeus. e.g
                {
                    "username": "admin",
                    "task_id": "string",
                    "host_id": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "log": "",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
                    "execution_time":""
                }
        Returns:
            str: status code
        """
        task_id = task_result["task_id"]
        host_id = task_result["host_id"]
        status = task_result["status"]
        self._save_result_to_es(task_id, host_id, task_result)
        status_code = self.proxy.update_cve_rollback_task_status(task_id, status, host_id)
        return status_code
