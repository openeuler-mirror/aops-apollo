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

from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, SUCCEED

from apollo.conf.constant import TaskType
from apollo.handler.task_handler.callback import TaskCallback


class CveFixCallback(TaskCallback):
    """
    Callback function for cve fixing.
    """

    def _save_result_to_es(self, task_id, host_id, task_type, task_result, username):
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
                    "rpms": [
                        {
                            "available_rpm": "string",
                            "result": "success",
                            "log": "string",
                        }
                    ],
                    "dnf_event_start": 1,
                    "dnf_event_end": 2,
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "failed",
                    "username": "admin",
                    "execution_time":""
            }
        """
        host_ip = task_result.pop("host_ip")
        host_name = task_result.pop("host_name")
        status = task_result.pop("status")
        result = {
            "task_id": task_id,
            "host_id": host_id,
            "host_ip": host_ip,
            "host_name": host_name,
            "status": status,
            "task_type": task_type,
            "latest_execute_time": task_result.pop("execution_time"),
            "task_result": task_result,
        }
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
                    "rpms": [
                        {
                            "available_rpm": "string",
                            "result": "success",
                            "log": "string",
                        }
                    ],
                    "dnf_event_start": 1,
                    "dnf_event_end": 2,
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "failed",
                    "username": "admin"
                }

        Returns:
            str: status code
        """
        task_id = task_result.pop("task_id")
        host_id = task_result.pop("host_id")
        status_code, username = self.proxy.get_account_name_by_task_id(task_id)
        if status_code != SUCCEED:
            LOGGER.error("Failed to query task info!")
            return DATABASE_UPDATE_ERROR

        self._save_result_to_es(
            task_id=task_id, host_id=host_id, task_type=TaskType.CVE_FIX, task_result=task_result, username=username
        )
        status_code = self.proxy.update_cve_fix_task_host_package_status(task_id, host_id, task_result)
        return status_code
