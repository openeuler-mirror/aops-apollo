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
import json

from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, PARTIAL_SUCCEED, SUCCEED

from apollo.conf.constant import TaskType
from apollo.handler.task_handler.callback import TaskCallback


class HotpatchRemoveCallback(TaskCallback):
    """
    Callback function for hotpatch remove.
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
                    "cves": [
                        {
                            "cve_id": "string",
                            "result": "succeed",
                            "log": ""
                        }
                    ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail",
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

                    "cves": [
                        {
                            "cve_id": "string",
                            "result": "succeed",
                            "log"": ""
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
        status_code, username = self.proxy.get_account_name_by_task_id(task_id)
        if status_code != SUCCEED:
            LOGGER.error("Failed to query task info!")
            return DATABASE_UPDATE_ERROR
        self._save_result_to_es(
            task_id=task_id,
            host_id=host_id,
            task_type=TaskType.HOTPATCH_REMOVE,
            task_result=task_result,
            username=username,
        )
        update_status_result = []
        for cve in task_result["cves"]:
            status_code = self.proxy.update_hotpatch_remove_cve_status(task_id, cve["cve_id"], host_id, cve["result"])
            update_status_result.append(status_code)

        if len(task_result["cves"]) != len(list(filter(lambda code: code == SUCCEED, update_status_result))):
            return PARTIAL_SUCCEED
        return SUCCEED
