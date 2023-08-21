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
import time
from vulcanus.restful.resp.state import SUCCEED, PARTIAL_SUCCEED
from apollo.conf.constant import TaskType
from apollo.handler.task_handler.callback import TaskCallback


class CveRollbackCallback(TaskCallback):
    """
    Callback function for cve rollback.
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
                            "log": ""
                        }
                    ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "fail"
            }
        """
        result = {
            "task_id": task_id,
            "host_id": host_id,
            "task_type": task_type,
            "latest_execute_time": int(time.time()),
            "task_result": task_result,
        }
        self.proxy.save_task_info(task_id, host_id, log=json.dumps(result))

    def callback(self, cve_rollback_result: dict) -> str:
        """
        Update cve status for the host and add the progress for the cves.

        Args:
            cve_rollback_result: e.g
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
                    "status": "fail"
                }

        Returns:
            str: status code
        """
        task_id = cve_rollback_result.pop("task_id")
        host_id = cve_rollback_result.pop("host_id")
        self._save_result_to_es(
            task_id=task_id,
            host_id=host_id,
            task_type=TaskType.CVE_ROLLBACK,
            task_result=cve_rollback_result,
        )
        update_status_result = []
        for cve in cve_rollback_result["cves"]:
            status_code = self.proxy.update_cve_status(task_id, cve["cve_id"], host_id, cve["result"])
            update_status_result.append(status_code)

        if len(cve_rollback_result["cves"]) != len(list(filter(lambda code: code == SUCCEED, update_status_result))):
            return PARTIAL_SUCCEED
        return SUCCEED
