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
Description: callback function of the repo setting task.
"""
import json

from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import DATABASE_UPDATE_ERROR, SUCCEED

from apollo.conf.constant import TaskType
from apollo.handler.task_handler.callback import TaskCallback


class RepoSetCallback(TaskCallback):
    """
    Callback function for repo setting.
    """

    def _save_repo_set_result_to_es(self, task_id, host_id, task_result, username):
        """
        save host repo set result to es

        Args:
            task_id(str): Unique code for identifying task
            host_id(int): host id
            task_result(dict): repo set result

        Return:
            None
        """
        result = {
            "task_id": task_id,
            "host_id": host_id,
            "task_type": TaskType.REPO_SET,
            "latest_execute_time": task_result.pop("execution_time"),
            "task_result": task_result,
        }
        self.proxy.save_task_info(task_id, host_id, json.dumps(result), **{"username": username})

    def callback(self, task_result: dict) -> str:
        """
        Set the callback after the repo task is completed

        Args:
            task_result(dict): repo set result info, e.g
                {
                    "host_id": "string",
                    "task_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "execution_time": 1692864499, //The timestamp of the task execution
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "repo_name": "string",
                    "log": "xxx",
                    "username": admin
                }
        Returns:
            status_code(str): database operation result when save repo_set result to elasticsearch and mysql
        """
        task_id = task_result.pop("task_id")
        host_id = task_result.pop("host_id")
        status_code, username = self.proxy.get_account_name_by_task_id(task_id)
        if status_code != SUCCEED:
            LOGGER.error("Failed to query task info!")
            return DATABASE_UPDATE_ERROR

        status_code = self.proxy.update_host_status_in_tasks(task_id, task_result.get("status"), [host_id])
        self._save_repo_set_result_to_es(task_id, host_id, task_result, username)

        if status_code != SUCCEED:
            LOGGER.debug(
                "Setting repo name to hosts and update repo host state failed, "
                f"repo name: {task_result['repo_name']}, task id: {task_id}."
            )
            return DATABASE_UPDATE_ERROR

        return SUCCEED
