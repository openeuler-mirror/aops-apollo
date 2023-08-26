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
from vulcanus.restful.resp.state import SUCCEED, DATABASE_UPDATE_ERROR
from apollo.conf.constant import TaskType

from apollo.handler.task_handler.callback import TaskCallback


class RepoSetCallback(TaskCallback):
    """
    Callback function for repo setting.
    """

    def _save_repo_set_result_to_es(self, task_id, host_id, task_result):
        """
        save host repo set result to es

        Args:
            task_id(str): Unique code for identifying task
            host_id(int): host id
            task_result(dict): repo set result and its log. e.g
                {
                    "result": "Succeed/Fail",
                    "log": "set succeed / fail reason",
                    "execution_time": 1692864499,//The timestamp of the task execution
                }

        Return:
            None
        """
        log = json.dumps(
            {
                "task_id": task_id,
                "host_id": host_id,
                "task_type": TaskType.REPO_SET,
                "latest_execute_time": task_result.pop("execution_time"),
                "task_result": task_result,
            }
        )
        self.proxy.save_task_info(task_id, host_id, log)

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
                    "log": "xxx"
                }
        Returns:
            status_code(str): database operation result when save repo_set result to elasticsearch and mysql
        """
        task_id = task_result.get("task_id")
        host_id = task_result.get("host_id")
        data = dict(task_id=task_id, status=task_result['status'], repo_name=task_result['repo_name'])
        status_code = self.proxy.update_repo_host_status_and_host_reponame(data, [host_id])

        to_save_result = {
            "log": task_result["log"],
            "result": task_result["status"],
            "execution_time": task_result["execution_time"],
        }
        self._save_repo_set_result_to_es(task_id, host_id, to_save_result)

        if status_code != SUCCEED:
            LOGGER.debug(
                "Setting repo name to hosts and upate repo host state failed, "
                f"repo name: {task_result['repo_name']}, task id: {task_id}."
            )
            return DATABASE_UPDATE_ERROR

        return SUCCEED
