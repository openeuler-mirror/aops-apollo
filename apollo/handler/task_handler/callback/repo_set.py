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
from apollo.handler.task_handler.callback import TaskCallback
from vulcanus.log.log import LOGGER
from vulcanus.restful.status import SUCCEED, DATABASE_UPDATE_ERROR


class RepoSetCallback(TaskCallback):
    """
    Callback function for repo setting.
    """

    def callback(self, task_id: str, task_info: dict) -> int:
        """
        Set the callback after the repo task is completed

        Returns:
            status_code: repo setting status
        """
        # it means it's a task for setting repo.
        host_ids = [task_info["host_id"]]
        data = dict(task_id=task_id,
                    status=task_info['status'], repo_name=task_info['repo_name'])
        status_code = self.proxy.update_repo_host_status_and_host_reponame(
            data, host_ids)

        if status_code != SUCCEED:
            LOGGER.debug(
                f"Setting repo name to hosts and upate repo host state failed, repo name: {task_info['repo_name']}, task id: {task_id}.")
            return DATABASE_UPDATE_ERROR

        return SUCCEED
