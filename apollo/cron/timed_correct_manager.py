#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
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
Description: 
"""
import datetime
import time
import sqlalchemy
from apollo.conf import configuration
from apollo.conf.constant import TIMED_TASK_CONFIG_PATH
from apollo.cron import TimedTaskBase
from apollo.cron.manager import get_timed_task_config_info
from apollo.database.proxy.task import TaskProxy
from vulcanus.log.log import LOGGER
from vulcanus.database.proxy import ElasticsearchProxy


class TimedCorrectTask(TimedTaskBase):
    """
    Timed correct data tasks
    """
    config_info = get_timed_task_config_info(TIMED_TASK_CONFIG_PATH)
    SERVICE_TIMEOUT_THRESHOLD_MIN = config_info.get(
        "correct_data").get("service_timeout_threshold_min", 15)

    @staticmethod
    def task_enter():
        """
        Start the correct after the specified time of day.
        """
        LOGGER.info("Begin to correct the whole host in %s.",
                    str(datetime.datetime.now()))
        try:
            with TaskProxy(configuration) as proxy:
                proxy.connect()
                abnormal_task_list, abnormal_host_list = TimedCorrectTask.get_abnormal_task(
                    proxy)
                proxy.update_repo_task_status(abnormal_task_list)
                proxy.update_cve_host_task_status(abnormal_task_list)
                proxy.update_host_status(abnormal_host_list)
        except sqlalchemy.exc.SQLAlchemyError:
            LOGGER.error("Connect to database fail.")

    @staticmethod
    def get_abnormal_task(proxy: TaskProxy):
        """
        Get abnormal tasks based on set thresholds and task creation time

        Args:
            proxy: Connected database proxy.

        Returns:
            list: The element of each list is the task ID
            list: The element of each list is the host ID
        """
        running_task_list, host_info_list = proxy.get_task_create_time()

        abnormal_task_list = []
        abnormal_host_list = []
        current_time = int(time.time())
        if running_task_list:
            for task_id, task_type, create_time in running_task_list:
                if current_time - int(create_time) >= int(TimedCorrectTask.SERVICE_TIMEOUT_THRESHOLD_MIN) * 60:
                    abnormal_task_list.append(task_id)

        if host_info_list:
            for host_id, last_scan in host_info_list:
                if current_time - int(last_scan) >= int(TimedCorrectTask.SERVICE_TIMEOUT_THRESHOLD_MIN) * 60:
                    abnormal_host_list.append(host_id)

        return abnormal_task_list, abnormal_host_list
