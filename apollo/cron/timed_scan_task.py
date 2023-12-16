#!/usr/bin/python3
# ******************************************************************************
# Copyright (c) Huawei Technologies Co., Ltd. 2021-2023. All rights reserved.
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
import uuid

import sqlalchemy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import SUCCEED
from vulcanus.timed import TimedTask

from apollo.conf.constant import HostStatus
from apollo.database.proxy.task.scan import ScanProxy
from apollo.handler.task_handler.manager.scan_manager import ScanManager


class TimedScanTask(TimedTask):
    """
    Timed scanning tasks
    """

    @staticmethod
    def _check_host_info(username, host_info):
        """
        Before start the scanning job for the user, check whether there are some
        hosts under scanning.

        Args:
            username (str)
            host_info (list)

        Returns:
            bool: check result
        """
        if len(host_info) == 0:
            LOGGER.info("There is no host info about user %s, ignore.", username)
            return False

        for host in host_info:
            if host["status"] == HostStatus.SCANNING:
                LOGGER.info("There are some hosts under scanning about user %s, ignore.", username)
                return False

        return True

    def execute(self):
        """
        Start the scan after the specified time of day.
        """
        LOGGER.info("Begin to scan the whole host in %s.", str(datetime.datetime.now()))

        # get the total host info first.
        try:
            with ScanProxy() as proxy:
                status, host_info_dict = proxy.get_total_host_info()
                if status != SUCCEED:
                    LOGGER.error("Query for host info failed, stop scanning.")
                    return

                # create works
                for username, host_info in host_info_dict['host_infos'].items():
                    if not self._check_host_info(username, host_info):
                        continue

                    task_id = str(uuid.uuid1()).replace('-', '')
                    # init status
                    cve_scan_manager = ScanManager(task_id, proxy, host_info, username, True)
                    cve_scan_manager.create_task()
                    if not cve_scan_manager.pre_handle():
                        continue
                    # run the tas in a thread
                    cve_scan_manager.execute_task()
        except sqlalchemy.exc.SQLAlchemyError:
            LOGGER.error("Connect to database fail.")
