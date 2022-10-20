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
Description: Task manager for cve scanning.
"""
import os
import re
import uuid
import datetime
import threading

from vulcanus.log.log import LOGGER
from vulcanus.restful.status import SUCCEED
from apollo.conf.constant import ANSIBLE_TASK_STATUS, CVE_SCAN_STATUS
from apollo.database import SESSION
from apollo.database.proxy.task import TaskMysqlProxy
from apollo.handler.task_handler.manager import Manager
from apollo.handler.task_handler.manager.task_manager import CveAnsible
from apollo.handler.task_handler.manager.playbook_manager import CveScanPlaybook
from apollo.handler.task_handler.callback.cve_scan import CveScanCallback
from apollo.handler.task_handler.config import cve_scan_time


class ScanManager(Manager):
    """
    Manager for scanning task
    """

    def __init__(self, task_id, proxy, host_info, username):
        """
        Args:
            task_id (str)
            proxy (object): proxy object of the database
            host_info (list)
            username (str)
        """
        self.host_list = [host['host_id'] for host in host_info]
        self.username = username
        self.pattern = re.compile(r'CVE-\d+-\d+')
        super().__init__(proxy, task_id, host_info)

    def pre_handle(self):
        """
        Init host scan status.

        Returns:
            bool
        """
        if self.proxy.init_host_scan(self.username, self.host_list) != SUCCEED:
            LOGGER.error(
                "Init the host status in database failed, stop scanning.")
            return False

        return True

    def handle(self):
        """
        Execute cve scan task.
        """
        LOGGER.info("Scanning task %s start to execute.", self.task_id)
        self.task = CveAnsible(inventory=self.inventory_path,
                               callback=CveScanCallback(self.username, self.proxy, self.task_info))
        self.task.playbook([self.playbook_path])
        LOGGER.info("Scanning task %s end.", self.task_id)

    def post_handle(self):
        """
        After executing the task, parse and save result to database.
        """
        LOGGER.debug(self.task.result)
        LOGGER.debug(self.task.info)

        result = {}
        for host_name, info in self.task.info.items():
            host_id = info['host_id']
            if self.task.result[host_name].get('scan') is not None and\
               self.task.result[host_name]['scan'].get('status') ==\
               ANSIBLE_TASK_STATUS.SUCCEED:
                scan_result = self.task.result[host_name]['scan']['info']
                cve_list = re.findall(self.pattern, scan_result)
                result[host_id] = list(set(cve_list))
            else:
                result[host_id] = []

        LOGGER.debug(result)
        # save the result to database and close database connection.
        self.proxy.save_scan_result(self.username, result)
        self.fault_handle()

    def fault_handle(self):
        """
        When the task is completed or execute fail, set the host status to 'unknown'.
        """
        self.proxy.update_scan_status(self.host_list)

    def __del__(self):
        """
        Destructor
        """
        self._delete_file()

    def _delete_file(self):
        """
        Clear local file when the task is quit
        """
        need_deleted_path = [self.playbook_path, self.inventory_path]
        for path in need_deleted_path:
            if os.path.exists(path):
                os.remove(path)

    @staticmethod
    def generate_playbook_and_inventory(host_info):
        """
        Generate playbook and inventory according to host info.

        Args:
            host_info (list)

        Returns:
            str: task id
        """
        task_id = str(uuid.uuid1()).replace('-', '')
        # generate playbook, dump to file.
        pb_manager = CveScanPlaybook(task_id, True)
        pb_manager.create_inventory(host_info)
        pb_manager.create_playbook()

        return task_id


class TimedScanManager:
    """
    Manager for timed task of cve scanning.
    """
    @staticmethod
    def _cve_scan_job(username, host_info):
        """
        A cve scanning job for a user.

        Args:
            username (str): [description]
            host_info (list): [description]

        Returns:
            bool: whether start the job succeed
            str: return username for recording the job info
        """
        proxy = TaskMysqlProxy()
        if not proxy.connect(SESSION):
            LOGGER.error("Connect to database fail, return.")
            return False, username

        task_id = ScanManager.generate_playbook_and_inventory(host_info)
        manager = ScanManager(task_id, proxy, host_info, username)
        manager.execute_task()
        return True, username

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
            LOGGER.info(
                "There is no host info about user %s, ignore.", username)
            return False

        for host in host_info:
            if host["status"] == CVE_SCAN_STATUS.SCANNING:
                LOGGER.info(
                    "There are some hosts under scanning about user %s, ignore.", username)
                return False

        return True

    @staticmethod
    def create_timed_scan_task():
        """
        Start the scan after the specified time of day.
        """
        LOGGER.info("Begin to scan the whole host in %s.",
                    str(datetime.datetime.now()))

        # get the total host info first.
        proxy = TaskMysqlProxy()
        if not proxy.connect(SESSION):
            LOGGER.error("Connect to database fail, return.")
            return

        res = proxy.get_total_host_info()
        if res[0] != SUCCEED:
            LOGGER.error("Query for host info failed, stop scanning.")
            return

        # create works
        works = []
        for username, host_info in res[1]['host_infos'].items():
            if TimedScanManager._check_host_info(username, host_info):
                work = threading.Thread(target=TimedScanManager._cve_scan_job,
                                        args=(username, host_info))
                work.start()
                works.append(work)

        for work in works:
            work.join()

    @staticmethod
    def add_timed_task(app):
        """
        Create timed task for cve scanning.

        Args:
            app (class): flask application
        """
        app.apscheduler.add_job(func=TimedScanManager.create_timed_scan_task,
                                id='cve scan timed task',
                                trigger='cron',
                                day_of_week="0-6",
                                hour=cve_scan_time)
        # trigger='interval',
        # seconds=5)