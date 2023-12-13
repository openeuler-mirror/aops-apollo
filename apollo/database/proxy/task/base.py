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
Description: vulnerability related database operation
"""
import json
import threading
from collections import defaultdict
from time import time
from typing import List, Tuple

import sqlalchemy.orm
from elasticsearch import ElasticsearchException
from sqlalchemy import case, func
from sqlalchemy.exc import SQLAlchemyError
from vulcanus.common import hash_value
from vulcanus.database.helper import sort_and_page, judge_return_code
from vulcanus.database.proxy import MysqlProxy, ElasticsearchProxy
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_DELETE_ERROR,
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
    SERVER_ERROR,
    PARTIAL_SUCCEED,
)

from apollo.conf.constant import TASK_INDEX, HostStatus, TaskStatus, TaskType
from apollo.database.table import (
    Cve,
    Task,
    CveFixTask,
    CveRollbackTask,
    HotpatchRemoveTask,
    TaskHostRepoAssociation,
    CveHostAssociation,
    CveAffectedPkgs,
    Host,
    User,
)
from apollo.function.customize_exception import EsOperationError


class TaskMysqlProxy(MysqlProxy):
    """
    Task related mysql table operation
    """

    lock = threading.Lock()

    def get_scan_host_info(self, username, host_list):
        """
        Query host info according to host id list.

        Args:
            username (str): user name
            host_list (list): host id list, can be empty

        Returns:
            list: host info, e.g.
                [
                    {
                        "host_id": 1,
                        "host_ip": "",
                        "host_name": "",
                        "status": ""
                    }
                ]
        """
        result = []
        try:
            result = self._get_host_info(username, host_list)
            LOGGER.debug("Finished getting host info.")
            return result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting host info failed due to internal error.")
            return result

    def _get_host_info(self, username, host_list):
        """
        get info of the host id in host_list. If host list is empty, query all hosts
        """
        filters = {Host.user == username}
        if host_list:
            filters.add(Host.host_id.in_(host_list))

        info_query = self.session.query(Host.host_id, Host.host_name, Host.host_ip, Host.status).filter(*filters)

        info_list = []
        for row in info_query:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "status": row.status,
            }
            info_list.append(host_info)
        return info_list

    def get_total_host_info(self):
        """
        Get the whole host info of each user.
        Args:

        Returns:
            int: status code
            dict: query result
        """
        temp_res = {}
        result = {"host_infos": temp_res}

        try:
            users = self.session.query(User).all()
            for user in users:
                name = user.username
                temp_res[name] = []
                for host in user.hosts:
                    host_info = {
                        "host_id": host.host_id,
                        "host_name": host.host_name,
                        "host_ip": host.host_ip,
                        "status": host.status,
                    }
                    temp_res[name].append(host_info)
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("query host basic info fail")
            return DATABASE_QUERY_ERROR, result

    def update_host_scan(self, status, host_list, username=None):
        """
        When the host need to be scanned, init the status to 'scanning',
        and update the last scan time to current time.
        Notice, if one host id doesn't exist, all hosts will not be scanned
        Args:
            status(str): init or finish
            host_list (list): host id list, if empty, scan all hosts
            username (str): user name
        Returns:
            int: status code
        """
        try:
            status_code = self._update_host_scan(update_type=status, host_list=host_list, username=username)
            self.session.commit()
            LOGGER.debug("Finished init host scan status.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init host scan status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _query_unaffected_cve(self, os_version: str, installed_packages: list):
        """
        query CVE information which has no effect on the version

        Args:
            os_version(str): OS version
            installed_packages(list): Scanned installed packages information,
                e.g: ["pkg1", "pkg2", "pkg3"]

        Returns:
            list: list of cve info

        """
        installed_packages_cve = (
            self.session.query(CveAffectedPkgs)
            .filter(
                CveAffectedPkgs.os_version == os_version,
                CveAffectedPkgs.package.in_(installed_packages),
                CveAffectedPkgs.affected == False,
            )
            .all()
        )
        return installed_packages_cve

    def save_cve_scan_result(self, task_info: dict) -> int:
        """
        Save cve scan result to database.
        Args:
            task_info (dict): task info, e.g.
                {
                    "task_id": "string",
                    "host_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "os_version": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "installed_packages": [
                        {
                            "name": "string",
                            "version": true
                        }
                    ],
                    "unfixed_cves":[
                        {
                            "cve_id": "CVE-2023-1513",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "available_rpm":"kernel-4.19.90-2304.1.0.0196.oe1.x86_64",
                            "support_way":"hotpatch/coldpatch/none"
                        }
                    ],
                    "fixed_cves": [
                        {
                            "cve_id": "CVE-2022-4904",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "fix_way": "hotpatch/coldpatch",
                            "hp_status": "ACCEPTED/ACTIVED"
                        }
                    ],
                    "reboot": true/false
                }
        Returns:
            int: status code
        """
        try:
            status = task_info["status"]
            if status == TaskStatus.SUCCEED:
                self._save_cve_scan_result(task_info)
            else:
                LOGGER.info(f"scan result failed with status {status}.")

            status_code = self._update_host_scan("finish", [task_info["host_id"]], task_info.get("reboot"))
            self.session.commit()
            LOGGER.debug("Finish saving scan result.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Save cve scan result failed.")
            return DATABASE_INSERT_ERROR

    def _save_cve_scan_result(self, task_info: dict):
        """
        Save cve scan result to database.
        Args:
            task_info (dict): task info, e.g.
                {
                    "task_id": "string",
                    "host_id": "string",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "string",
                    "os_version": "string",
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "installed_packages": [
                        {
                            "name": "string",
                            "version": true
                        }
                    ],
                    "unfixed_cves":[
                        {
                            "cve_id": "CVE-2023-1513",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "available_rpm":"kernel-4.19.90-2304.1.0.0196.oe1.x86_64",
                            "support_way":"hotpatch/coldpatch/none"
                        }
                    ],
                    "fixed_cves": [
                        {
                            "cve_id": "CVE-2022-4904",
                            "installed_rpm":"kernel-4.19.90-2304.1.0.0131.oe1.x86_64",
                            "fix_way": "hotpatch/coldpatch",
                            "hp_status": "ACCEPTED/ACTIVED"
                        }
                    ],
                }
        Returns:
            int: status code
            list: list of unfixed cve
        """

        host_id = task_info["host_id"]
        installed_packages = [package["name"] for package in task_info["installed_packages"]]
        os_version = task_info["os_version"]

        waiting_to_save_cve_info = []

        for unaffected_cve in self._query_unaffected_cve(os_version, installed_packages):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": unaffected_cve.cve_id,
                    "host_id": host_id,
                    "affected": False,
                }
            )

        for unfixed_vulnerability_info in task_info.get("unfixed_cves"):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": unfixed_vulnerability_info.get("cve_id"),
                    "host_id": host_id,
                    "affected": True,
                    "fixed": False,
                    "support_way": unfixed_vulnerability_info.get("support_way") or None,
                    "installed_rpm": unfixed_vulnerability_info.get("installed_rpm") or None,
                    "available_rpm": unfixed_vulnerability_info.get("available_rpm") or None,
                }
            )

        for fixed_vulnerability_info in task_info.get("fixed_cves", []):
            waiting_to_save_cve_info.append(
                {
                    "cve_id": fixed_vulnerability_info.get("cve_id"),
                    "host_id": host_id,
                    "affected": True,
                    "fixed": True,
                    "fixed_way": fixed_vulnerability_info.get("fix_way"),
                    "installed_rpm": fixed_vulnerability_info.get("installed_rpm"),
                    "hp_status": fixed_vulnerability_info.get("hp_status"),
                }
            )
        with self.lock:
            self.session.query(CveHostAssociation).filter(CveHostAssociation.host_id == host_id).delete(
                synchronize_session=False
            )
            self.session.commit()

        self.session.bulk_insert_mappings(CveHostAssociation, waiting_to_save_cve_info)

    def _get_unaffected_cve(self, cves: list, os_version: str) -> list:
        """
        Get the unaffected CVEs.
        Args:
            cves (list): CVE list, e.g.
                ["CVE-1999-20304", "CVE-1999-20303", "CVE-1999-20301"]
            os_version(str): os version, e.g. "openEuler-22.03-LTS"

        Returns:
            list: unaffected CVEs
        """
        os_unaffected_cve_list = self._get_os_unaffected_cve(os_version)

        unaffected_cve_list = []
        for cve in cves:
            if cve in os_unaffected_cve_list:
                unaffected_cve_list.append(cve)

        return unaffected_cve_list

    def _get_os_unaffected_cve(self, os_version: str) -> list:
        """
        Query the unaffected cves under the os.
        Args:
            os_version(str):e.g. "openEuler-22.03-LTS"

        Returns:
            list: CVE list, e.g.
                ['CVE-2018-16301', 'CVE-2019-10301', 'CVE-2019-11301']
        """
        cves_list_query = (
            self.session.query(CveAffectedPkgs.cve_id)
            .filter(CveAffectedPkgs.os_version == os_version, CveAffectedPkgs.affected == 0)
            .all()
        )

        cve_list = []
        if cves_list_query:
            cve_list = [cve[0] for cve in cves_list_query]

        return cve_list

    def _update_host_scan(self, update_type, host_list, reboot=False, username=None):
        """
        Update hosts scan status and last_scan time
        Args:
            update_type (str): 'init' or 'finish'
            host_list (list): host id list
            reboot (bool): host restart status
            username (str): user name
        Returns:

        """
        if update_type == "init":
            update_dict = {Host.status: HostStatus.SCANNING, Host.last_scan: int(time())}
        elif update_type == "finish":
            update_dict = {Host.status: HostStatus.DONE, Host.reboot: reboot}
        else:
            LOGGER.error(
                "Given host scan update type '%s' is not in default type list ['init', 'finish']." % update_type
            )
            return SERVER_ERROR

        host_scan_query = self._query_scan_status_and_time(host_list, username)
        succeed_list = [row.host_id for row in host_scan_query]
        fail_list = set(host_list) - set(succeed_list)
        if fail_list:
            LOGGER.debug("No data found when setting the status of host: %s." % fail_list)
            if update_type == "init":
                return NO_DATA

        # update() is not applicable to 'in_' method without synchronize_session=False
        host_scan_query.update(update_dict, synchronize_session=False)
        return SUCCEED

    def _query_scan_status_and_time(self, host_list, username):
        """
        query host status and last_scan data of specific user
        Args:
            host_list (list): host id list, when empty, query all hosts
            username (str/None): user name
        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = set()
        if host_list:
            filters.add(Host.host_id.in_(host_list))
        if username:
            filters.add(Host.user == username)

        hosts_status_query = self.session.query(Host).filter(*filters)
        return hosts_status_query

    def get_task_list(self, data):
        """
        Get the task list.
        Args:
            data (dict): parameter, e.g.
                {
                    "username": "admin",
                    "sort": "host_num",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "filter": {
                        "task_name": "task2",
                        "task_type": ["repo set"]
                    }
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [
                        {
                            "task_id": "id1",
                            "task_name": "task1",
                            "task_type": "cve fix",
                            "description": "a long description",
                            "host_num": 12,
                            "create_time": 1111111111
                        }
                    ]
                }
        """
        result = {}
        try:
            result = self._get_processed_task_list(data)
            LOGGER.debug("Finished getting task list.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task list failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_list(self, data):
        """
        Get sorted, paged and filtered task list.

        Args:
            data(dict): sort, page and filter info

        Returns:
            dict
        """
        result = {"total_count": 0, "total_page": 0, "result": []}

        filters = self._get_task_list_filters(data.get("filter"))
        task_list_query = self._query_task_list(data["username"], filters)

        total_count = task_list_query.count()
        if not total_count:
            return result

        sort_column = getattr(Task, data.get("sort")) if "sort" in data else None
        direction, page, per_page = data.get('direction'), data.get('page'), data.get('per_page')

        processed_query, total_page = sort_and_page(task_list_query, sort_column, direction, per_page, page)

        result['result'] = self._task_list_row2dict(processed_query)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    def _query_task_list(self, username, filters):
        """
        query needed task list
        Args:
            username (str): user name of the request
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_list_query = (
            self.session.query(
                Task.task_id, Task.task_name, Task.task_type, Task.description, Task.host_num, Task.create_time
            )
            .filter(Task.username == username)
            .filter(*filters)
        )
        return task_list_query

    @staticmethod
    def _task_list_row2dict(rows):
        result = []
        for row in rows:
            task_info = {
                "task_id": row.task_id,
                "task_name": row.task_name,
                "task_type": row.task_type,
                "description": row.description,
                "host_num": row.host_num,
                "create_time": row.create_time,
            }
            result.append(task_info)
        return result

    @staticmethod
    def _get_task_list_filters(filter_dict):
        """
        Generate filters

        Args:
            filter_dict(dict): filter dict to filter cve list, e.g.
                {
                    "task_name": "task2",
                    "task_type": ["cve fix", "repo set", "cve scan"]
                }

        Returns:
            set
        """
        filters = set()
        if not filter_dict:
            return filters

        if filter_dict.get("task_name"):
            filters.add(Task.task_name.like("%" + filter_dict["task_name"] + "%"))
        if filter_dict.get("task_type"):
            filters.add(Task.task_type.in_(filter_dict["task_type"]))
        return filters

    def get_task_progress(self, data):
        """
        Get the task progress.
        Args:
            data (dict): parameter, e.g.
                {
                    "task_list": ["task1", "task2"],
                    "username": "admin"
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "task1": {
                            "succeed": 1,
                            "fail": 0,
                            "running": 11,
                            "unknown": 0
                        },
                        "task2": {
                            "succeed": 12,
                            "fail": 0,
                            "running": 0,
                            "unknown": 0
                        }
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_progress(data)
            LOGGER.debug("Finished getting task progress.")
            return status_code, result
        except (SQLAlchemyError, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting task progress failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_progress(self, data: dict):
        """
        Get each task's progress
        Args:
            data (dict): task list info

        Returns:
            int: status code
            dict: query result
        """
        task_list = data["task_list"]
        username = data["username"]
        repo_task, cve_task, cve_rollback_task, hp_remove_task = self._split_task_list(username, task_list)

        result = {}
        result.update(self._get_repo_task_progress(repo_task))
        result.update(self._get_cve_series_task_progress(cve_task, TaskType.CVE_FIX))
        result.update(self._get_cve_series_task_progress(cve_rollback_task, TaskType.CVE_ROLLBACK))
        result.update(self._get_cve_series_task_progress(hp_remove_task, TaskType.HOTPATCH_REMOVE))

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.debug("No data found when getting the progress of task: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": result}

    def _split_task_list(self, username: str, task_list: list) -> Tuple[list, list, list, list]:
        """
        split task list based on task's type
        Args:
            username (str): user name
            task_list (list): task id list

        Returns:
            list: repo task list
            list: cve task list
            liST: cve rollback task list
            list: hotpatch remove task list
        """
        repo_task = []
        cve_task = []
        cve_rollback_task = []
        hp_remove_task = []

        # filter task's type in case of other type added into task table
        task_query = self.session.query(Task.task_id, Task.task_type).filter(
            Task.username == username,
            Task.task_id.in_(task_list),
            Task.task_type.in_(TaskType.attribute()),
        )

        for row in task_query:
            if row.task_type == TaskType.REPO_SET:
                repo_task.append(row.task_id)
            elif row.task_type == TaskType.CVE_FIX:
                cve_task.append(row.task_id)
            elif row.task_type == TaskType.CVE_ROLLBACK:
                cve_rollback_task.append(row.task_id)
            elif row.task_type == TaskType.HOTPATCH_REMOVE:
                hp_remove_task.append(row.task_id)
        return repo_task, cve_task, cve_rollback_task, hp_remove_task

    @staticmethod
    def _get_status_result():
        def status_dict():
            return {TaskStatus.SUCCEED: 0, TaskStatus.FAIL: 0, TaskStatus.RUNNING: 0, TaskStatus.UNKNOWN: 0}

        return defaultdict(status_dict)

    def _get_cve_series_task_progress(self, task_list: list, task_type: str):
        """
        get progress of cve fix task or cve rollback task or hotpatch remove task
        Args:
            task_list (list): cve tasks' id list
            task_type (str): type of cve series tasks.

        Returns:
            dict: e.g.
                {"task1": {"succeed": 1, "fail": 0, "running": 10, "unknown": 1}}

        Raises:
            KeyError
        """

        def defaultdict_set():
            return defaultdict(set)

        task_table_map = {
            TaskType.CVE_FIX: CveFixTask,
            TaskType.CVE_ROLLBACK: CveRollbackTask,
            TaskType.HOTPATCH_REMOVE: HotpatchRemoveTask,
        }
        tasks_dict = defaultdict(defaultdict_set)
        result = self._get_status_result()

        task_query = self._query_cve_series_task_host_status(task_list, task_table_map[task_type])
        for row in task_query:
            tasks_dict[row.task_id][row.host_id].add(row.status)

        for task_id, hosts_dict in tasks_dict.items():
            for status_set in hosts_dict.values():
                host_status = self._get_cve_task_status(status_set)
                result[task_id][host_status] += 1

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.error("CVE task '%s' exist but status data is not record." % fail_list)
        return result

    def _query_cve_series_task_host_status(self, task_list: list, task_table):
        """
        query host status of cve fix task or cve rollback task or hotpatch remove task
        Args:
            task_list (list): task id list
            task_table (sqlalchemy table): table of cve series tasks. Pay attention, the table must have "task_id",
                "host_id" and "status" columns

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_query = self.session.query(task_table.task_id, task_table.host_id, task_table.status).filter(
            task_table.task_id.in_(task_list)
        )
        return task_query

    @staticmethod
    def _get_cve_task_status(status_set: set):
        """
        get cve task's host or cve's overall status
        Args:
            status_set (set): host or cve's status set

        Returns:
            str
        """
        if TaskStatus.RUNNING in status_set:
            return TaskStatus.RUNNING
        if TaskStatus.UNKNOWN in status_set:
            return TaskStatus.UNKNOWN
        if TaskStatus.FAIL in status_set:
            return TaskStatus.FAIL
        return TaskStatus.SUCCEED

    def _get_repo_task_progress(self, task_list):
        """
        get repo tasks' progress
        Args:
            task_list (list): repo tasks' id list

        Returns:
            dict: e.g.
                {"task1": {"succeed": 1, "fail": 0, "running": 10, "unknown": 1}}

        Raises:
            KeyError
        """
        result = self._get_status_result()

        task_query = self._query_repo_task_host(task_list)
        for row in task_query:
            if row.status == TaskStatus.SUCCEED:
                result[row.task_id][TaskStatus.SUCCEED] += 1
            elif row.status == TaskStatus.FAIL:
                result[row.task_id][TaskStatus.FAIL] += 1
            elif row.status == TaskStatus.RUNNING:
                result[row.task_id][TaskStatus.RUNNING] += 1
            elif row.status == TaskStatus.UNKNOWN:
                result[row.task_id][TaskStatus.UNKNOWN] += 1
            else:
                LOGGER.error("Unknown repo task's host status '%s'" % row.status)

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.error("Repo task '%s' exist but status data is not record." % fail_list)
        return result

    def _query_repo_task_host(self, task_list):
        """
        query host and CVE's relationship and status of required tasks
        Args:
            task_list (list): task id list

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_query = self.session.query(TaskHostRepoAssociation.task_id, TaskHostRepoAssociation.status).filter(
            TaskHostRepoAssociation.task_id.in_(task_list)
        )
        return task_query

    def get_task_info(self, data):
        """
        Get a task's info
        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "username": "admin"
                }
        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "task_name": "task",
                        "description": "a long description",
                        "host_num": 2,
                        "latest_execute_time": 1111111111,
                        "accept": true,
                        "takeover": false
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_info(data)
            LOGGER.debug("Finished getting task info.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_info(self, data):
        """
        query and process task info
        Args:
            data (dict): task id info

        Returns:
            int: status code
            dict: query result
        """
        task_id = data["task_id"]
        username = data["username"]

        task_info_data = (
            self.session.query(
                Task.task_name, Task.description, Task.host_num, Task.latest_execute_time, Task.accepted, Task.takeover
            )
            .filter(Task.task_id == task_id, Task.username == username)
            .first()
        )

        if not task_info_data:
            LOGGER.debug("No data found when getting the info of task: %s." % task_id)
            return NO_DATA, {"result": {}}

        # raise exception when multiple record found
        info_dict = self._task_info_row2dict(task_info_data)
        return SUCCEED, {"result": info_dict}

    @staticmethod
    def _task_info_row2dict(row):
        task_info = {
            "task_name": row.task_name,
            "description": row.description,
            "host_num": row.host_num,
            "latest_execute_time": row.latest_execute_time,
            "accept": row.accepted,
            "takeover": row.takeover,
        }
        return task_info

    def fix_task_status(self, task_id, task_type):
        """
        After executing the task, in case that internal error occured, set the status of
        running host in the task to 'unknown'.

        Args:
            task_id (str)
            task_type (str)

        Returns:
            int: status code
        """
        try:
            status_code = self._set_failed_task_status(task_id, task_type)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished setting task %s status to unknown." % task_id)
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting task %s status to unknown failed due to internal error." % task_id)
            return DATABASE_UPDATE_ERROR

    def _set_failed_task_status(self, task_id, task_type):
        """
        set failed task's running hosts' status to "unknown"
        """
        if task_type == TaskType.CVE_FIX or task_type == TaskType.CVE_ROLLBACK:
            host_query = self.session.query(HotpatchRemoveTask).filter(
                HotpatchRemoveTask.task_id == task_id, HotpatchRemoveTask.status == TaskStatus.RUNNING
            )
            host_query.update({HotpatchRemoveTask.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        elif task_type == TaskType.REPO_SET:
            host_query = self.session.query(TaskHostRepoAssociation).filter(
                TaskHostRepoAssociation.task_id == task_id, TaskHostRepoAssociation.status == TaskStatus.RUNNING
            )
            host_query.update({TaskHostRepoAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        else:
            LOGGER.error("Unknown task type '%s' when setting its status." % task_type)
            return SERVER_ERROR

        return SUCCEED

    def get_task_type(self, task_id, username):
        """
        Return the type of the task, return None if check failed.

        Args:
            task_id (str): task id
            username (str): user name

        Returns:
            int
            str or None
        """
        try:
            status_code, task_type = self._get_task_type(task_id, username)
            if status_code == SUCCEED:
                LOGGER.debug("Finished getting task's type.")
            return task_type
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task's type failed due to internal error.")
            return None

    def _get_task_type(self, task_id, username):
        """
        query task's type.
        """
        type_query = self.session.query(Task.task_type).filter(Task.task_id == task_id, Task.username == username)

        if not type_query.count():
            LOGGER.error("Querying type of task '%s' failed due to no data found." % task_id)
            return NO_DATA, None
        if type_query.count() > 1:
            LOGGER.error("Querying type of task '%s' failed due to internal error." % task_id)
            return DATABASE_QUERY_ERROR, None

        task_type = type_query.one().task_type
        return SUCCEED, task_type

    def update_task_execute_time(self, task_id, cur_time):
        """
        Update task latest execute time when task is executed
        Args:
            task_id (str): task id
            cur_time (int): latest execute time

        Returns:
            int: status code
        """
        try:
            status_code = self._update_latest_execute_time(task_id, cur_time)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished updating task's latest execute time.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating task's latest execute time failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_latest_execute_time(self, task_id, cur_time):
        """
        update a task's latest execute time
        """
        status_query = self.session.query(Task).filter(Task.task_id == task_id)

        if not status_query.count():
            LOGGER.error("Updating latest execute time of task '%s' failed due to no data found." % task_id)
            return NO_DATA
        if status_query.count() > 1:
            LOGGER.error("Updating latest execute time of task '%s' failed due to internal error." % task_id)
            return DATABASE_UPDATE_ERROR

        status_query.one().latest_execute_time = cur_time
        return SUCCEED

    def check_task_status(self, task_id, task_type):
        """
        check the task is open for execute or not
        Args:
            task_id (str): task id
            task_type (str): for now, 'cve fix' or 'repo set' or 'cve rollback' or 'hotpatch remove'

        Returns:
            bool
        """
        if task_type in [TaskType.CVE_FIX, TaskType.CVE_ROLLBACK, TaskType.HOTPATCH_REMOVE]:
            task_progress = self._get_cve_series_task_progress([task_id], task_type)
        elif task_type == TaskType.REPO_SET:
            task_progress = self._get_repo_task_progress([task_id])
        else:
            LOGGER.error("Unknown task type '%s' was given when checking task '%s' status." % (task_type, task_id))
            return True

        if task_progress[task_id][TaskStatus.RUNNING]:
            return False
        return True

    def query_user_email(self, username: str) -> tuple:
        """
        query user email from database by username

        Args:
            username(str)

        Returns:
            str: status_code
            str: email address
        """
        try:
            user = self.session.query(User).filter(User.username == username).one()
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_QUERY_ERROR, ""

        return SUCCEED, user.email

    def query_host_cve_info(self, username: str) -> Tuple[str, list]:
        """
        query cve info with host info from database

        Args:
            username (str)

        Returns:
            Tuple[str, list]
            a tuple containing two elements (status code, host with its cve info list).
        """
        try:
            host_cve_info_list = self._quer_processed_host_cve_info(username)
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_QUERY_ERROR, []

        return SUCCEED, host_cve_info_list

    def _quer_processed_host_cve_info(self, username: str) -> List[dict]:
        """
        query and process host with its cve info

        Args:
            username(str)

        Returns:
            list: host cve info list. e.g
                [{
                    "host_id": 1,
                    "host_ip": "127.0.0.1",
                    "host_name": "client",
                    "cve_id": "CVE-XXXX-XXXX",
                    "cvss_score": 7.5,
                    "severity": "Important",
                    "installed_rpm": "rpm-name-6.2.5-1.x86_64",
                    "source_package": {"rpm-name.src.rpm"},
                    "available_rpms": {"rpm-name-6.2.5-2.x86_64","patch-rpm-name-6.2.5-1-ACC...."},
                    "support_ways": {"hotpatch", "coldpatch"},
                }]
        """
        subquery = (
            self.session.query(
                CveHostAssociation.host_id,
                CveHostAssociation.cve_id,
                CveHostAssociation.installed_rpm,
                CveHostAssociation.available_rpm,
                CveHostAssociation.support_way,
                case([(Cve.cvss_score == None, "-")], else_=Cve.cvss_score).label("cvss_score"),
                case([(Cve.severity == None, "-")], else_=Cve.severity).label("severity"),
                case([(CveAffectedPkgs.package == None, "-")], else_=CveAffectedPkgs.package).label("package"),
            )
            .outerjoin(Cve, Cve.cve_id == CveHostAssociation.cve_id)
            .outerjoin(CveAffectedPkgs, CveAffectedPkgs.cve_id == CveHostAssociation.cve_id)
            .filter(CveHostAssociation.affected == True, CveHostAssociation.fixed == False)
            .subquery()
        )

        query_rows = (
            self.session.query(
                Host.host_ip,
                Host.host_name,
                subquery.c.host_id,
                subquery.c.cve_id,
                subquery.c.installed_rpm,
                func.ifnull(subquery.c.available_rpm, "-").label("available_rpm"),
                func.ifnull(subquery.c.support_way, "-").label("support_way"),
                subquery.c.cvss_score,
                subquery.c.severity,
                func.ifnull(subquery.c.package, "-").label("package"),
            )
            .outerjoin(subquery, Host.host_id == subquery.c.host_id)
            .filter(Host.user == username)
            .all()
        )

        host_cve_info = self._host_cve_info_rows_to_dict(query_rows)
        return host_cve_info

    @staticmethod
    def _host_cve_info_rows_to_dict(rows: list) -> List[dict]:
        """
        turn query rows to dict

        Args:
            rows(list): sqlalchemy query result list

        Returns:
            list
        """
        result = dict()

        for row in rows:
            key = f"{row.host_id}-{row.cve_id}-{row.installed_rpm}"

            if key in result:
                result[key]["available_rpms"].add(row.available_rpm)
                result[key]["support_ways"].add(row.support_way)
                result[key]["source_package"].add(row.package)
            else:
                result[key] = {
                    "host_id": row.host_id,
                    "host_ip": row.host_ip,
                    "host_name": row.host_name,
                    "cve_id": row.cve_id,
                    "cvss_score": row.cvss_score,
                    "severity": row.severity,
                    "installed_rpm": row.installed_rpm,
                    "source_package": {row.package},
                    "available_rpms": {row.available_rpm},
                    "support_ways": {row.support_way},
                }

        return list(result.values())


class TaskEsProxy(ElasticsearchProxy):
    def save_task_info(self, task_id, host_id, log, **kwargs):
        """
         Every time log are generated, save them to es database.

        Args:
            task_id (str): task id
            log (str): task's log

        Returns:
            int: status code
        """
        if not log:
            LOGGER.warning("task log to be inserted is empty")
            return DATABASE_INSERT_ERROR
        task_body = {"task_id": task_id, "host_id": host_id, "log": log}
        task_body.update(**kwargs)
        document_id = hash_value(str(task_id) + "_" + str(host_id))
        operation_code, exists = self.exists(TASK_INDEX, document_id=document_id)
        if not operation_code:
            LOGGER.error("Failed to query whether the task exists or not due to internal error")
            return DATABASE_INSERT_ERROR

        if exists:
            operation_code = self.update_bulk(TASK_INDEX, [{"_id": document_id, "doc": task_body}])
        else:
            operation_code = TaskEsProxy.insert(self, index=TASK_INDEX, body=task_body, document_id=document_id)

        if operation_code:
            LOGGER.debug("Finished saving task info into es.")
            return SUCCEED

        LOGGER.error("Saving task info into es failed due to internal error.")
        return DATABASE_INSERT_ERROR

    def _query_task_info_from_es(self, task_id, host_id=None, username=None, source=True):
        """
        query task's info from elasticsearch
        Args:
            task_id (str): task id
            host_id (int): host id
            username (str/None): user name, used for authorisation check
            source (bool/list): list of source

        Returns:
            bool
            dict
        """
        query_body = self._general_body()
        query_body.update({"from": 0, "size": 10000})
        query_body['query']['bool']['must'].append({"term": {"task_id": task_id}})
        if username:
            query_body['query']['bool']['must'].append({"term": {"username": username}})
        if host_id:
            query_body['query']['bool']['must'].append({"term": {"host_id": host_id}})

        operation_code, res = self.query(TASK_INDEX, query_body, source)
        return operation_code, res

    def get_task_log_info(self, task_id, host_id=None, username=None) -> Tuple[int, list]:
        """
        Get task's info (log) from es

        Args:
            task_id (str): task id
            username (str): user name, used for authorisation check

        Returns:
            int: status code
            list: needed task log info
        """

        operation_code, res = self._query_task_info_from_es(task_id, host_id, username, ["log"])

        if not operation_code:
            LOGGER.debug("Querying log info of task host '%s' failed due to internal error." % task_id)
            return DATABASE_QUERY_ERROR, []

        if not res["hits"]["hits"]:
            LOGGER.debug("No data found when getting log info of task '%s'." % task_id)
            return NO_DATA, []

        task_infos = [json.loads(task_info["_source"]["log"]) for task_info in res["hits"]["hits"]]

        LOGGER.debug("Querying task log succeed.")
        return SUCCEED, task_infos


class TaskProxy(TaskMysqlProxy, TaskEsProxy):
    def __init__(self, host=None, port=None):
        """
        Instance initialization

        Args:
            configuration (Config)
            host(str)
            port(int)
        """
        TaskMysqlProxy.__init__(self)
        TaskEsProxy.__init__(self, host, port)

    def delete_task(self, data):
        """
        Delete task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_list": []
                }

        Returns:
            int: status code
            task id: running task id list
        """
        try:
            running_task = self._delete_task(data)
            self.session.commit()
            if running_task:
                return PARTIAL_SUCCEED, running_task

            LOGGER.debug("Finished deleting task.")
            return SUCCEED, running_task
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Deleting task failed due to internal error.")
            return DATABASE_DELETE_ERROR, None

    def _delete_task(self, data):
        """
        Delete task's info from both mysql and es.
        Args:
            data (dict): task list info

        Returns:
            running_task: running task id list
        Raises:
            ElasticsearchException
        """
        username = data["username"]
        task_list = data["task_list"]
        deleted_task, running_task = self._delete_task_from_mysql(username, task_list)
        self._delete_task_from_es(username, deleted_task)
        return running_task

    def _delete_task_from_mysql(self, username, task_list):
        """
        Delete task from Task table in mysql, related rows in other tables will also be deleted.
        Args:
            username (str): user name
            task_list (list): task id list

        Returns:
            wait_delete_task_list: deleted task id list
            running_task_id_list: running task id list
        """
        task_query = self.session.query(Task).filter(Task.username == username, Task.task_id.in_(task_list))

        succeed_list = [row.task_id for row in task_query]
        fail_list = list(set(task_list) - set(succeed_list))
        # query running tasks
        running_tasks = (
            self.session.query(HotpatchRemoveTask.task_id)
            .filter(HotpatchRemoveTask.status == TaskStatus.RUNNING, HotpatchRemoveTask.task_id.in_(task_list))
            .union(
                self.session.query(TaskHostRepoAssociation.task_id).filter(
                    TaskHostRepoAssociation.task_id.in_(task_list), TaskHostRepoAssociation.status == TaskStatus.RUNNING
                )
            )
            .union(
                self.session.query(CveFixTask.task_id).filter(
                    CveFixTask.task_id.in_(task_list), CveFixTask.status == TaskStatus.RUNNING
                )
            )
            .all()
        )
        running_task_id_list = [task.task_id for task in running_tasks]

        if fail_list:
            LOGGER.debug("No data found when deleting the task '%s' from mysql." % fail_list)
        if running_task_id_list:
            LOGGER.warning("A running task exists, tasks id: %s." % " ".join(running_task_id_list))

        wait_delete_task_list = list(set(succeed_list) - set(running_task_id_list))
        self.session.query(Task).filter(Task.task_id.in_(wait_delete_task_list)).delete(synchronize_session=False)
        LOGGER.debug("Delete task from mysql succeed.")
        return wait_delete_task_list, running_task_id_list

    def _delete_task_from_es(self, username, task_list):
        """
        Delete task from elasticsearch's 'task' index
        Args:
            username (str): user name
            task_list (list): task id list

        Raises:
            EsOperationError
        """
        query_body = self._general_body()
        query_body["query"]["bool"]["must"].extend([{"terms": {"_id": task_list}}, {"term": {"username": username}}])

        res = TaskEsProxy.delete(self, TASK_INDEX, query_body)
        if res:
            LOGGER.debug("Delete task from elasticsearch succeed.")
            return

        raise EsOperationError("Delete task from elasticsearch failed due to internal error.")

    def get_running_task_form_task_cve_host(self) -> list:
        """
        Get all CVE repair tasks with running status under Username

        Returns:
            list: task id list
        """
        task_cve_query = (
            self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.status == TaskStatus.RUNNING).all()
        )
        task_id_list = [task.task_id for task in task_cve_query]
        return task_id_list

    def get_running_task_form_task_host_repo(self) -> list:
        """
        Get all repo set tasks with running status under Username

        Returns:
            list: task id list
        """
        host_repo_query = (
            self.session.query(TaskHostRepoAssociation)
            .filter(TaskHostRepoAssociation.status == TaskStatus.RUNNING)
            .all()
        )
        task_id_list = [task.task_id for task in host_repo_query]
        return task_id_list

    def get_scanning_status_and_time_from_host(self) -> list:
        """
        Get all host id and time with scanning status from the host table

        Returns:
            list: host id list
        """
        host_info_query = self.session.query(Host).filter(Host.status == HostStatus.SCANNING).all()
        host_info_list = [(host.host_id, host.last_scan) for host in host_info_query]
        return host_info_list

    def get_task_create_time(self):
        """
        Get the creation time for each running task

        Returns:
            list: Each element is a task information, including the task ID, task type, creation time
        """
        task_cve_id_list = self.get_running_task_form_task_cve_host()
        task_repo_id_list = self.get_running_task_form_task_host_repo()
        host_info_list = self.get_scanning_status_and_time_from_host()
        task_id_list = task_cve_id_list + task_repo_id_list

        task_query = self.session.query(Task).filter(Task.task_id.in_(task_id_list)).all()
        running_task_list = [(task.task_id, task.create_time) for task in task_query]
        return running_task_list, host_info_list

    def update_host_status(self, host_id_list: list):
        """
        Change the status of the exception service to succeed

        Args:
            host_id_list: A list of IDs for the exception host

        Returns:
            int: status_code
        """
        host_query = self.session.query(Host).filter(Host.host_id.in_(host_id_list))
        try:
            host_query.update({Host.status: HostStatus.UNKNOWN}, synchronize_session=False)
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update host table status failed.")
            return DATABASE_UPDATE_ERROR

        self.session.commit()

        return SUCCEED

    def update_task_status(self, task_id_list: list):
        """
        Change the status of the exception service to succeed

        Args:
            task_id_list: A list of IDs for the exception task

        Returns:
            int: status_code
        """
        cve_task_query = self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.task_id.in_(task_id_list))
        try:
            cve_task_query.update({HotpatchRemoveTask.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_UPDATE_ERROR

        repo_task_query = self.session.query(TaskHostRepoAssociation).filter(
            TaskHostRepoAssociation.task_id.in_(task_id_list)
        )
        try:
            repo_task_query.update({TaskHostRepoAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update task_host_repo table status failed.")
            return DATABASE_UPDATE_ERROR

        self.session.commit()

        return SUCCEED

    def update_repo_task_status(self, task_id_list: list):
        """
        Change the status of the exception service to unknown

        Args:
            task_id_list: A list of IDs for the exception task

        Returns:
            int: status_code
        """

        repo_task_query = self.session.query(TaskHostRepoAssociation).filter(
            TaskHostRepoAssociation.task_id.in_(task_id_list)
        )
        try:
            repo_task_query.update({TaskHostRepoAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update task_host_repo table status failed.")
            return DATABASE_UPDATE_ERROR

        return SUCCEED

    def update_cve_host_task_status(self, task_id_list: list):
        """
        Change the status of the exception service to unknown

        Args:
            task_id_list: A list of IDs for the exception task

        Returns:
            int: status_code
        """
        cve_task_query = self.session.query(HotpatchRemoveTask).filter(HotpatchRemoveTask.task_id.in_(task_id_list))
        try:
            cve_task_query.update({HotpatchRemoveTask.status: TaskStatus.UNKNOWN}, synchronize_session=False)
            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_UPDATE_ERROR

        return SUCCEED

    def validate_cves(self, cve_id: list) -> bool:
        """
        Verifying cve validity

        Args:
            cve_id: id of the cve to be validate

        Returns:
            bool:  A return of true indicates that the validation passed
        """

        try:
            exists_cve_count = (
                self.session.query(CveHostAssociation.cve_id)
                .filter(CveHostAssociation.cve_id.in_(cve_id))
                .distinct()
                .count()
            )

            return True if exists_cve_count == len(cve_id) else False
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return False

    def validate_hosts(self, host_id: list, username=None) -> bool:
        """
        Verifying host validity

        Args:
            host_id: id of the host to be validate
            username: system user name

        Returns:
            bool:  A return of true indicates that the validation passed
        """
        try:
            exists_host_query = self.session.query(Host).filter(Host.host_id.in_(host_id))
            if username:
                exists_host_query.filter(Host.user == username)
            exists_host_count = exists_host_query.count()
            return True if exists_host_count == len(host_id) else False
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return False

    def _query_task_basic_info(self, task_id: str) -> sqlalchemy.orm.Query:
        """
        query basic task info

        Args:
            task_id

        Returns:
            sqlalchemy.orm.Query
        """
        task_query = self.session.query(
            Task.task_id, Task.task_name, Task.task_type, Task.check_items, Task.accepted, Task.takeover, Task.fix_type
        ).filter(Task.task_id == task_id)
        return task_query

    def get_task_hosts(self, task_id) -> tuple:
        """
        Getting hosts of the task, only support cve fix task or hotpatch remove task or cve rollback task

        Args:
            task_id: task id

        Returns:
            status_code: str
            hosts: list
        """

        try:
            hosts = self._get_task_hosts(task_id)
            if not hosts:
                return NO_DATA, hosts
            LOGGER.debug("Finished getting host info of task.")
            return SUCCEED, hosts
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def _get_task_hosts(self, task_id: str) -> list:
        hosts = []
        task_info = self.session.query(Task).filter(Task.task_id == task_id).first()
        if not task_info:
            return hosts
        if task_info.task_type == TaskType.HOTPATCH_REMOVE:
            hosts = (
                self.session.query(HotpatchRemoveTask.host_id)
                .filter(HotpatchRemoveTask.task_id == task_id)
                .group_by(HotpatchRemoveTask.host_id)
                .all()
            )
        elif task_info.task_type == TaskType.CVE_FIX:
            hosts = (
                self.session.query(CveFixTask.host_id)
                .filter(CveFixTask.task_id == task_id)
                .group_by(CveFixTask.host_id)
                .all()
            )
        elif task_info.task_type == TaskType.CVE_ROLLBACK:
            hosts = (
                self.session.query(CveRollbackTask.host_id)
                .filter(CveRollbackTask.task_id == task_id)
                .group_by(CveRollbackTask.host_id)
                .all()
            )
        return hosts
