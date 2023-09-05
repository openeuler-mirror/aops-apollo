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
import copy
import json
import math
from collections import defaultdict
from time import time
from typing import Dict, List, Tuple

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
    WRONG_DATA,
)

from apollo.conf.constant import REPO_FILE, TASK_INDEX, HostStatus, TaskStatus, TaskType
from apollo.database.table import (
    Cve,
    Repo,
    Task,
    TaskCveHostAssociation,
    TaskCveHostRpmAssociation,
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
            status_code = self._update_host_scan(status, host_list, username)
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

            status_code = self._update_host_scan("finish", [task_info["host_id"]])
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
                    "support_way": unfixed_vulnerability_info.get("support_way"),
                    "installed_rpm": unfixed_vulnerability_info.get("installed_rpm"),
                    "available_rpm": unfixed_vulnerability_info.get("available_rpm"),
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
        self.session.query(CveHostAssociation).filter(CveHostAssociation.host_id == host_id).delete(
            synchronize_session=False
        )

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

    def _update_host_scan(self, update_type, host_list, username=None):
        """
        Update hosts scan status and last_scan time
        Args:
            update_type (str): 'init' or 'finish'
            host_list (list): host id list
            username (str): user name
        Returns:

        """
        if update_type == "init":
            update_dict = {Host.status: HostStatus.SCANNING, Host.last_scan: int(time())}
        elif update_type == "finish":
            update_dict = {Host.status: HostStatus.DONE}
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

    def _get_processed_task_progress(self, data):
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
        cve_task, repo_task = self._split_task_list(username, task_list)
        cve_task_progress = self._get_cve_task_progress(cve_task)
        repo_task_progress = self._get_repo_task_progress(repo_task)

        result = {}
        result.update(cve_task_progress)
        result.update(repo_task_progress)

        succeed_list = list(result.keys())
        fail_list = list(set(task_list) - set(succeed_list))
        if fail_list:
            LOGGER.debug("No data found when getting the progress of task: %s." % fail_list)

        status_dict = {"succeed_list": succeed_list, "fail_list": fail_list}
        status_code = judge_return_code(status_dict, NO_DATA)
        return status_code, {"result": result}

    def _split_task_list(self, username, task_list):
        """
        split task list based on task's type
        Args:
            username (str): user name
            task_list (list): task id list

        Returns:
            list: cve task list
            list: repo task list
        """
        cve_task = []
        repo_task = []

        # filter task's type in case of other type added into task table
        task_query = self.session.query(Task.task_id, Task.task_type).filter(
            Task.username == username,
            Task.task_id.in_(task_list),
            Task.task_type.in_([TaskType.CVE_FIX, TaskType.CVE_ROLLBACK, TaskType.REPO_SET]),
        )

        for row in task_query:
            if row.task_type == TaskType.REPO_SET:
                repo_task.append(row.task_id)
            else:
                cve_task.append(row.task_id)
        return cve_task, repo_task

    @staticmethod
    def _get_status_result():
        def status_dict():
            return {TaskStatus.SUCCEED: 0, TaskStatus.FAIL: 0, TaskStatus.RUNNING: 0, TaskStatus.UNKNOWN: 0}

        return defaultdict(status_dict)

    def _get_cve_task_progress(self, task_list):
        """
        get cve tasks' progress
        Args:
            task_list (list): cve tasks' id list

        Returns:
            dict: e.g.
                {"task1": {"succeed": 1, "fail": 0, "running": 10, "unknown": 1}}

        Raises:
            KeyError
        """

        def defaultdict_set():
            return defaultdict(set)

        tasks_dict = defaultdict(defaultdict_set)
        result = self._get_status_result()

        task_query = self._query_cve_task_host_status(task_list)
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

    def _query_cve_task_host_status(self, task_list):
        """
        query host and CVE's relationship and status of required tasks
        Args:
            task_list (list): task id list

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_query = self.session.query(
            TaskCveHostAssociation.task_id, TaskCveHostAssociation.host_id, TaskCveHostAssociation.status
        ).filter(TaskCveHostAssociation.task_id.in_(task_list))
        return task_query

    @staticmethod
    def _get_cve_task_status(status_set):
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
        if None in status_set:
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

        task_info_data = self._query_task_info_from_mysql(username, task_id).first()
        if not task_info_data:
            LOGGER.debug("No data found when getting the info of task: %s." % task_id)
            return NO_DATA, {"result": {}}

        # raise exception when multiple record found

        info_dict = self._task_info_row2dict(task_info_data)
        return SUCCEED, {"result": info_dict}

    def _query_task_info_from_mysql(self, username, task_id):
        """
        query needed task info
        Args:
            username (str): user name of the request
            task_id (str): task id

        Returns:
            sqlalchemy.orm.query.Query
        """
        task_info_query = self.session.query(
            Task.task_name, Task.description, Task.host_num, Task.latest_execute_time, Task.accepted, Task.takeover
        ).filter(Task.task_id == task_id, Task.username == username)
        return task_info_query

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

    def get_cve_task_info(self, data):
        """
        Get the specific info about the cve fixing task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "sort": "host_num",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "cve_id": "",
                        "status": []
                    }
                }

        Returns:
            int: status code
            dict: task's cve info. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [{
                        "cve_id": "id1",
                        "package": "tensorflow",
                        "host_num": 3,
                        "status": "running"
                    }]
                }
        """
        result = {}
        try:
            result = self._get_processed_cve_task(data)
            LOGGER.debug("Finished getting task's cve info.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting task's cve info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_task(self, data):
        """
        Query and process cve task's cve info
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        result = {"total_count": 0, "total_page": 1, "result": []}

        task_id = data["task_id"]
        filter_dict = data.get("filter", {})
        filters = self._get_cve_task_filters(filter_dict)
        task_cve_query = self._query_cve_task(data["username"], task_id, filters)
        cve_info_list = self._process_cve_task_data(task_cve_query, filter_dict)

        total_count = len(cve_info_list)
        # NO_DATA code is NOT returned because no data situation here is normal
        # with filter
        if not total_count:
            return result

        processed_result, total_page = self._sort_and_page_task_cve(cve_info_list, data)
        result['result'] = processed_result
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    @staticmethod
    def _get_cve_task_filters(filter_dict):
        """
        Generate filters to filter cve task's cve info
        (filter by status will be manually implemented)
        Args:
            filter_dict(dict): filter dict to filter cve task's cve info, e.g.
                {
                    "cve_id": ""
                }

        Returns:
            set
        """
        filters = set()

        if filter_dict.get("cve_id"):
            filters.add(TaskCveHostAssociation.cve_id.like("%" + filter_dict["cve_id"] + "%"))
        return filters

    def _query_cve_task(self, username, task_id, filters):
        """
        query needed cve task's cve info
        Args:
            username (str): user name of the request
            task_id (str): task id
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "cve_id": "CVE-2021-0001",
                    "package": "tensorflow",
                    "host_id": "id1",
                    "status": "fixed"
                }
        """
        task_cve_query = (
            self.session.query(
                TaskCveHostAssociation.cve_id,
                CveAffectedPkgs.package,
                TaskCveHostAssociation.host_id,
                TaskCveHostAssociation.status,
            )
            .outerjoin(CveAffectedPkgs, CveAffectedPkgs.cve_id == TaskCveHostAssociation.cve_id)
            .outerjoin(Task, Task.task_id == TaskCveHostAssociation.task_id)
            .filter(Task.task_id == task_id, Task.username == username)
            .filter(*filters)
        )

        return task_cve_query

    def _process_cve_task_data(self, task_cve_query, filter_dict):
        """
        process task cve query data, get each cve's total status and host_num, then filter by status
        Args:
            task_cve_query (sqlalchemy.orm.query.Query): query result of cve task's cve info
                each row's structure:
                    {
                        "cve_id": "CVE-2021-0001",
                        "package": "tensorflow",
                        "host_id": "id1",
                        "status": "fixed"
                    }
            filter_dict (None/dict): the status user want
        Returns:
            list. e.g.
                [{
                    "cve_id": "CVE-2021-0001",
                    "package": "tensorflow",
                    "host_num": 3,
                    "status": "running"
                }]
        """
        need_status = filter_dict.get("status") if filter_dict else None
        cve_info_list = []
        cve_dict = {}

        for row in task_cve_query:
            cve_id = row.cve_id
            if cve_id not in cve_dict:
                cve_dict[cve_id] = {"package": {row.package}, "host_set": {row.host_id}, "status_set": {row.status}}
            else:
                cve_dict[cve_id]["package"].add(row.package)
                cve_dict[cve_id]["host_set"].add(row.host_id)
                cve_dict[cve_id]["status_set"].add(row.status)

        if isinstance(need_status, list):
            if not need_status:
                return cve_info_list
            for cve_id, cve_info in cve_dict.items():
                cve_status = self._get_cve_task_status(cve_info.pop("status_set"))
                if cve_status in need_status:
                    cve_info["cve_id"] = cve_id
                    cve_info["package"] = (
                        ','.join(list(filter(None, cve_info["package"]))) if filter(None, cve_info["package"]) else None
                    )
                    cve_info["host_num"] = len(cve_info.pop("host_set"))
                    cve_info["status"] = cve_status
                    cve_info_list.append(cve_info)
        else:
            for cve_id, cve_info in cve_dict.items():
                cve_info["cve_id"] = cve_id
                cve_info["package"] = (
                    ','.join(list(filter(None, cve_info["package"]))) if filter(None, cve_info["package"]) else None
                )
                cve_info["host_num"] = len(cve_info.pop("host_set"))
                cve_info["status"] = self._get_cve_task_status(cve_info.pop("status_set"))
                cve_info_list.append(cve_info)
        return cve_info_list

    @staticmethod
    def _sort_and_page_task_cve(cve_info_list, data):
        """
        sort and page cve task's cve info
        Args:
            cve_info_list (list): cve task's cve info list. not empty.
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "sort": "host_num",
                    "direction": "asc",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "cve_id": "",
                        "reboot": True,
                        "status": []
                    }
                }

        Returns:
            list: sorted cve info list
            int: total page
        """
        page = data.get('page')
        per_page = data.get('per_page')
        reverse = False
        if data.get("sort") == "host_num" and data.get("direction") == "desc":
            reverse = True

        total_page = 1
        total_count = len(cve_info_list)

        cve_info_list.sort(key=lambda cve_info: cve_info["host_num"], reverse=reverse)

        if page and per_page:
            total_page = math.ceil(total_count / per_page)
            return cve_info_list[per_page * (page - 1) : per_page * page], total_page

        return cve_info_list, total_page

    def get_task_cve_status(self, data):
        """
        Get the status of each host of the cve in the task

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "cve_list": ["cve1"],  // if empty, query all cve
                    "username": "admin"
                }

        Returns:
            int: status code
            dict: query result. e.g.
                {
                    "result": {
                        "cve1": [
                            {
                                "host_id": "id1",
                                "host_name": "name1",
                                "host_ip": "127.0.0.1",
                                "status": "running"
                            }
                        ]
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_cve_status(data)
            LOGGER.debug("Finished getting the status of each host of the cve in cve task")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the status of each host of the cve in cve task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_cve_status(self, data):
        """
        query and process the hosts' fixing status of cve in a cve task
        Args:
            data (dict): parameter

        Returns:
            dict
        """
        task_id = data["task_id"]
        cve_list = data["cve_list"]
        username = data["username"]
        status_query = self._query_cve_task_cve_status(username, task_id, cve_list, with_host=True)

        if not status_query.all():
            LOGGER.debug(
                "No data found when getting the hosts' fixing status of cve '%s' "
                "in cve task: %s." % (cve_list, task_id)
            )
            return NO_DATA, {"result", {}}

        result = defaultdict(list)
        for row in status_query:
            host_dict = self._cve_host_status_row2dict(row)
            result[row.cve_id].append(host_dict)

        succeed_list = list(result.keys())
        fail_list = list(set(cve_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug(
                "No data found when getting the hosts' fixing status of cve '%s' "
                "in cve task: %s." % (fail_list, task_id)
            )
            return PARTIAL_SUCCEED, {"result": dict(result)}

        return SUCCEED, {"result": dict(result)}

    def _query_cve_task_cve_status(self, username, task_id, cve_list, with_host=False):
        """
        query the hosts' fixing status of given cve list in a cve task
        Args:
            username (str): user name of the request
            task_id (str): task id
            cve_list (list): cve id list, if empty, query all cve
            with_host (bool): with host info or not

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {Task.username == username, TaskCveHostAssociation.task_id == task_id}
        if cve_list:
            filters.add(TaskCveHostAssociation.cve_id.in_(cve_list))

        if with_host:
            status_query = (
                self.session.query(
                    TaskCveHostAssociation.status,
                    TaskCveHostAssociation.cve_id,
                    TaskCveHostAssociation.host_id,
                    TaskCveHostAssociation.host_name,
                    TaskCveHostAssociation.host_ip,
                )
                .join(Task, Task.task_id == TaskCveHostAssociation.task_id)
                .filter(*filters)
            )
        else:
            status_query = (
                self.session.query(TaskCveHostAssociation.status, TaskCveHostAssociation.cve_id)
                .join(Task, Task.task_id == TaskCveHostAssociation.task_id)
                .filter(*filters)
            )
        return status_query

    @staticmethod
    def _cve_host_status_row2dict(row):
        host_status = {"host_id": row.host_id, "host_name": row.host_name, "host_ip": row.host_ip, "status": row.status}
        return host_status

    def get_task_cve_progress(self, data):
        """
        Get progress and status of each cve in the task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "cve_list": ["cve1"], if empty, query all cve
                    "username": "admin"
                }

        Returns:
            int: status code
            dict: cve's progress and status info. e.g.
                {
                    "result": {
                        "cve1": {
                            "progress": 1,
                            "status": "running"
                        }
                    }
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_task_cve_progress(data)
            LOGGER.debug("Finished getting the progress and status of the cve in cve task")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the progress and status of the cve in cve task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_task_cve_progress(self, data):
        """
        query and process the progress and status of cve in the cve task.
        Args:
            data (dict): parameter

        Returns:
            dict
        """
        task_id = data["task_id"]
        cve_list = data["cve_list"]
        username = data["username"]
        progress_query = self._query_cve_task_status_progress(username, task_id, cve_list)

        if not progress_query.all():
            LOGGER.debug(
                "No data found when getting the status and progress of cve '%s' "
                "in cve task: %s." % (cve_list, task_id)
            )
            return NO_DATA, {"result": {}}

        result = {}
        for row in progress_query:
            cve_id = row.cve_id
            if row.running:
                status = TaskStatus.RUNNING
            elif row.unknown:
                status = TaskStatus.UNKNOWN
            elif row.fail:
                status = TaskStatus.FAIL
            elif row.none:
                status = TaskStatus.UNKNOWN
            else:
                status = TaskStatus.SUCCEED
            result[cve_id] = {"progress": row.total - row.running - row.none, "status": status}

        succeed_list = list(result.keys())
        fail_list = list(set(cve_list) - set(succeed_list))

        if fail_list:
            LOGGER.debug(
                "No data found when getting the status and progress of cve '%s' "
                "in cve task: %s." % (fail_list, task_id)
            )
            return PARTIAL_SUCCEED, {"result": result}

        return SUCCEED, {"result": result}

    def _query_cve_task_status_progress(self, username, task_id, cve_list):
        """
        query cve task's assigned cve's status and progress
        Args:
            username (str): user name
            task_id (str): task id
            cve_list (list): cve id list, if empty, query all cve

        Returns:
            sqlalchemy.orm.query.Query
        """
        filters = {Task.username == username, TaskCveHostAssociation.task_id == task_id}
        if cve_list:
            filters.add(TaskCveHostAssociation.cve_id.in_(cve_list))
        # Count the number of states, sql e.g
        # sum(case when status='running' then 1 else 0 end) as running
        task_query = (
            self.session.query(
                TaskCveHostAssociation.cve_id,
                func.sum(case([(TaskCveHostAssociation.status == TaskStatus.RUNNING, 1)], else_=0)).label("running"),
                func.sum(case([(TaskCveHostAssociation.status == TaskStatus.UNKNOWN, 1)], else_=0)).label("unknown"),
                func.sum(case([(TaskCveHostAssociation.status == TaskStatus.FAIL, 1)], else_=0)).label("fail"),
                func.sum(case([(TaskCveHostAssociation.status == None, 1)], else_=0)).label("none"),
                func.count().label("total"),
            )
            .join(Task, Task.task_id == TaskCveHostAssociation.task_id)
            .filter(*filters)
            .group_by(TaskCveHostAssociation.cve_id)
        )
        return task_query

    def get_rollback_cve_list(self, data):
        """
        Just get the cve id list whose status is "succeed" and "fail", according to task id and
        username, the interface is used to verify the parameter for rollback.

        Args:
            data (dict): e.g.
                {
                    "task_id": "aa",
                    "username": "admin"
                }

        Returns:
            list
        """
        result = []
        try:
            result = self._get_rollback_cve_list(data)
            LOGGER.debug("Finished getting the cve task list which may need roll back.")
            return result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the cve task list which may need roll back failed due to internal error.")
            return result

    def _get_rollback_cve_list(self, data):
        """
        query the cve id whose status is "succeed" and "fail"
        """
        username = data["username"]
        task_id = data["task_id"]
        status_query = self._query_cve_task_cve_status(username, task_id, [])

        status_dict = defaultdict(set)
        for row in status_query:
            status_dict[row.cve_id].add(row.status)

        cve_list = []
        for cve_id, status_set in status_dict.items():
            cve_status = self._get_cve_task_status(status_set)
            if cve_status in [TaskStatus.SUCCEED, TaskStatus.FAIL]:
                cve_list.append(cve_id)

        return cve_list

    def get_cve_basic_info(self, task_id):
        """
        Get cve task basic info of the task id, for generating the task info.

        Args:
            task_id (str): task_id

        Returns:
            int: status code
            dict: e.g.
                {
                    "task_id": "2",
                    "task_name": "",
                    "task_type": "cve fix",
                    "total_hosts": [1,2],
                    "check_items": ["network","kabi"],
                    "takeover":true,
                    "accepted":true,
                    "tasks": [
                        {
                            "host_id": "id1",
                            "cves": [
                                {
                                    "cve_id": "cve1",
                                    "rpms":[
                                        {
                                            "installed_rpm": "kernel-4.19xxx",
                                            "available_rpm": "kernel-4.19xxx-new-release",
                                            "fix_way": "coldpatch"
                                        }
                                    ]
                                }
                            ]
                        }
                    ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_basic_info(task_id)
            LOGGER.debug("Finished getting the basic info of cve task.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the basic info of cve task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_basic_info(self, task_id: str) -> Tuple[str, Dict]:
        """
        query and process cve task's basic info
        Args:
            task_id (str): task id

        Returns:
            str
            dict
        """
        task_cve_host = self._query_cve_fix_task_host_info(task_id).all()
        basic_task = self._query_task_basic_info(task_id).first()
        if not all([task_cve_host, basic_task]):
            LOGGER.debug("No data found when getting the info of cve task: %s." % task_id)
            return NO_DATA, {}

        task_info = {
            "task_id": basic_task.task_id,
            "task_name": basic_task.task_name,
            "task_type": basic_task.task_type,
            "check_items": basic_task.check_items.split(',') if basic_task.check_items else [],
            "accepted": basic_task.accepted,
            "takeover": basic_task.takeover,
            "total_hosts": [],
            "tasks": [],
        }
        task_cve_host_id = [cve_host.task_cve_host_id for cve_host in task_cve_host]
        task_packages = self._query_cve_fix_task_package_info(task_cve_host_id=task_cve_host_id).all()
        temp_info = defaultdict(list)
        for cve_host_row in task_cve_host:
            rpms = []
            for rpm in filter(lambda package: package.task_cve_host_id == cve_host_row.task_cve_host_id, task_packages):
                rpms.append(dict(installed_rpm=rpm.installed_rpm, available_rpm=rpm.available_rpm, fix_way=rpm.fix_way))
            temp_info[cve_host_row.host_id].append(dict(cve_id=cve_host_row.cve_id, rpms=rpms))

        task_info['total_hosts'] = list(temp_info.keys())
        for host_id, cve_info in temp_info.items():
            task_info['tasks'].append({'host_id': host_id, 'cves': cve_info})

        return SUCCEED, task_info

    def _query_task_basic_info(self, task_id: str) -> sqlalchemy.orm.Query:
        """
        query basic task info

        Args:
            task_id

        Returns:
            sqlalchemy.orm.Query
        """
        task_query = self.session.query(
            Task.task_id, Task.task_name, Task.task_type, Task.check_items, Task.accepted, Task.takeover
        ).filter(Task.task_id == task_id)
        return task_query

    def _query_cve_fix_task_host_info(self, task_id: str) -> sqlalchemy.orm.Query:
        """
        query host and cve info of the cve fix task

        Args:
            task_id (str): task id

        Returns:
            sqlalchemy.orm.Query
        """
        task_query = self.session.query(
            TaskCveHostAssociation.cve_id, TaskCveHostAssociation.host_id, TaskCveHostAssociation.task_cve_host_id
        ).filter(TaskCveHostAssociation.task_id == task_id)
        return task_query

    def _query_cve_fix_task_package_info(self, task_cve_host_id: list) -> sqlalchemy.orm.Query:
        """
        query package info of the cve fix task

        Args:
            task_cve_host_id (list): Combination id of a host and cve in a task

        Returns:
            sqlalchemy.orm.Query
        """
        task_package_query = self.session.query(
            TaskCveHostRpmAssociation.available_rpm,
            TaskCveHostRpmAssociation.installed_rpm,
            TaskCveHostRpmAssociation.task_cve_host_id,
            TaskCveHostRpmAssociation.fix_way,
        ).filter(TaskCveHostRpmAssociation.task_cve_host_id.in_(task_cve_host_id))
        return task_package_query

    def update_cve_status(self, task_id, cve_id, host_id, status):
        """
        Every time a cve in a host has been tried to be fixed or rollbacked, update the status

        Args:
            task_id (str): task id
            cve_id (str): cve id
            host_id (str): host id
            status (str): status

        Returns:
            int: status code
        """
        try:
            status_code = self._update_cve_host_status(task_id, cve_id, host_id, status)
            if status_code != SUCCEED:
                return status_code
            self.session.commit()
            LOGGER.debug("Finished updating cve host status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating cve host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_cve_host_status(self, task_id, cve_id, host_id, status):
        """
        update a cve's one host's result of a cve task or rollback
        """
        status_query = self.session.query(TaskCveHostAssociation).filter(
            TaskCveHostAssociation.task_id == task_id,
            TaskCveHostAssociation.cve_id == cve_id,
            TaskCveHostAssociation.host_id == host_id,
        )

        if not status_query.count():
            LOGGER.error("Updating cve host status failed due to no data found.")
            return NO_DATA
        if status_query.count() > 1:
            LOGGER.error("Updating cve host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

        status_query.one().status = status
        return SUCCEED

    def init_cve_rollback_task(self, task_id, cve_list, status=None):
        """
        Before rollbacking cve, set related host status to 'running'

        Args:
            task_id (str): task id
            cve_list (list): cve id list, it can be empty which means all cve id.
            status (str): cve status
        Returns:
            int: status code
        """
        try:
            filters = {TaskCveHostAssociation.task_id == task_id}
            if cve_list:
                filters.add(TaskCveHostAssociation.cve_id.in_(cve_list))
            status = status if status else TaskStatus.RUNNING
            status_query = self.session.query(TaskCveHostAssociation).filter(*filters)
            status_query.update({TaskCveHostAssociation.status: status}, synchronize_session=False)
            self.session.commit()
            LOGGER.debug("Finished init cve task's status and progress.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init cve task's status and progress failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def init_cve_task(self, task_id, cve_list, status=None):
        """
        Before fixing or rollbacking cve, set related host status to 'running', and set progress
        to 0, these two actions are placed together for they can be rollbacked together when one
        of them failed.

        Args:
            task_id (str): task id
            cve_list (list): cve id list, it can be empty which means all cve id.
            status (str): cve status
        Returns:
            int: status code
        """
        try:
            status_code = self._init_cve_task(task_id, cve_list, status)
            self.session.commit()
            LOGGER.debug("Finished init cve task's status and progress.")
            return status_code
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init cve task's status and progress failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _init_cve_task(self, task_id, cve_list, status):
        """
        set cve's related host's status to running, and set the cve's progress to 0
        """
        # set status to running
        filters = {TaskCveHostAssociation.task_id == task_id}
        if cve_list:
            filters.add(TaskCveHostAssociation.cve_id.in_(cve_list))
        status = status if status else TaskStatus.RUNNING
        status_query = self.session.query(TaskCveHostAssociation).filter(*filters)
        status_query.update({TaskCveHostAssociation.status: status}, synchronize_session=False)
        # Set the status of all software packages to Running
        task_cve_host_ids = [task_cve_host.task_cve_host_id for task_cve_host in status_query]
        self.session.query(TaskCveHostRpmAssociation).filter(
            TaskCveHostRpmAssociation.task_cve_host_id.in_(task_cve_host_ids)
        ).update({TaskCveHostRpmAssociation.status: status}, synchronize_session=False)

        return SUCCEED

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
            host_query = self.session.query(TaskCveHostAssociation).filter(
                TaskCveHostAssociation.task_id == task_id, TaskCveHostAssociation.status == TaskStatus.RUNNING
            )
            host_query.update({TaskCveHostAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        elif task_type == TaskType.REPO_SET:
            host_query = self.session.query(TaskHostRepoAssociation).filter(
                TaskHostRepoAssociation.task_id == task_id, TaskHostRepoAssociation.status == TaskStatus.RUNNING
            )
            host_query.update({TaskHostRepoAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
        else:
            LOGGER.error("Unknown task type '%s' when setting its status." % task_type)
            return SERVER_ERROR

        return SUCCEED

    def get_repo_task_info(self, data):
        """
        Get repo task info.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "page": 1,
                    "per_page": 10,
                    "filter": {
                        "host_name": "",
                        "status": [],
                        "host_id": ""
                    }
                }

        Returns:
            int: status code
            dict. e.g.
                {
                    "result": [
                        {
                            "host_id": "id1",
                            "host_name": "host1",
                            "host_ip": "id1",
                            "repo_name": "repo1",
                            "status": "running"
                        }
                    ],
                    "total_count": 1,
                    "total_page": 1
                }
        """
        result = {}
        try:
            result = self._get_processed_repo_task(data)
            LOGGER.debug("Finished getting repo task info.")
            return SUCCEED, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo task info failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_repo_task(self, data):
        """
        query and process repo task info
        Args:
            data (dict): query condition

        Returns:
            int: status code
            dict
        """
        result = {"total_count": 0, "total_page": 1, "result": []}

        task_id = data["task_id"]
        filter_dict = data.get("filter")
        filters = self._get_repo_task_filters(filter_dict)
        repo_task_query = self._query_repo_task(data["username"], task_id, filters)

        total_count = len(repo_task_query.all())
        # NO_DATA code is NOT returned because no data situation here is normal
        # with filter
        if not total_count:
            return result

        page = data.get('page')
        per_page = data.get('per_page')
        processed_query, total_page = sort_and_page(repo_task_query, None, None, per_page, page)

        result['result'] = self._repo_task_info_row2dict(processed_query)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    def _query_repo_task(self, username, task_id, filters):
        """
        query needed repo task's host info
        Args:
            username (str): user name of the request
            task_id (str): task id
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "host_id": "id1",
                    "host_name": "name1",
                    "host_ip": "ip1",
                    "repo_name": "repo1",
                    "status": "unset"
                }
        """
        task_repo_query = (
            self.session.query(
                TaskHostRepoAssociation.host_id,
                TaskHostRepoAssociation.host_name,
                TaskHostRepoAssociation.host_ip,
                TaskHostRepoAssociation.repo_name,
                TaskHostRepoAssociation.status,
            )
            .join(Task, Task.task_id == TaskHostRepoAssociation.task_id)
            .filter(Task.username == username, TaskHostRepoAssociation.task_id == task_id)
            .filter(*filters)
        )

        return task_repo_query

    @staticmethod
    def _get_repo_task_filters(filter_dict):
        """
        Generate filters to filter repo task's host info
        Args:
            filter_dict(dict): filter dict to filter repo task's host info, e.g.
                {
                    "host_name": "name1",
                    "status": [],
                    "host_id":""
                }

        Returns:
            set
        """
        filters = set()
        if not filter_dict:
            return filters

        if filter_dict.get("host_name"):
            filters.add(TaskHostRepoAssociation.host_name.like("%" + filter_dict["host_name"] + "%"))
        if filter_dict.get("status"):
            filters.add(TaskHostRepoAssociation.status.in_(filter_dict["status"]))
        if filter_dict.get("host_id"):
            filters.add(TaskHostRepoAssociation.host_id == filter_dict["host_id"])
        return filters

    @staticmethod
    def _repo_task_info_row2dict(rows):
        result = []
        for row in rows:
            host_info = {
                "host_id": row.host_id,
                "host_name": row.host_name,
                "host_ip": row.host_ip,
                "repo_name": row.repo_name,
                "status": row.status,
            }
            result.append(host_info)
        return result

    def set_host_repo(self, repo_name, host_list):
        """
        set repo name to hosts when "set repo" task finished successfully.
        Args:
            repo_name (str): repo name
            host_list (list): host id list

        Returns:
            int
        """
        try:
            self._update_host_repo(repo_name, host_list)
            self.session.commit()
            LOGGER.debug("Finished setting repo name to hosts when task finished.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting repo name to hosts when task finished failed due to " "internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_host_repo(self, repo_name, host_list):
        """
        set repo name to relative hosts
        """
        self.session.query(Host).filter(Host.host_id.in_(host_list)).update(
            {Host.repo_name: repo_name}, synchronize_session=False
        )

    def set_repo_status(self, task_id, host_list, status):
        """
        Everytime a repo setting task will be executed or has been completed,
        update the related status.

        Args:
            task_id (str)
            host_list (list): host id list, can be empty, which means all host.
            status (str): can be "set", "unset", "running", "unknown"
            ('unknown' when task has some error, but prefer using 'fix_task_status' in this case)

        Returns:
            int: status code
        """
        try:
            self._update_repo_host_status(task_id, host_list, status)
            self.session.commit()
            LOGGER.debug("Finished updating repo host status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Updating repo host status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _update_repo_host_status(self, task_id, host_list, status):
        """
        update a host's repo setting status of a repo task
        """
        filters = {TaskHostRepoAssociation.task_id == task_id}
        if host_list:
            filters.add(TaskHostRepoAssociation.host_id.in_(host_list))

        status_query = self.session.query(TaskHostRepoAssociation).filter(*filters)
        status_query.update({TaskHostRepoAssociation.status: status}, synchronize_session=False)

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
            task_type (str): for now, 'cve fix' or 'repo set' or 'cve rollback'

        Returns:
            bool
        """
        if task_type == TaskType.CVE_FIX or task_type == TaskType.CVE_ROLLBACK:
            task_progress = self._get_cve_task_progress([task_id])
        elif task_type == TaskType.REPO_SET:
            task_progress = self._get_repo_task_progress([task_id])
        else:
            LOGGER.error("Unknown task type '%s' was given when checking task '%s' status." % (task_type, task_id))
            return True

        if task_progress[task_id][TaskStatus.RUNNING]:
            return False
        return True

    def get_repo_info(self, data: dict):
        """
        GET repo information

        Args:
            data(dict): e.g.
                {
                    "repo_name": "repo1",
                    "username": "admin"
                }
        Returns:
            stattus_code: State of the query
            repo(dict): repo info e.g
                {
                    "repo_id":"",
                    "repo_name":"",
                    "repo_data":"",
                    "repo_attr":""
                }
        """
        try:
            status_code, repo_info = self._get_repo_info(data.get("repo_name"), data.get("username"))
            LOGGER.debug("Finished getting repo info.")
            return status_code, repo_info
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo info failed due to internal error.")
            return DATABASE_QUERY_ERROR, None

    def _get_repo_info(self, repo_name, username):
        """
        Query repo info
        """
        filters = {Repo.repo_name == repo_name}
        if username:
            filters.add(Repo.username == username)

        query_repo_info = (
            self.session.query(Repo.repo_id, Repo.repo_name, Repo.repo_attr, Repo.repo_data).filter(*filters).first()
        )
        if not query_repo_info:
            LOGGER.debug(f"Repo information does not exist: {repo_name}.")
            return NO_DATA, None
        repo_info = dict(
            repo_name=query_repo_info.repo_name,
            repo_data=query_repo_info.repo_data,
            repo_attr=query_repo_info.repo_attr,
            repo_id=query_repo_info.repo_id,
        )
        return SUCCEED, repo_info

    def get_repo_set_task_template(self, task_id: str, username: str):
        """
        Get the task template set by repo

        Args:
            task_id: id of the task set by repo
            username: user name
        Returns:
            status_code: State of the query
            task: task info
        """
        # query task info

        status_code, task_info = self.get_task_info(data=dict(task_id=task_id, username=username))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting task info failed, task id: {task_id}.")
            return status_code, None
        # query task host
        status_code, host_info = self.get_repo_task_info(data=dict(username=username, task_id=task_id))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting repo task info failed, task id: {task_id}.")
            return status_code, None
        repo_name = host_info["result"][-1]["repo_name"]

        # query repo info
        status_code, repo_info = self.get_repo_info(dict(repo_name=repo_name, username=username))
        if status_code != SUCCEED:
            LOGGER.debug(f"Getting repo info failed, repo name: {repo_name}.")
            return status_code, None
        task_template = {
            "task_id": task_id,
            "task_name": task_info["result"]["task_name"],
            "task_type": TaskType.REPO_SET,
            "check_items": [],
            "repo_info": {"name": repo_name, "repo_content": repo_info["repo_data"], "dest": REPO_FILE},
            "total_hosts": [host["host_id"] for host in host_info["result"]],
        }

        return SUCCEED, task_template

    def update_repo_host_status_and_host_reponame(self, data: dict, hosts_id_list: list):
        """
        After repo is successfully set, update the host status and set repo name to the host name

        Args:
            data: e.g
                {
                    "task_id":"",
                    "status":"",
                    "repo_name":
                }

        Returns:
            status_code: update state
        """
        try:
            self._update_repo_host_status(data["task_id"], hosts_id_list, data["status"])
            if data["status"] == TaskStatus.SUCCEED:
                self._update_host_repo(data["repo_name"], hosts_id_list)
            self.session.commit()
            LOGGER.debug("Finished setting repo name to hosts and upate repo host state when task finished .")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting repo name to hosts and upate repo host state failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def update_cve_status_and_set_package_status(self, task_id, host_id, cves: list):
        """
        Setting cve fixing rpm status and update cve host status

        Args:
            task_id: task id
            host_id: host id
            cves: List of cves to be updated

        Returns:
            status_code: update state
        """
        try:
            for cve in cves:
                self._update_cve_host_status(task_id, cve["cve_id"], host_id, cve["result"])
                self._set_package_status(task_id, cve["cve_id"], host_id, cve["rpms"])

            self.session.commit()
            LOGGER.debug("Finished setting cve fixing progress and update cve host status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting cve fixing progress failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _set_package_status(self, task_id, cve_id, host_id, rpms: list):
        task_cve_host_id = hash_value(text=task_id + cve_id + str(host_id))
        for rpm_result in rpms:
            self.session.query(TaskCveHostRpmAssociation).filter(
                TaskCveHostRpmAssociation.task_cve_host_id == task_cve_host_id,
                TaskCveHostRpmAssociation.installed_rpm == rpm_result["installed_rpm"],
            ).update({TaskCveHostRpmAssociation.status: rpm_result["result"]}, synchronize_session=False)

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

    def get_cve_rollback_task_info(self, task_id):
        """
        Get cve rollback task basic info of the task id, for generating the task info.

        Args:
            task_id (str): task_id

        Returns:
            int: status code
            dict: e.g.
                {
                    "task_id": "1",
                    "task_name": "CVE修复回滚",
                    "task_type": "cve rollback",
                    "total_hosts": ["id1", "id2"],
                    "tasks": [
                        {
                            "host_id": "id1",
                            "cves": [
                                {
                                    "cve_id": "cve1",
                                    "hotpatch": true
                                }
                            }
                        }
                    ]
                }
        """
        result = dict()
        try:
            status_code, result = self._get_cve_rollback_task_info(task_id)
            LOGGER.debug("Finished getting the basic info of cve rollback task.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the basic info of cve rollback task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_cve_rollback_task_info(self, task_id: str) -> Tuple[int, Dict]:
        """
        query cve rollback task's basic info
        Args:
            task_id (str): task id

        Returns:
            int
            dict
        """
        task_hosts = (
            self.session.query(
                TaskCveHostAssociation.cve_id, TaskCveHostAssociation.host_id, TaskCveHostAssociation.hotpatch
            )
            .filter(TaskCveHostAssociation.task_id == task_id)
            .all()
        )

        task_basic_info = self._query_task_basic_info(task_id).first()
        if not all([task_hosts, task_basic_info]):
            LOGGER.debug("No data found when getting the info of cve task: %s." % task_id)
            return NO_DATA, {}

        task_info = {
            "task_id": task_basic_info.task_id,
            "task_name": task_basic_info.task_name,
            "task_type": task_basic_info.task_type,
            "total_hosts": [],
            "tasks": [],
        }
        tasks = dict()
        for task_host in task_hosts:
            cve_info = dict(cve_id=task_host.cve_id, hotpatch=task_host.hotpatch)
            if task_host.host_id in tasks:
                tasks[task_host.host_id].append(cve_info)
            else:
                tasks[task_host.host_id] = [cve_info]
        task_info["total_hosts"] = list(tasks.keys())
        task_info["tasks"] = [{"host_id": host_id, "cves": cves} for host_id, cves in tasks.items()]

        return SUCCEED, task_info


class TaskEsProxy(ElasticsearchProxy):
    def get_package_info(self, data):
        """
        Get package info of the cve.

        Args:
            data (list): e.g.
                [
                    {
                        "cve_id": "cve-11-11",
                        "host_info": [
                            {
                                "host_name": "name1",
                                "host_ip": "11.1.1.1",
                                "host_id": "1"
                            }
                        ]
                    }
                ]

        Returns:
            int: status code
            dict: package info. e.g.
                    {
                        "cve-11-11": ["xx.rpm", "yy"],
                        "cve-11-12": ["x"]
                    }
        """
        return SUCCEED, {}

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

    def get_task_log_info(self, task_id, host_id=None, username=None) -> list:
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
            return DATABASE_QUERY_ERROR, ""

        if not res["hits"]["hits"]:
            LOGGER.debug("No data found when getting log info of task '%s'." % task_id)
            return NO_DATA, ""

        task_infos = [json.loads(task_info["_source"]["log"]) for task_info in res["hits"]["hits"]]

        LOGGER.debug("Querying task log succeed.")
        return SUCCEED, task_infos

    def get_task_cve_result(self, data):
        """
        Get the result of each cve in the task, in addition to basic info of the task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "cve_list": []  // if empty, return all cve's result
                }

        Returns:
            int: status code
            list: query result. e.g.
                [{
                    "task_id": "90d0a61e32a811ee8677000c29766160",
                    "host_id": "2",
                    "latest_execute_time": "1691465474",
                    "task_type": "cve fix",
                    "task_result": {
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
                                "result": "string",
                                "log": "string",
                                "rpms":[
                                    {
                                        "rpm": "string",
                                        "result": "string",
                                        "log": "string",
                                    }
                                ],
                            }
                        ],
                        "host_ip": "172.168.63.86",
                        "host_name": "host1_12001",
                        "status": "fail"
                }
            }]
        """
        result = {}
        try:
            status_code, result = self._get_cve_task_result(data)
            LOGGER.debug("Finished getting cve task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_cve_task_result(self, data):
        """
        query cve task result from mysql and es.
        """
        username = data["username"]
        task_id = data["task_id"]
        # task log is in the format of returned dict of func
        status_code, task_log = self.get_task_log_info(task_id=task_id, username=username)
        if status_code != SUCCEED:
            return status_code, []

        if data["cve_list"]:
            for log_info in task_log:
                log_info["task_result"]["cves"] = list(
                    filter(lambda cve: cve["cve_id"] in data["cve_list"], log_info["task_result"]["cves"])
                )

        return SUCCEED, task_log

    def get_task_repo_result(self, data):
        """
        Get the result of each host in the task, in addition to basic info of the task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "host_list": []  // if empty, return all host's result
                }

        Returns:
            int: status code
            list: query result. e.g.
                [{
                "task_id": "90d0a61e32a811ee8677000c29766160",
                "host_id": "2",
                "latest_execute_time": "1691465474",
                "task_type": "repo set",
                "task_result": {
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                        ],
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "log": "operate success",
                    "repo": "2203sp2",
                    "status": "fail"
                }
            }]

        """
        result = {}
        try:
            status_code, result = self._get_repo_task_result(data)
            LOGGER.debug("Finished getting repo task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting repo task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_repo_task_result(self, data):
        """
        query repo task result from mysql and es.
        """
        username = data["username"]
        task_id = data["task_id"]
        host_list = data["host_list"]
        # task log is in the format of returned dict of func
        status_code, task_log = self.get_task_log_info(task_id=task_id, username=username)
        if status_code != SUCCEED:
            return status_code, []

        if host_list and task_log:
            task_log = [log for log in task_log if log["host_id"] in host_list]

        return SUCCEED, task_log

    @staticmethod
    def _process_repo_task_result(task_dict, host_list):
        task_result = task_dict.pop("task_result")
        filtered_result = []
        for host_result in task_result:
            if host_result["host_id"] in host_list:
                filtered_result.append(host_result)
        task_dict["task_result"] = filtered_result


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

    def generate_cve_task(self, data):
        """
        For generating, save cve task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "create_time": 1,
                    "check_items": "",
                    "accepted": True,
                    "takeover": False,
                    "info": [
                        {
                            "cve_id": "cve1",
                            "rpms": [
                                {
                                    "installed_rpm":"pkg1",
                                    "available_rpm": "pkg1-1",
                                    "fix_way":"hotpatch"
                                }
                            ]
                            "host_info": [
                                {
                                    "host_id": "id1",
                                    "host_name": "",
                                    "host_ip": ""
                                }
                            ]
                        }
                    ]
                }

        Returns:
            int: status code
        """
        try:
            self._generate_cve_fix_task(data)
            self.session.commit()
            LOGGER.debug("Finished generating cve task.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating cve task failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _generate_cve_fix_task(self, data):
        """
        generate cve task. Process data, then:
        1. insert task basic info into mysql Task table
        2. insert host and cve's relationship and fixing status into mysql
           TaskCveHostAssociation table
        3. insert packages to TaskCvePackageAssociation table
        Args:
            data (dict): cve task info

        Raises:
            EsOperationError
        """
        task_id = data["task_id"]
        cve_host_info = data.pop("info")
        wait_fix_rpms = dict()
        task_cve_host_rows = []
        task_package_rows = []
        host_set = set()
        for task_info in cve_host_info:
            wait_fix_rpms[task_info["cve_id"]] = dict(
                rpms=task_info.get("rpms", []), host_ids=[host['host_id'] for host in task_info["host_info"]]
            )

            for host in task_info["host_info"]:
                task_cve_host_id = hash_value(text=task_id + task_info["cve_id"] + str(host["host_id"]))
                host_set.add(host["host_id"])
                task_cve_host_rows.append(
                    self._task_cve_host_row_dict(task_cve_host_id, task_id, task_info["cve_id"], host)
                )
        data["host_num"] = len(host_set)
        task_package_rows, wait_rm_cve_host = self._gen_task_cve_host_rpm_rows(wait_fix_rpms, task_id)
        # insert data into mysql tables
        if wait_rm_cve_host:
            task_cve_host_rows = list(
                filter(lambda cve_host: cve_host["task_cve_host_id"] not in wait_rm_cve_host, task_cve_host_rows)
            )
        self._insert_cve_task_tables(data, task_package_rows, task_cve_host_rows)

    def _gen_task_cve_host_rpm_rows(self, fix_rpms: dict, task_id) -> tuple:
        """
        Generate the cve package for the host of the task
        1. Filter The list of Cves with only CVes but no rpm package
        2. Query the rpm package that the cve needs to repair
        3. This section describes how to combine the RPMS of cve hosts

        Args:
            fix_rpms: e.g
                {
                    "CVE-2023-3332":{
                        "rpms": [],
                        "host_ids":[1,2]
                    },
                    "CVE-2023-3332":{
                        "rpms": [
                            {
                                "installed_rpm":"pkg1",
                                "available_rpm": "pkg1-1",
                                "fix_way":"hotpatch"
                            }
                        ],
                        "host_ids":[1,2]
                    }
                }
            task_id: task id
        """
        task_package_rows = []
        wait_rm_cve_host = []
        for cve_id, host_rpms in fix_rpms.items():
            host_cve_packages = self._get_host_cve_packages(cve_id, host_rpms)
            for host_id, cve_packages in host_cve_packages.items():
                task_cve_host_id = hash_value(text=task_id + cve_id + str(host_id))
                # If the cve has no recoverable rpm packages, remove them
                if not cve_packages:
                    wait_rm_cve_host.append(task_cve_host_id)
                    LOGGER.debug("No available rpm was found while repairing %s of host %s" % (cve_id, str(host_id)))
                    continue
                for pacakge in cve_packages:
                    wait_fix_rpm = copy.deepcopy(pacakge)
                    wait_fix_rpm.update(dict(task_cve_host_id=task_cve_host_id))
                    task_package_rows.append(wait_fix_rpm)
        return task_package_rows, wait_rm_cve_host

    def _get_host_cve_packages(self, cve_id, host_rpms: dict):
        """

        Args:
            cve_id: cve id
            host_rpms: dict e.g
                {
                    "rpms": [
                            {
                                "installed_rpm":"pkg1",
                                "available_rpm": "pkg1-1",
                                "fix_way":"hotpatch"
                            }
                        ],
                    "host_ids":[1,2]
                } or
                {
                    "rpms": [],
                    "host_ids":[1,2]
                }

        Returns:
            {
                1: [
                    {
                        "installed_rpm":"pkg1",
                        "available_rpm": "pkg1-1",
                        "fix_way":"hotpatch"
                    }
                ]
            }
        """
        host_rpm_dict = dict()
        for rpm in host_rpms["rpms"]:
            if rpm["installed_rpm"] in host_rpm_dict:
                host_rpm_dict[rpm["installed_rpm"]].append(rpm["available_rpm"])
            else:
                host_rpm_dict[rpm["installed_rpm"]] = [rpm["available_rpm"]]
        cve_host_packages = (
            self.session.query(CveHostAssociation)
            .filter(
                CveHostAssociation.cve_id == cve_id,
                CveHostAssociation.fixed == False,
                CveHostAssociation.available_rpm != None,
                CveHostAssociation.host_id.in_(host_rpms["host_ids"]),
            )
            .all()
        )
        cve_host_package_dict = dict()
        for host_id in host_rpms["host_ids"]:
            filter_host_package = filter(lambda host_package: host_package.host_id == int(host_id), cve_host_packages)
            if host_rpm_dict:
                filter_host_package = filter(
                    lambda host_package: host_package.installed_rpm in host_rpm_dict, filter_host_package
                )
            installed_rpm = self._filter_installed_rpm(list(filter_host_package), host_rpm_dict)
            cve_host_package_dict[host_id] = installed_rpm

        return cve_host_package_dict

    def _filter_installed_rpm(self, host_packages: list, host_rpm_dict: dict):
        """

        Args:
            host_packages: list CveHostAssociation table data
            host_rpm_dict: If you do not expand to select rpm, this is None e.g
                {
                    "kernel-4.19": ["kernel-5-ACC","kernel-5-SGL","kernel"]
                }

        Return:
            [
                {
                    "installed_rpm":"pkg1",
                    "available_rpm": "pkg1-1-ACC",
                    "fix_way":"hotpatch"
                }
            ]
        """
        cve_host_packages = list()
        # If the rpm package is not selected, query all rpm packages affected by cve on a host
        if not host_rpm_dict:
            for package in host_packages:
                if package.installed_rpm in host_rpm_dict:
                    host_rpm_dict[package.installed_rpm].append(package.available_rpm)
                else:
                    host_rpm_dict[package.installed_rpm] = [package.available_rpm]

        for install_rpm, available_rpms in host_rpm_dict.items():
            package = self._priority_fix_package(host_packages, install_rpm, available_rpms)
            if not package:
                continue
            cve_host_packages.append(
                dict(
                    installed_rpm=package.installed_rpm,
                    available_rpm=package.available_rpm,
                    fix_way=package.support_way,
                )
            )

        return cve_host_packages

    def _priority_fix_package(self, host_packages, install_rpm, available_rpms):
        installed_host_packages = list(
            filter(
                lambda host_rpm: host_rpm.installed_rpm == install_rpm,
                host_packages,
            )
        )
        if list(filter(lambda rpm: rpm.endswith("ACC"), available_rpms)):
            priority = ["ACC", "SGL"]
        elif list(filter(lambda rpm: rpm.endswith("SGL"), available_rpms)):
            priority = ["SGL"]
        else:
            priority = ["ACC", "SGL"]

        package = None
        for priority_fun in priority:
            package = list(
                filter(
                    lambda host_rpm: host_rpm.available_rpm and host_rpm.available_rpm.endswith(priority_fun),
                    installed_host_packages,
                )
            )
            if package:
                package = package[0]
                break
        if not package and installed_host_packages:
            package = installed_host_packages[0]
        return package

    def _insert_cve_task_tables(self, task_data, task_package_rows, task_cve_host_rows):
        """
        insert data into three mysql tables when generating cve task.
        Task table need commit after add, otherwise following insertion will fail due to
        task.task_id foreign key constraint.
        Args:
            task_data (dict): task basic info for Task table
            task_package_rows (list): list of row dict for TaskCvePackageAssociation table
            task_cve_host_rows (list): list of row dict for TaskCveHostAssociation table

        Raises:
            SQLAlchemyError
        """

        self.session.add(Task(**task_data))
        self.session.bulk_insert_mappings(TaskCveHostRpmAssociation, task_package_rows)
        self.session.bulk_insert_mappings(TaskCveHostAssociation, task_cve_host_rows)

    @staticmethod
    def _task_cve_host_row_dict(task_cve_host_id, task_id, cve_id, host_info):
        """
        insert cve task's fixing status of each cve and host into TaskCveHostAssociation table
        """
        return {
            "task_cve_host_id": task_cve_host_id,
            "task_id": task_id,
            "cve_id": cve_id,
            "host_id": host_info["host_id"],
            "host_name": host_info["host_name"],
            "host_ip": host_info["host_ip"],
            # "status": TaskStatus.UNKNOWN,
            "status": None,
            "hotpatch": host_info.get("hotpatch", False),
        }

    def generate_repo_task(self, data):
        """
        For generating, save repo task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin"
                    "task_id": "",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "repo_name": "",
                    "create_time": 1,
                    "info": [
                        {
                            "host_id": "",
                            "host_name": "",
                            "host_ip": ""
                        }
                    ]
                }

        Returns:
            int: status code
        """
        try:
            self._gen_repo_task(data)
            self.session.commit()
            LOGGER.debug("Finished generating repo task.")
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generate repo task failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _gen_repo_task(self, data):
        """
        generate repo task. Process data, then:
        1. insert task basic info into mysql Task table
        2. insert host and repo's relationship and setting status into mysql
           TaskHostRepoAssociation table
        3. insert task's id and username into elasticsearch
        Args:
            data (dict): repo task info

        Raises:
            EsOperationError
        """
        task_id = data["task_id"]
        repo_name = data.pop("repo_name")
        host_list = data.pop("info")

        task_repo_host_rows = []
        for host_info in host_list:
            task_repo_host_rows.append(self._task_repo_host_row_dict(task_id, repo_name, host_info))

        # insert data into mysql tables
        data["host_num"] = len(host_list)
        self._insert_repo_task_tables(data, task_repo_host_rows)

    @staticmethod
    def _task_repo_host_row_dict(task_id, repo_name, host_info):
        """
        insert repo setting into TaskHostRepoAssociation table
        """
        return {
            "task_id": task_id,
            "repo_name": repo_name,
            "host_id": host_info["host_id"],
            "host_name": host_info["host_name"],
            "host_ip": host_info["host_ip"],
            "status": "fail",
        }

    def _insert_repo_task_tables(self, task_data, task_repo_host_rows):
        """
        insert data into two tables when generating repo task.
        Task table need commit after add, otherwise following insertion will fail due to
        task.task_id foreign key constraint.
        Args:
            task_data (dict): task basic info for Task table
            task_repo_host_rows (list): list of row dict for TaskHostRepoAssociation table

        Raises:
            SQLAlchemyError
        """
        self.session.add(Task(**task_data))
        self.session.commit()

        try:
            self.session.bulk_insert_mappings(TaskHostRepoAssociation, task_repo_host_rows)
        except SQLAlchemyError:
            self.session.rollback()
            self.session.query(Task).filter(Task.task_id == task_data["task_id"]).delete()
            self.session.commit()
            raise

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
            self.session.query(TaskCveHostAssociation.task_id)
            .filter(TaskCveHostAssociation.status == TaskStatus.RUNNING, TaskCveHostAssociation.task_id.in_(task_list))
            .union(
                self.session.query(TaskHostRepoAssociation.task_id).filter(
                    TaskHostRepoAssociation.task_id.in_(task_list), TaskHostRepoAssociation.status == TaskStatus.RUNNING
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
            self.session.query(TaskCveHostAssociation).filter(TaskCveHostAssociation.status == TaskStatus.RUNNING).all()
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
        running_task_list = [(task.task_id, task.task_type, task.create_time) for task in task_query]
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
        cve_task_query = self.session.query(TaskCveHostAssociation).filter(
            TaskCveHostAssociation.task_id.in_(task_id_list)
        )
        try:
            cve_task_query.update({TaskCveHostAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
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
        cve_task_query = self.session.query(TaskCveHostAssociation).filter(
            TaskCveHostAssociation.task_id.in_(task_id_list)
        )
        try:
            cve_task_query.update({TaskCveHostAssociation.status: TaskStatus.UNKNOWN}, synchronize_session=False)
            self.session.commit()
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("update task_cve_host table status failed.")
            return DATABASE_UPDATE_ERROR

        return SUCCEED

    def generate_cve_rollback_task(self, data):
        """
        For generating, save cve rollback task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
                    "task_id": "",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "create_time": 1,
                    "info": [
                        {
                            "host_id": "id1",
                            "cves": [
                                {
                                    "cve_id": "cve1",
                                    "hotpatch": true
                                }
                            ],
                        }
                    ]
                }

        Returns:
            int: status code
        """
        try:
            self._gen_cve_rollback_task(data)
            self.session.commit()
            LOGGER.debug("Finished generating cve rollback task.")
            return SUCCEED
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating cve rollback task failed due to internal error.")
            return DATABASE_INSERT_ERROR

    def _gen_cve_rollback_task(self, data):
        task_id = data["task_id"]
        task_cve_host = dict()
        cves = dict()
        for task_info in data.pop("info"):
            task_cve_host[task_info["host_id"]] = []
            for cve in task_info["cves"]:
                cves[cve["cve_id"]] = cves[cve["cve_id"]] + 1 if cve["cve_id"] in cves else 1
                task_cve_host[task_info["host_id"]].append((cve["cve_id"], cve["hotpatch"]))

        task_cve_host_rows = []
        hosts = self.session.query(Host).filter(Host.host_id.in_(list(task_cve_host.keys()))).all()
        for host in hosts:
            host_info = {"host_id": host.host_id, "host_name": host.host_name, "host_ip": host.host_ip}
            for cve_id, hotpatch in task_cve_host[host.host_id]:
                host_info["hotpatch"] = hotpatch
                task_cve_host_id = hash_value(text=task_id + cve_id + str(host.host_id))
                task_cve_host_rows.append(self._task_cve_host_row_dict(task_cve_host_id, task_id, cve_id, host_info))

        # insert data into mysql tables
        data["host_num"] = len(task_cve_host.keys())
        self.session.add(Task(**data))
        self.session.bulk_insert_mappings(TaskCveHostAssociation, task_cve_host_rows)

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

    def validate_hosts(self, host_id: list) -> bool:
        """
        Verifying host validity

        Args:
            host_id: id of the host to be validate

        Returns:
            bool:  A return of true indicates that the validation passed
        """
        try:
            exists_host_count = self.session.query(Host).filter(Host.host_id.in_(host_id)).count()
            return True if exists_host_count == len(host_id) else False
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return False

    def query_task_cve_rpm_info(self, task_id: str, cve_id: str) -> Tuple[str, list]:
        """
        query cve's rpm info about cve-fix task

        Args:
            task_id(str): task id which need to query
            cve_id(str): cve id which need to query

        Returns:
            Tuple[str, list]
            a tuple containing two elements (return code, database query rows).
        """
        try:
            rows = (
                self.session.query(
                    TaskCveHostAssociation.host_id,
                    TaskCveHostRpmAssociation.installed_rpm,
                    TaskCveHostRpmAssociation.available_rpm,
                    TaskCveHostRpmAssociation.fix_way,
                )
                .join(
                    TaskCveHostRpmAssociation,
                    TaskCveHostAssociation.task_cve_host_id == TaskCveHostRpmAssociation.task_cve_host_id,
                )
                .filter(TaskCveHostAssociation.task_id == task_id, TaskCveHostAssociation.cve_id == cve_id)
            ).all()
            return SUCCEED, rows
        except SQLAlchemyError as error:
            LOGGER.error(error)
            return DATABASE_QUERY_ERROR, []

    def get_task_cve_rpm_host(self, data):
        """
        Obtain the host list of the rpm corresponding to the cve in the repair task

        Args:
            data: dict e.g.
                {
                    "task_id":"a99aca2a47ad11eebf2752540030a9b2",
                    "cve_id":"CVE-2023-0120",
                    "installed_rpm":"kernel-tools-5.10.0-153.12.0.92.oe2203sp2.x86_64",
                    "available_rpm":"kernel-tools-5.10.0-153.24.0.100.oe2203sp2.x86_64"
                }

        Returns:
            status_code (str)
            host_list (list): e.g
                [
                    {
                        "host_name":"主机1",
                        "host_ip":"127.0.0.1"
                    }
                ]
        """
        try:
            host_list = self._get_task_cve_rpm_host(data)
            if not host_list:
                return NO_DATA, host_list
            LOGGER.debug("Finished getting cve package host list.")
            return SUCCEED, host_list
        except (SQLAlchemyError, ElasticsearchException, EsOperationError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve package host list failed due to internal error.")
            return DATABASE_QUERY_ERROR, []

    def _get_task_cve_rpm_host(self, data):
        host_id_list = (
            self.session.query(TaskCveHostAssociation.host_id)
            .outerjoin(
                TaskCveHostRpmAssociation,
                TaskCveHostAssociation.task_cve_host_id == TaskCveHostRpmAssociation.task_cve_host_id,
            )
            .filter(
                TaskCveHostAssociation.task_id == data["task_id"],
                TaskCveHostAssociation.cve_id == data["cve_id"],
                TaskCveHostRpmAssociation.installed_rpm == data["installed_rpm"],
                TaskCveHostRpmAssociation.available_rpm == data["available_rpm"],
            )
            .group_by(TaskCveHostAssociation.host_id)
            .all()
        )
        if not host_id_list:
            return []
        host_ids = [host.host_id for host in host_id_list]
        hosts = self.session.query(Host.host_ip, Host.host_name).filter(Host.host_id.in_(host_ids)).all()
        host_info_list = [dict(host_name=host.host_name, host_ip=host.host_ip) for host in hosts]
        return host_info_list
