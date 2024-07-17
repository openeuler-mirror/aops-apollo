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
import time
import uuid
from collections import defaultdict
from typing import Dict, Tuple

import sqlalchemy.orm
from elasticsearch import ElasticsearchException
from flask import g
from sqlalchemy import func, case
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql import or_

from apollo.conf.constant import TaskStatus, TaskType
from apollo.database.proxy.task.base import TaskProxy
from apollo.database.table import Task, CveFixTask, CveHostAssociation
from vulcanus.database.helper import sort_and_page
from vulcanus.log.log import LOGGER
from vulcanus.restful.resp.state import (
    DATABASE_INSERT_ERROR,
    NO_DATA,
    DATABASE_QUERY_ERROR,
    DATABASE_UPDATE_ERROR,
    SUCCEED,
)


class CveFixTaskProxy(TaskProxy):
    """
    Cve fix task is implemented
    """

    def generate_cve_task(self, data):
        """
        For generating, save cve task basic info to mysql, init task info in es.

        Args:
            data (dict): e.g.
                {
                    "username": "admin",
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
                                    "host_id": "id1"
                                }
                            ]
                        }
                    ]
                }

        Returns:
            str: status code
            fix_tasks: e.g
                [
                    {
                        "task_id": "8878b35288df11eeb0815254001a9e0d",
                        "fix_way": "hotpatch/coldpatch"
                    }
                ]
        """
        try:
            status_code, fix_tasks = self._generate_cve_fix_task(data)
            if status_code != SUCCEED:
                return status_code, []
            self.session.commit()
            LOGGER.debug("Finished generating cve task.")
            return status_code, fix_tasks
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Generating cve task failed due to internal error.")
            return DATABASE_INSERT_ERROR, []

    def _generate_cve_fix_task(self, data) -> tuple:
        """
        generate cve fix task.  then:
        1. insert task basic info into mysql Task table
        2. insert host and package's relationship and fixing status into mysql
           table CveFixTask
        Args:
            data (dict): cve task info

        Returns:
            Tuple[str, list]: A tuple containing the status and task info list
        """
        host_dict = data.pop("host_dict")
        fix_host_rpm_info = data.pop("info")
        wait_fix_rpms = dict()

        for task_info in fix_host_rpm_info:
            wait_fix_rpms[task_info["cve_id"]] = dict(rpms=task_info.get("rpms", []), hosts=list(host_dict.keys()))

        hotpatch_fix_rpms, coldpatch_fix_rpms = self._get_cold_and_hotpatch_fix_rpm(wait_fix_rpms, data["takeover"])
        fix_tasks = []
        subtask = all([coldpatch_fix_rpms, hotpatch_fix_rpms])
        # insert data into mysql tables
        if coldpatch_fix_rpms:
            coldpatch_fix_task_id = self._save_fix_task_info(data, coldpatch_fix_rpms, host_dict, "coldpatch", subtask)
            fix_tasks.append(dict(task_id=coldpatch_fix_task_id, fix_way="coldpatch"))
        if hotpatch_fix_rpms:
            hotpatch_fix_task_id = self._save_fix_task_info(data, hotpatch_fix_rpms, host_dict, "hotpatch", subtask)
            fix_tasks.append(dict(task_id=hotpatch_fix_task_id, fix_way="hotpatch"))

        return SUCCEED, fix_tasks

    def _get_cold_and_hotpatch_fix_rpm(self, wait_fix_rpms: dict, takeover=False) -> tuple:
        """
        Get coldpatch and hotpatch fix rpm

        Args:
            wait_fix_rpms: e.g
                {
                    "CVE-2023-3332":{
                        "rpms": [],
                        "hosts":[1,2,3]
                    },
                    "CVE-2023-3332":{
                        "rpms": [
                            {
                                "installed_rpm":"pkg1",
                                "available_rpm": "pkg1-1",
                                "fix_way":"hotpatch"
                            }
                        ],
                        "hosts":[1,2,3]
                    }
                }
            takeover: install cold patches during hot patch remediation

        Returns:
            {
                1: {
                    "cves": "CVE-2023-123,CVE-2023-2345",
                    "available_rpm": "kernel-5.1",
                    "installed_rpm": "kernel-4.19",
                    "fix_way": "coldpatch/hotpatch"
                }
            }
        """

        host_packages = dict()
        for cve_id, host_rpms in wait_fix_rpms.items():
            host_packages_dict = self._get_host_cve_packages(cve_id, host_rpms)
            for host_id, cve_packages in host_packages_dict.items():
                host_packages.setdefault(host_id, []).extend(cve_packages)

        hotpatch_fix_rpms, coldpatch_fix_rpms = self._analyze_rpm_fix_way(host_packages, takeover)
        coldpatch_task_info = self._gen_host_package_map(coldpatch_fix_rpms, "coldpatch")
        hotpatch_task_info = self._gen_host_package_map(hotpatch_fix_rpms, "hotpatch")
        return hotpatch_task_info, coldpatch_task_info

    def _gen_host_package_map(self, patch_fix_rpms, fix_way) -> dict:
        """
        Args:
            patch_fix_rpms: e.g
                {
                    "installed_rpm": "kernel-4.19",,
                    "available_rpm": "kernel-5.1",
                    "fix_way": "coldpatch/hotpatch"
                    "cve_id": "CVE-2023-123"
                }

        Returns:
            {
                1: {
                    "cves": "CVE-2023-123,CVE-2023-2345",
                    "available_rpm": "kernel-5.1",
                    "installed_rpm": "kernel-4.19",
                    "fix_way": "coldpatch/hotpatch"
                }
            }
        """
        fix_task_info_dict = dict()
        for host_id, wait_fix_rpm in patch_fix_rpms.items():
            cve_rpm_dict = dict()
            for rpm in wait_fix_rpm:
                if rpm["installed_rpm"] not in cve_rpm_dict:
                    cve_rpm_dict[rpm["installed_rpm"]] = dict(rpm=[], cve=[])
                cve_rpm_dict[rpm["installed_rpm"]]["rpm"].append(rpm["available_rpm"])
                cve_rpm_dict[rpm["installed_rpm"]]["cve"].append(rpm["cve_id"])
            fix_task_info_dict[host_id] = []
            for installed_rpm, cve_rpm_map_info in cve_rpm_dict.items():
                available_rpm = sorted(cve_rpm_map_info["rpm"])[-1]
                cves = ",".join(sorted(set(cve_rpm_map_info["cve"])))
                fix_task_info_dict[host_id].append(
                    {"cves": cves, "available_rpm": available_rpm, "installed_rpm": installed_rpm, "fix_way": fix_way}
                )
        return fix_task_info_dict

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
                    "hosts":[1,2,3]
                } or
                {
                    "rpms": [],
                    "hosts":[1,2,3]
                }
            takeover: true/false, install cold patches during hot patch remediation

        Returns:
            {
                1: [
                    {
                        "installed_rpm":"pkg1",
                        "available_rpm": "pkg1-1",
                        "fix_way":"hotpatch",
                        "cve_id": "CVE-2023-1234"
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

        host_package_list = (
            self.session.query(CveHostAssociation)
            .filter(
                CveHostAssociation.cve_id == cve_id,
                CveHostAssociation.fixed == False,
                CveHostAssociation.available_rpm != None,
                CveHostAssociation.host_id.in_(host_rpms["hosts"]),
            )
            .all()
        )
        host_wait_fix_package_dict = dict()
        for host_id in host_rpms["hosts"]:
            filter_host_package = list(filter(lambda host_package: host_package.host_id == host_id, host_package_list))
            if not host_rpm_dict and filter_host_package:
                installed_rpm = self._filter_installed_rpm(filter_host_package)
                for rpm in installed_rpm:
                    rpm["cve_id"] = cve_id
                host_wait_fix_package_dict[host_id] = installed_rpm
                continue

            host_packages = []
            for rpm in host_rpms["rpms"]:
                host_package = list(
                    filter(lambda host_rpm: host_rpm.installed_rpm == rpm["installed_rpm"], filter_host_package)
                )
                if not host_package:
                    continue
                rpm["cve_id"] = cve_id
                host_packages.append(rpm)

            host_wait_fix_package_dict[host_id] = host_packages

        return host_wait_fix_package_dict

    def _filter_installed_rpm(self, host_packages: list):
        """

        Args:
            host_packages: list CveHostAssociation table data

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
        host_installed_rpm = set([package.installed_rpm for package in host_packages])
        for installed_rpm in host_installed_rpm:
            packages = self._priority_fix_package(host_packages, installed_rpm)
            if not packages:
                continue
            cve_host_packages.extend(
                [
                    dict(
                        installed_rpm=package.installed_rpm,
                        available_rpm=package.available_rpm,
                        fix_way=package.support_way,
                    )
                    for package in packages
                ]
            )

        return cve_host_packages

    def _priority_fix_package(self, host_packages, installed_rpm):
        """
        If multiple hot patches are available for repair, the patch package is preferred

        """
        installed_host_packages = filter(
            lambda host_rpm: host_rpm.installed_rpm == installed_rpm,
            host_packages,
        )
        packages = []
        hotpatch_acc = None
        hotpatch_sgl = None

        for rpm in installed_host_packages:
            if rpm.support_way == "coldpatch":
                packages.append(rpm)
                continue
            if not rpm.available_rpm:
                continue
            try:
                # rpm.installed_rpm e.g redis-6.2.5-1.x86_64 or samba-common-4.17.5-6.oe2203sp2.x86_64
                available_rpm = rpm.available_rpm.split(rpm.installed_rpm.rsplit('.', 1)[0] + "-")[1]
            except IndexError:
                continue
            if available_rpm.startswith("ACC"):
                hotpatch_acc = rpm
            if available_rpm.startswith("SGL"):
                hotpatch_sgl = rpm

        if all([hotpatch_acc, hotpatch_sgl]) or hotpatch_acc:
            packages.append(hotpatch_acc)
            return packages
        if hotpatch_sgl:
            packages.append(hotpatch_sgl)

        return packages

    def _analyze_rpm_fix_way(self, host_packages: dict, takeover: bool):
        """
        Get the best fixes for cold patching and hot patching for each host.
        And when the hot patch is compiled using a cold patch, the best cold patch must be installed.

        Args:
            host_packages: e.g
            {
                1: [
                    {
                        "installed_rpm":"pkg1",
                        "available_rpm": "pkg1-1",
                        "fix_way":"hotpatch",
                        "cve_id": "CVE-2023-1234"
                    }
                ]
            }
        """
        hotpatch_fix_rpms, coldpatch_fix_rpms = dict(), dict()
        cve_ids = set()
        for host_id, host_packages_list in host_packages.items():
            for host_package in host_packages_list:
                if host_package["fix_way"] == "hotpatch":
                    hotpatch_fix_rpms.setdefault(host_id, []).append(host_package)
                    cve_ids.add(host_package["cve_id"])
                else:
                    coldpatch_fix_rpms.setdefault(host_id, []).append(host_package)

        if takeover and hotpatch_fix_rpms:
            host_ids = hotpatch_fix_rpms.keys()
            host_installed_packages = [
                rpm["installed_rpm"] for packages in hotpatch_fix_rpms.values() for rpm in packages
            ]
            coldpatch_fix_packages = (
                self.session.query(
                    CveHostAssociation.host_id,
                    CveHostAssociation.installed_rpm,
                    CveHostAssociation.cve_id,
                    CveHostAssociation.available_rpm,
                    CveHostAssociation.support_way,
                )
                .filter(
                    CveHostAssociation.host_id.in_(host_ids),
                    CveHostAssociation.support_way == "coldpatch",
                    CveHostAssociation.installed_rpm.in_(host_installed_packages),
                    CveHostAssociation.cve_id.in_(cve_ids),
                )
                .all()
            )
            for coldpatch_fix_rpm in coldpatch_fix_packages:
                coldpatch_fix_rpms.setdefault(coldpatch_fix_rpm.host_id, []).append(
                    {
                        "installed_rpm": coldpatch_fix_rpm.installed_rpm,
                        "available_rpm": coldpatch_fix_rpm.available_rpm,
                        "fix_way": coldpatch_fix_rpm.support_way,
                        "cve_id": coldpatch_fix_rpm.cve_id,
                    }
                )

        return hotpatch_fix_rpms, coldpatch_fix_rpms

    def _save_fix_task_info(self, data, wait_fix_rpms: dict, host_dict: dict, fix_way, subtask=False) -> str:
        """
        Args:
            data: e.g
                {
                    "username": "admin",
                    "task_name": "",
                    "task_type": "",
                    "description": "",
                    "create_time": 1,
                    "check_items": "",
                    "accepted": True,
                    "takeover": False
                }
            host_dict: e.g
                {
                    1: {
                        "host_id": 1,
                        "host_ip": "127.0.0.1",
                        "host_name: "主机"
                    }
                }
            wait_fix_rpms: e.g
                {
                    1: {
                        "cves": "CVE-2023-123,CVE-2023-2345",
                        "available_rpm": "kernel-5.1",
                        "installed_rpm": "kernel-4.19",
                        "fix_way": "coldpatch/hotpatch"
                    }
                }

        """
        task_id = str(uuid.uuid1()).replace('-', '')
        task_info = copy.deepcopy(data)
        task_info['task_id'] = task_id
        task_info['task_type'] = TaskType.CVE_FIX
        task_info['create_time'] = int(time.time())
        task_info["check_items"] = ",".join(task_info["check_items"])
        task_info["host_num"] = len(wait_fix_rpms.keys())
        task_info["fix_type"] = fix_way
        if subtask:
            task_prefix = "冷补丁修复：" if fix_way == "coldpatch" else "热补丁修复："
            task_info["description"] = task_prefix + task_info["description"]
            task_info["task_name"] = task_prefix + task_info["task_name"]
            task_info["takeover"] = False if fix_way == "coldpatch" else task_info["takeover"]

        fix_task_host_package_rows = []
        for host_id, wait_fix_rpm in wait_fix_rpms.items():
            for rpm_info in wait_fix_rpm:
                fix_task_host_package_rows.append(
                    {
                        "task_id": task_id,
                        "host_id": host_id,
                        "host_ip": host_dict[host_id]["host_ip"],
                        "host_name": host_dict[host_id]["host_name"],
                        "cves": rpm_info["cves"],
                        "available_rpm": rpm_info["available_rpm"],
                        "installed_rpm": rpm_info["installed_rpm"],
                        "fix_way": rpm_info["fix_way"],
                        "status": TaskStatus.UNKNOWN,
                    }
                )
        self._insert_fix_task_tables(task_info, fix_task_host_package_rows)
        return task_id

    def _insert_fix_task_tables(self, task_data, task_package_rows):
        """
        insert data into three mysql tables when generating cve task.
        Task table need commit after add, otherwise following insertion will fail due to
        task.task_id foreign key constraint.
        Args:
            task_data (dict): task basic info for Task table
            task_package_rows (list): list of row dict for TaskCvePackageAssociation table

        Raises:
            SQLAlchemyError
        """

        self.session.add(Task(**task_data))
        self.session.bulk_insert_mappings(CveFixTask, task_package_rows)

    def query_task_cve_fix_rpm_info(self, task_id: str, host_id: int) -> Tuple[str, list]:
        """
        query cve's rpm info about cve-fix task

        Args:
            task_id(str): task id which need to query
            host_id(int): host id which need to query

        Returns:
            Tuple[str, list]
            a tuple containing two elements (return code, database query rows).
        """
        try:
            fix_host_rpms_list = self._query_task_cve_fix_rpm_info(task_id, host_id)
            if not fix_host_rpms_list:
                return NO_DATA, fix_host_rpms_list
            LOGGER.debug("Finished getting rpm info about cve-fix task.")
            return SUCCEED, fix_host_rpms_list
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting rpm info about cve-fix task failed due to internal error.")
            return DATABASE_QUERY_ERROR, []

    def _query_task_cve_fix_rpm_info(self, task_id: str, host_id: int) -> Tuple[str, list]:
        """
        query cve's rpm info about cve-fix task

        Args:
            task_id(str): task id which need to query
            cve_id(str): cve id which need to query

        Returns:
            Tuple[str, list]
            a tuple containing two elements (return code, database query rows).
        """
        fix_host_rpms = (
            self.session.query(
                CveFixTask.installed_rpm,
                CveFixTask.available_rpm,
                CveFixTask.cves,
                CveFixTask.status,
            )
            .filter(CveFixTask.task_id == task_id, CveFixTask.host_id == host_id)
            .all()
        )

        fix_host_rpms_list = []
        for fix_host_rpm in fix_host_rpms:
            fix_host_rpms_list.append(
                {
                    "installed_rpm": fix_host_rpm.installed_rpm,
                    "available_rpm": fix_host_rpm.available_rpm,
                    "cves": fix_host_rpm.cves,
                    "status": fix_host_rpm.status,
                }
            )
        return fix_host_rpms_list

    def update_cve_fix_task_host_package_status(self, task_id, host_id, fix_info: dict):
        """
        Setting cve fixing rpm status and update host status

        Args:
            task_id: task id
            host_id: host id
            fix_info: fix result
                {
                    "check_items":[
                        {
                            "item":"network",
                            "result":true,
                            "log":"xxxx"
                        }
                    ],
                    "rpms": [
                        {
                            "available_rpm": "string",
                            "result": "success",
                            "log": "string",
                        }
                    ],
                    "dnf_event_start": 1,
                    "dnf_event_end": 2,
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
                    "status": "failed"
                }

        Returns:
            status_code: update state
        """
        try:
            dnf_event_start = fix_info.get("dnf_event_start")
            dnf_event_end = fix_info.get("dnf_event_end")
            for rpm in fix_info["rpms"]:
                self._set_cve_fix_task_host_package_status(task_id, host_id, rpm, dnf_event_start, dnf_event_end)

            self.session.commit()
            LOGGER.debug("Finished update host rpm status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Setting host rpm status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def _set_cve_fix_task_host_package_status(self, task_id, host_id, rpm: dict, dnf_event_start, dnf_event_end):
        self.session.query(CveFixTask).filter(
            CveFixTask.task_id == task_id,
            CveFixTask.host_id == host_id,
            CveFixTask.available_rpm == rpm["available_rpm"],
        ).update(
            {
                CveFixTask.status: rpm["result"],
                CveFixTask.dnf_event_start: dnf_event_start,
                CveFixTask.dnf_event_end: dnf_event_end,
            },
            synchronize_session=False,
        )

    def get_cve_basic_info(self, task_id):
        """
        Get cve task basic info of the task id, for generating the task info.

        Args:
            task_id (str): task_id

        Returns:
            str: status code
            dict: e.g.
                {
                    "task_id": "2",
                    "task_name": "",
                    "task_type": "cve fix",
                    "total_hosts": [1,2],
                    "check_items": ["network","kabi"],
                    "fix_type": "hotpatch/coldpatch",
                    "tasks": [
                        {
                            "host_id": "id1",
                            "host_ip": "172.168.50.127",
                            "host_name": "50.127oe2203sp2-x86",
                            "rpms":[{
                                        "installed_rpm":"pkg1",
                                        "available_rpm": "pkg1-1",
                                    }]
                        }
                    ]
                }
        """
        result = {}
        try:
            status_code, result = self._get_processed_cve_fix_basic_info(task_id)
            LOGGER.debug("Finished getting the basic info of cve task.")
            return status_code, result
        except SQLAlchemyError as error:
            LOGGER.error(error)
            LOGGER.error("Getting the basic info of cve task failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_processed_cve_fix_basic_info(self, task_id: str) -> Tuple[str, Dict]:
        """
        query and process cve task's basic info
        Args:
            task_id (str): task id

        Returns:
            str
            dict
        """
        basic_task = self._query_task_basic_info(task_id).first()
        if not basic_task:
            LOGGER.debug("No data found when getting the info of cve task: %s." % task_id)
            return NO_DATA, {}

        task_info = {
            "task_id": basic_task.task_id,
            "task_name": basic_task.task_name,
            "task_type": basic_task.task_type,
            "check_items": basic_task.check_items.split(',') if basic_task.check_items else [],
            "accepted": basic_task.accepted,
            "fix_type": basic_task.fix_type,
            "total_hosts": [],
            "tasks": None,
        }
        task_host_packages = self._query_cve_fix_task_package_info(task_id=task_id).all()
        temp_info = defaultdict(list)
        for host_pkg_row in task_host_packages:
            rpm_info = dict(installed_rpm=host_pkg_row.installed_rpm, available_rpm=host_pkg_row.available_rpm)
            if host_pkg_row.host_id in temp_info:
                temp_info[host_pkg_row.host_id]["rpms"].append(rpm_info)
            else:
                temp_info[host_pkg_row.host_id] = {
                    "host_id": host_pkg_row.host_id,
                    "rpms": [rpm_info],
                }

        task_info['total_hosts'] = list(temp_info.keys())
        task_info['tasks'] = [host_rpm_info for host_rpm_info in temp_info.values()]

        return SUCCEED, task_info

    def _query_cve_fix_task_package_info(self, task_id: str) -> sqlalchemy.orm.Query:
        """
        query package info of the cve fix task

        Args:
            task_id (str): cve fix task id

        Returns:
            sqlalchemy.orm.Query
        """
        task_package_query = self.session.query(
            CveFixTask.available_rpm, CveFixTask.installed_rpm, CveFixTask.host_id
        ).filter(CveFixTask.task_id == task_id)
        return task_package_query

    def init_cve_fix_task(self, task_id, status=TaskStatus.RUNNING):
        """
        Before fixing cve, set related host status to 'running'

        Args:
            task_id (str): task id
            status (str): cve status
        Returns:
            str: status code
        """
        try:
            self.session.query(CveFixTask).filter(CveFixTask.task_id == task_id).update(
                {CveFixTask.status: status}, synchronize_session=False
            )
            self.session.commit()
            LOGGER.debug("Finished init cve task's status.")
            return SUCCEED
        except SQLAlchemyError as error:
            self.session.rollback()
            LOGGER.error(error)
            LOGGER.error("Init cve task's status failed due to internal error.")
            return DATABASE_UPDATE_ERROR

    def get_cve_task_info(self, data):
        """
        Get the specific info about the cve fixing task.

        Args:
            data (dict): parameter, e.g.
                {
                    "task_id": "id1",
                    "page": 1,
                    "per_page": 10,
                    "username": "admin",
                    "filter": {
                        "status": ["fail","running","succeed"],
                        "search_key": "host_name/host_ip"
                    }
                }

        Returns:
            str: status code
            dict: task's cve info. e.g.
                {
                    "total_count": 1,
                    "total_page": 1,
                    "result": [{
                        "host_id": 1,
                        "host_name": "",
                        "host_ip": "127.0.0.1",
                        "cve_num": 1,
                        "status": "running/succeed/failed/None"
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
            str: status code
            dict
        """
        result = {"total_count": 0, "total_page": 0, "result": []}
        task_info = self.session.query(Task).filter(Task.task_id == data["task_id"]).first()
        if not task_info:
            return result
        filters = self._get_cve_task_filters(data.get("filter", dict()), data["task_id"])
        status = data.get("filter", dict()).get("status")
        task_cve_fix_query = self._query_cve_fix_task(status, filters)

        total_count = task_cve_fix_query.count()
        # # NO_DATA code is NOT returned because no data situation here is normal
        # # with filter
        if not total_count:
            return result

        page, per_page = data.get('page'), data.get('per_page')
        cve_fix_info_result, total_page = sort_and_page(task_cve_fix_query, None, None, per_page, page)

        result['result'] = self._cve_fix_task_info_row2dict(cve_fix_info_result)
        result['total_page'] = total_page
        result['total_count'] = total_count

        return result

    @staticmethod
    def _get_cve_task_filters(filter_dict, task_id):
        """
        Generate filters to filter status task's cve info
        (filter by status will be manually implemented)
        Args:
            filter_dict(dict): filter dict to filter cve task's cve info, e.g.
                {
                    "status":["running","succeed","failed"]
                }

        Returns:
            set
        """
        filters = {CveFixTask.task_id == task_id}
        if filter_dict.get("search_key"):
            filters.add(
                or_(
                    CveFixTask.host_ip.like("%" + filter_dict["search_key"] + "%"),
                    CveFixTask.host_name.like("%" + filter_dict["search_key"] + "%"),
                )
            )
        return filters

    def _query_cve_fix_task(self, status, filters):
        """
        query needed cve task's cve info
        Args:
            status: host status
            filters (set): filter given by user

        Returns:
            sqlalchemy.orm.query.Query. row structure:
                {
                    "host_id": 1,
                    "host_name": "",
                    "host_ip": "127.0.0.1",
                    "cves": "cve-2023-0989,cve-2022-2989",
                    "status": "running,succeed,failed"
                }
        """
        task_cve_fix_subquery = (
            self.session.query(
                CveFixTask.host_id,
                CveFixTask.host_ip,
                CveFixTask.host_name,
                func.group_concat(func.distinct(CveFixTask.status)).label("status"),
                func.group_concat(func.distinct(CveFixTask.cves)).label("cves"),
            )
            .filter(*filters)
            .group_by(CveFixTask.host_id, CveFixTask.host_ip, CveFixTask.host_name)
            .subquery()
        )
        task_cve_fix_status_subquery = self.session.query(
            task_cve_fix_subquery.c.host_id,
            task_cve_fix_subquery.c.host_ip,
            task_cve_fix_subquery.c.host_name,
            case(
                [
                    (task_cve_fix_subquery.c.status.contains(TaskStatus.RUNNING), TaskStatus.RUNNING),
                    (task_cve_fix_subquery.c.status.contains(TaskStatus.FAIL), TaskStatus.FAIL),
                    (task_cve_fix_subquery.c.status.contains(TaskStatus.UNKNOWN), TaskStatus.UNKNOWN),
                ],
                else_=TaskStatus.SUCCEED,
            ).label("status"),
            task_cve_fix_subquery.c.cves,
        ).subquery()

        task_cve_fix_query = self.session.query(
            task_cve_fix_status_subquery.c.host_id,
            task_cve_fix_status_subquery.c.host_ip,
            task_cve_fix_status_subquery.c.host_name,
            task_cve_fix_status_subquery.c.status,
            task_cve_fix_status_subquery.c.cves,
        )
        if status:
            task_cve_fix_query = task_cve_fix_query.filter(task_cve_fix_status_subquery.c.status.in_(status))

        return task_cve_fix_query

    def _cve_fix_task_info_row2dict(self, cve_fix_info_result):
        """
        process task cve query data, get each cve's total status and cve_num
        Args:
            cve_fix_info_result (sqlalchemy.orm.query.Query): query result of cve task's cve info
                each row's structure:
                    {
                        "host_id": 1,
                        "host_name": "",
                        "host_ip": "127.0.0.1",
                        "cves": "cve-2023-0989,cve-2022-2989",
                        "status": "running/succeed/failed"
                    }
        Returns:
            list. e.g.
                [{
                    "host_id": 1,
                    "host_name": "",
                    "host_ip": "127.0.0.1",
                    "cves": 2,
                    "status": "running"
                }]
        """
        cve_fix_info_list = []
        for row in cve_fix_info_result:
            cve_fix_info_list.append(
                {
                    "host_id": row.host_id,
                    "host_name": row.host_name,
                    "host_ip": row.host_ip,
                    "cve_num": len(set(row.cves.split(","))),
                    "status": row.status,
                }
            )
        return cve_fix_info_list

    def get_task_cve_result(self, data):
        """
        Get the result of each cve in the task, in addition to basic info of the task.

        Args:
            data (dict): parameter. e.g.
                {
                    "username": "admin",
                    "task_id": ""
                }

        Returns:
            str: status code
            list: query result. e.g.
                [{
                    "host_id": "2",
                    "host_ip": "172.168.63.86",
                    "host_name": "host1_12001",
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
                        "rpms": [
                            {
                                "installed_rpm": "",
                                "available_rpm": "",
                                "cves": "CVE-2023-12,CVE-2022-4567",
                                "result": "succeed/failed",
                                "log": "string"
                            }
                        ],
                        "status": "failed"
                    }
            }]
        """
        result = {}
        try:
            status_code, result = self._get_cve_fix_task_result(data)
            LOGGER.debug("Finished getting cve fix task result.")
            return status_code, result
        except (ElasticsearchException, KeyError) as error:
            LOGGER.error(error)
            LOGGER.error("Getting cve fix task result failed due to internal error.")
            return DATABASE_QUERY_ERROR, result

    def _get_cve_fix_task_result(self, data):
        """
        query cve fix task result from mysql and es.
        """
        task_id = data["task_id"]
        # task log is in the format of returned dict of func
        status_code, task_log = self.get_task_log_info(task_id=task_id)
        if status_code != SUCCEED:
            return status_code, []

        return SUCCEED, task_log
